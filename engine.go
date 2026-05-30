package samln

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"text/scanner"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/0TrustCloud/ultimate_db"
	"github.com/0TrustCloud/service_keys"
)

type contextKey string
const securityNonceKey contextKey = "samln-nonce"

type SAMLnContext struct {
	W          http.ResponseWriter
	R          *http.Request
	Claims     map[string]interface{}
	TokenNonce string
}

type SAMLnEngine struct {
	DB         *ultimate_db.DB
	Mux        *http.ServeMux
	signingKey *rsa.PrivateKey
	keyID      string
	issuer     string
	authPageID ultimate_db.PageID
	mu         sync.RWMutex
}

func New(db *ultimate_db.DB, issuer string, privateKey *rsa.PrivateKey, authPageID ultimate_db.PageID) (*SAMLnEngine, error) {
	if db == nil || privateKey == nil {
		return nil, errors.New("cannot initialize SAMLn engine without active storage and private key")
	}
	return &SAMLnEngine{
		DB:         db,
		Mux:        http.NewServeMux(),
		signingKey: privateKey,
		keyID:      "samln-v3-hardware-decoupled",
		issuer:     issuer,
		authPageID: authPageID,
	}, nil
}

// =============================================================================
// Token Synthesis & Compilation
// =============================================================================

func (se *SAMLnEngine) CompileSAMLnString(script string, variables map[string]interface{}) (string, error) {
	if strings.TrimSpace(script) == "" {
		return "", errors.New("empty samln source schema mapping script")
	}

	parser := NewParser(script)
	nodes := parser.Parse()

	coreClaims := make(jwt.MapClaims)
	coreClaims["iss"] = se.issuer
	coreClaims["iat"] = time.Now().Unix()

	for k, v := range variables {
		coreClaims[k] = v
	}

	samlAttributes := make(map[string]interface{})
	authnStatement := make(map[string]interface{})
	subjectConfirmation := make(map[string]interface{})
	hardwareSig := make(map[string]interface{})
	deviceBinding := make(map[string]interface{})

	for _, node := range nodes {
		if elem, ok := node.(Element); ok {
			switch strings.ToLower(elem.Tag) {
			case "assertion":
				if id, found := elem.Attributes["id"]; found {
					coreClaims["jti"] = id
				}
				coreClaims["saml_issue_instant"] = time.Now().Format(time.RFC3339)
				se.compileHardwareCoreBlocks(elem.Children, coreClaims, samlAttributes, authnStatement, subjectConfirmation, hardwareSig, deviceBinding)
			}
		}
	}

	if len(samlAttributes) > 0 { coreClaims["saml:AttributeStatement"] = samlAttributes }
	if len(authnStatement) > 0 { coreClaims["saml:AuthnStatement"] = authnStatement }
	if len(subjectConfirmation) > 0 { coreClaims["saml:SubjectConfirmation"] = subjectConfirmation }
	if len(hardwareSig) > 0 { coreClaims["saml:HardwareSignature"] = hardwareSig }
	if len(deviceBinding) > 0 { coreClaims["saml:DeviceBinding"] = deviceBinding }

	if _, exists := coreClaims["exp"]; !exists {
		coreClaims["exp"] = time.Now().Add(1 * time.Hour).Unix()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, coreClaims)
	token.Header["kid"] = se.keyID
	
	return token.SignedString(se.signingKey)
}

func (se *SAMLnEngine) compileHardwareCoreBlocks(children []Node, claims jwt.MapClaims, attrs, authn, subConf, hwSig, devBind map[string]interface{}) {
	for _, child := range children {
		elem, ok := child.(Element)
		if !ok { continue }

		switch strings.ToLower(elem.Tag) {
		case "subject":
			if len(elem.Children) > 0 {
				claims["sub"] = elem.Children[0].Eval()
			}
		case "hardwaresignature":
			if keyType, found := elem.Attributes["keytype"]; found {
				hwSig["KeyType"] = keyType
			}
			if proof, found := elem.Attributes["proof"]; found {
				hwSig["Proof"] = proof
			}
			for _, subChild := range elem.Children {
				if sc, ok := subChild.(Element); ok && strings.ToLower(sc.Tag) == "tpmpubkey" {
					hwSig["TPMPublicBytes"] = sc.Children[0].Eval()
				}
			}
		case "devicebinding":
			if sessionRef, found := elem.Attributes["sessionref"]; found {
				devBind["SessionRef"] = sessionRef
			}
			if challenge, found := elem.Attributes["challenge"]; found {
				devBind["Challenge"] = challenge
			}
			for _, subChild := range elem.Children {
				if sc, ok := subChild.(Element); ok && strings.ToLower(sc.Tag) == "dbscpubkey" {
					devBind["DBSCPubKey"] = sc.Children[0].Eval()
				}
			}
		case "attribute":
			if name, found := elem.Attributes["name"]; found && len(elem.Children) > 0 {
				attrs[name] = elem.Children[0].Eval()
			}
		}
	}
}

// =============================================================================
// Decoupled Hardware Verification Path
// =============================================================================

func (se *SAMLnEngine) ValidateHardwareAssertion(tokenString string, expectedChallenge string) (bool, error) {
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &se.signingKey.PublicKey, nil
	})
	if err != nil || !parsedToken.Valid {
		return false, fmt.Errorf("invalid assertion token signature profile: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok { return false, errors.New("corrupted claims data payload") }

	subjectName, _ := claims["sub"].(string)
	if subjectName == "" { return false, errors.New("assertion missing required subject field identifier") }

	rawHwSig, absoluteHardwarePresent := claims["saml:HardwareSignature"]
	rawDevBind, absoluteDBSCPresent := claims["saml:DeviceBinding"]

	if absoluteHardwarePresent {
		hwSig := rawHwSig.(map[string]interface{})
		proofStr, _ := hwSig["Proof"].(string)

		sigBytes, err := base64.StdEncoding.DecodeString(proofStr)
		if err != nil { return false, errors.New("failed decoding base64 envelope signature bytes") }

		// Rebuild the verification payload string to match the tracked hash format
		payload := fmt.Sprintf("%s|%s", claims["jti"].(string), subjectName)

		// FIXED: Call service_keys manager directly to process verification completely
		skm := service_keys.NewServiceKeyManager(se.DB, nil, nil)
		if !skm.VerifySignature(subjectName, []byte(payload), sigBytes) {
			return false, errors.New("TPM service key assertion signature challenge verification failed via service_keys")
		}
	}

	if absoluteDBSCPresent {
		devBind := rawDevBind.(map[string]interface{})
		challenge, _ := devBind["Challenge"].(string)

		if expectedChallenge != "" && challenge != expectedChallenge {
			return false, errors.New("DBSC hardware verification rejected: runtime challenge out of sync")
		}
	}

	return true, nil
}

// =============================================================================
// Parser Engine Core
// =============================================================================

type Node interface { Eval() string }
type Text string
func (t Text) Eval() string { return string(t) }

type Element struct {
	Tag        string
	Attributes map[string]string
	Children   []Node
}
func (e Element) Eval() string {
	if len(e.Children) > 0 { return e.Children[0].Eval() }
	return ""
}

type Parser struct {
	s   scanner.Scanner
	tok rune
}

func NewParser(src string) *Parser {
	var s scanner.Scanner
	s.Init(strings.NewReader(src))
	s.Error = func(s *scanner.Scanner, msg string) {}
	s.IsIdentRune = func(ch rune, i int) bool {
		return ch == '_' || ch == '-' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
	}
	p := &Parser{s: s}
	p.next()
	return p
}

func (p *Parser) next() { p.tok = p.s.Scan() }

func (p *Parser) Parse() []Node {
	var nodes []Node
	for p.tok != scanner.EOF {
		if node := p.parseExpr(); node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func stripQuotes(s string) string {
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '`' && s[len(s)-1] == '`')) {
		return s[1 : len(s)-1]
	}
	return s
}

func (p *Parser) parseExpr() Node {
	switch p.tok {
	case scanner.Ident:
		tag := p.s.TokenText()
		p.next()

		attrs := make(map[string]string)
		for p.tok == '.' || p.tok == '#' || p.tok == ':' {
			modifier := p.tok
			p.next()

			if modifier == '.' {
				className := stripQuotes(p.s.TokenText())
				p.next()
				attrs["class"] = strings.TrimSpace(attrs["class"] + " " + className)
			} else if modifier == '#' {
				attrs["id"] = stripQuotes(p.s.TokenText())
				p.next()
			} else if modifier == ':' {
				attrName := strings.ToLower(stripQuotes(p.s.TokenText()))
				p.next()
				attrValue := "true"

				if p.tok == '.' {
					p.next()
					attrValue = stripQuotes(p.s.TokenText())
					p.next()
				}
				attrs[attrName] = attrValue
			}
		}

		var children []Node
		if p.tok == '(' {
			p.next()
			for p.tok != ')' && p.tok != scanner.EOF {
				if arg := p.parseExpr(); arg != nil {
					children = append(children, arg)
				}
				if p.tok == ',' { p.next() }
			}
			if p.tok == ')' { p.next() }
		}
		return Element{Tag: tag, Attributes: attrs, Children: children}

	case scanner.String, scanner.RawString:
		val := stripQuotes(p.s.TokenText())
		p.next()
		return Text(val)

	default:
		p.next()
		return nil
	}
}
