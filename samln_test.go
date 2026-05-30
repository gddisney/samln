package samln

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/0TrustCloud/ultimate_db"
)

func setupSAMLnTestEnv(t *testing.T, dbFile, walFile string) (*SAMLnEngine, func()) {
	_ = os.Remove(dbFile)
	_ = os.Remove(walFile)

	device, err := ultimate_db.NewOSFileDevice(dbFile)
	if err != nil {
		t.Fatalf("Failed to initialize system block storage file: %v", err)
	}

	disk := ultimate_db.NewDiskManager(device)
	evictor := ultimate_db.NewLRUEvictionPolicy()
	metrics := ultimate_db.NewAtomicMetrics()
	bp := ultimate_db.NewBufferPool(disk, 32, evictor, metrics)
	wal, _ := ultimate_db.NewBatchingWAL(walFile)
	db := ultimate_db.NewDB(bp, wal, metrics)

	for i := 0; i <= 12; i++ {
		_, _ = bp.NewPage()
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to spin up transient RSA identity key: %v", err)
	}

	engine, err := New(db, "https://idp.servicekeys.io", privKey, ultimate_db.PageID(1))
	if err != nil {
		t.Fatalf("Failed to boot SAMLn Microkernel: %v", err)
	}

	cleanup := func() {
		_ = db.Close()
		_ = os.Remove(dbFile)
		_ = os.Remove(walFile)
	}

	return engine, cleanup
}

func TestSAMLn_HardwareAssertionValidation(t *testing.T) {
	engine, cleanup := setupSAMLnTestEnv(t, "hw_test.db", "hw_test.wal")
	defer cleanup()

	jti := "hw-bound-txn-881"
	subject := "mesh-node-edge-east"

	tpmSimKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate simulation key: %v", err)
	}
	
	// FIXED: Packed raw binary bytes for a TPMT_PUBLIC RSA block directly to avoid struct assignment variations
	var tpmBuf bytes.Buffer
	_ = binary.Write(&tpmBuf, binary.BigEndian, uint16(0x0001)) // Type: AlgRSA (0x0001)
	_ = binary.Write(&tpmBuf, binary.BigEndian, uint16(0x000B)) // NameAlg: AlgSHA256 (0x000B)
	_ = binary.Write(&tpmBuf, binary.BigEndian, uint32(0x00020042)) // ObjectAttributes standard flag set
	_ = binary.Write(&tpmBuf, binary.BigEndian, uint16(0))      // AuthPolicy length empty
	_ = binary.Write(&tpmBuf, binary.BigEndian, uint16(0x0010)) // Symmetric: AlgNull (0x0010)
	_ = binary.Write(&tpmBuf, binary.BigEndian, uint16(0x0014)) // Scheme: AlgRSASSA (0x0014)
	_ = binary.Write(&tpmBuf, binary.BigEndian, uint16(0x000B)) // Scheme Hash: AlgSHA256 (0x000B)
	_ = binary.Write(&tpmBuf, binary.BigEndian, uint16(0x0800)) // KeyBits: 2048 (0x0800)
	_ = binary.Write(&tpmBuf, binary.BigEndian, uint32(0))      // Exponent standard 0 index offset
	
	modulusBytes := tpmSimKey.N.Bytes()
	_ = binary.Write(&tpmBuf, binary.BigEndian, uint16(len(modulusBytes)))
	_, _ = tpmBuf.Write(modulusBytes)
	tpmEncodedBytes := tpmBuf.Bytes()

	mockUserPayload := map[string]interface{}{
		"id":          tpmEncodedBytes,
		"name":        subject,
		"displayName": "Service Node East",
	}
	userBytes, _ := json.Marshal(mockUserPayload)

	txn := engine.DB.BeginTxn()
	err = engine.DB.Write(ultimate_db.PageID(1), txn, []byte("user:"+subject), userBytes, 0)
	engine.DB.CommitTxn(txn)
	if err != nil {
		t.Fatalf("Failed to pre-seed authorized test identity record: %v", err)
	}

	payload := fmt.Sprintf("%s|%s", jti, subject)
	payloadHash := sha256.Sum256([]byte(payload))
	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, tpmSimKey, crypto.SHA256, payloadHash[:])
	if err != nil {
		t.Fatalf("Failed generating mock hardware signature block: %v", err)
	}
	proofBase64Str := base64.StdEncoding.EncodeToString(signatureBytes)

	samlHwScript := fmt.Sprintf(`
		assertion#%s (
			subject("%s"),
			hardwaresignature:keytype."TPM_RSA":proof."%s" (
				tpmpubkey("ignored-metadata-layer")
			),
			devicebinding:sessionref."session_jti_001":challenge."nonce_99182" (
				dbscpubkey("MOCK_DBSC_JWK_METADATA_STR")
			),
			attribute:name."clearance"("system_level")
		)
	`, jti, subject, proofBase64Str)

	tokenString, err := engine.CompileSAMLnString(samlHwScript, nil)
	if err != nil {
		t.Fatalf("Hardware assertion script compilation processing failed: %v", err)
	}

	isValid, err := engine.ValidateHardwareAssertion(tokenString, "nonce_99182")
	if err != nil {
		t.Fatalf("Cryptographic validation check threw an unexpected tracking error: %v", err)
	}

	if !isValid {
		t.Fatal("Validation logic rejected a fully authenticated hardware bound assertion profile")
	}
}
