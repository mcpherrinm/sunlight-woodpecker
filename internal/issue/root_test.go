package issue

import (
	"path/filepath"
	"testing"
)

func TestCreateRoot(t *testing.T) {
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "root.crt")
	keyFile := filepath.Join(tempDir, "root.key")

	err := CreateRoot(certFile, keyFile)
	if err != nil {
		t.Fatalf("CreateRoot failed: %v", err)
	}

	issuer, err := New(certFile, keyFile)
	if err != nil {
		t.Fatalf("Failed to load cert and key: %v", err)
	}

	_, err = issuer.GetPrecert([]string{"test.invalid"})
	if err != nil {
		t.Fatalf("GetPrecert failed: %v", err)
	}
}
