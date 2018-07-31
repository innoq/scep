// Package csrverifier defines an interface for CSR verification.
package cmsverifier

// Verify the raw decrypted CSR.
type CMSVerifier interface {
	Verify(data []byte) (bool, error)
}
