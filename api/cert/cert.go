package cert

import "sync/atomic"

type NebulaCertificate struct {
	Details   NebulaCertificateDetails
	Signature []byte

	// the cached hex string of the calculated sha256sum
	// for VerifyWithCache
	sha256sum atomic.Pointer[string]

	// the cached public key bytes if they were verified as the signer
	// for VerifyWithCache
	signatureVerified atomic.Pointer[[]byte]
}
