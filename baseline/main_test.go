package main

import (
	"crypto/sha256"
	"testing"

	"github.com/miekg/pkcs11"
)

// The baseline's correctness claim rests on one thing: that it measures the *same* work
// the Rust proxy measures. If it signed a different payload shape, or picked a mechanism
// the proxy does not use, the comparison would be meaningless while still producing
// plausible numbers. These tests pin that down without needing a token.

func TestMechanismForECDSASignsADigest(t *testing.T) {
	mechs, payload, err := mechanismFor("ecdsa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mechs) != 1 {
		t.Fatalf("expected exactly one mechanism, got %d", len(mechs))
	}
	if mechs[0].Mechanism != pkcs11.CKM_ECDSA {
		t.Errorf("expected CKM_ECDSA (%d), got %d", pkcs11.CKM_ECDSA, mechs[0].Mechanism)
	}

	// CKM_ECDSA signs a pre-computed digest, never the message. Handing it a raw message
	// would still produce a signature, just one over the wrong bytes -- and the token
	// would not complain.
	if len(payload) != sha256.Size {
		t.Errorf("CKM_ECDSA needs a %d-byte digest, got %d bytes", sha256.Size, len(payload))
	}

	want := sha256.Sum256([]byte("baseline benchmark payload"))
	if string(payload) != string(want[:]) {
		t.Error("payload is not the SHA-256 digest of the benchmark message")
	}
}

func TestMechanismForRSASignsTheMessage(t *testing.T) {
	mechs, payload, err := mechanismFor("rsa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mechs[0].Mechanism != pkcs11.CKM_SHA256_RSA_PKCS {
		t.Errorf("expected CKM_SHA256_RSA_PKCS (%d), got %d",
			pkcs11.CKM_SHA256_RSA_PKCS, mechs[0].Mechanism)
	}

	// The opposite of ECDSA: this mechanism hashes internally, so it must receive the
	// message. Passing a digest would hash the digest and sign something else entirely.
	if string(payload) != "baseline benchmark payload" {
		t.Errorf("CKM_SHA256_RSA_PKCS needs the message, got %q", payload)
	}
	if len(payload) == sha256.Size {
		t.Error("payload looks like a digest; this mechanism hashes internally")
	}
}

func TestMechanismForRejectsUnknown(t *testing.T) {
	// A typo must fail loudly at startup rather than silently benchmarking the wrong
	// algorithm, which would produce a number nobody could explain later.
	for _, name := range []string{"", "ECDSA", "ed25519", "rsa2048"} {
		if _, _, err := mechanismFor(name); err == nil {
			t.Errorf("mechanismFor(%q) should have failed", name)
		}
	}
}

func TestEnvOrPrefersEnvironment(t *testing.T) {
	t.Setenv("GLL_TEST_VAR", "from-env")
	if got := envOr("GLL_TEST_VAR", "fallback"); got != "from-env" {
		t.Errorf("expected the environment value, got %q", got)
	}
	if got := envOr("GLL_TEST_UNSET_VAR", "fallback"); got != "fallback" {
		t.Errorf("expected the fallback, got %q", got)
	}
}

// An empty environment variable must fall back rather than being treated as a real
// setting -- otherwise `PKCS11_MODULE= ./baseline` would try to dlopen "".
func TestEnvOrTreatsEmptyAsUnset(t *testing.T) {
	t.Setenv("GLL_TEST_EMPTY", "")
	if got := envOr("GLL_TEST_EMPTY", "fallback"); got != "fallback" {
		t.Errorf("an empty value should fall back, got %q", got)
	}
}
