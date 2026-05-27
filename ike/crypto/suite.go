// Package crypto implements IKEv2 cryptographic operations.
// Based on RFC 7296 §2.13-2.15 and 3GPP TS 33.402.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
)

// ---- Diffie-Hellman Groups (RFC 3526, RFC 5903) ----

// DHGroup represents a Diffie-Hellman group.
type DHGroup struct {
	ID      uint16
	Name    string
	P       *big.Int // prime modulus
	G       *big.Int // generator
	KeySize int      // key size in bytes
}

var (
	// MODP-2048 (Group 14, RFC 3526)
	DHMODP2048 = &DHGroup{
		ID:      14,
		Name:    "MODP-2048",
		KeySize: 256,
		G:       big.NewInt(2),
		P: func() *big.Int {
			p, _ := new(big.Int).SetString(
				"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
					"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
					"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
					"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
					"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
					"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
					"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
					"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
					"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
					"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
					"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
			return p
		}(),
	}
)

// GenerateDHKeyPair generates a DH private/public key pair for the given group.
func GenerateDHKeyPair(group *DHGroup) (private, public *big.Int, err error) {
	// generate random private key in [2, p-2]
	pMinus2 := new(big.Int).Sub(group.P, big.NewInt(2))
	for {
		private, err = rand.Int(rand.Reader, pMinus2)
		if err != nil {
			return nil, nil, fmt.Errorf("DH keygen: %w", err)
		}
		if private.Sign() > 0 {
			break
		}
	}
	public = new(big.Int).Exp(group.G, private, group.P)
	return private, public, nil
}

// ComputeDHSharedSecret computes the DH shared secret.
func ComputeDHSharedSecret(group *DHGroup, private, peerPublic *big.Int) []byte {
	shared := new(big.Int).Exp(peerPublic, private, group.P)
	b := shared.Bytes()
	// pad to group key size
	if len(b) < group.KeySize {
		padded := make([]byte, group.KeySize)
		copy(padded[group.KeySize-len(b):], b)
		return padded
	}
	return b
}

// ---- PRF (Pseudo-Random Function) ----

// PRF computes HMAC-SHA256 as the IKEv2 PRF.
func PRF(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// PRFPlus implements the IKEv2 prf+ function (RFC 7296 §2.13).
// It generates 'length' bytes of keying material.
func PRFPlus(key, seed []byte, length int) []byte {
	var result []byte
	var prev []byte
	counter := uint8(1)
	for len(result) < length {
		input := append(prev, seed...)
		input = append(input, counter)
		t := PRF(key, input)
		result = append(result, t...)
		prev = t
		counter++
	}
	return result[:length]
}

// ---- SKEYSEED and Key Derivation (RFC 7296 §2.14) ----

// DeriveIKEKeys derives all IKEv2 SA keys from the DH shared secret.
// Returns SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr.
func DeriveIKEKeys(dhShared, nI, nR []byte, spiI, spiR [8]byte) *IKEKeyMaterial {
	// SKEYSEED = prf(Ni | Nr, g^ir)
	nonce := append(nI, nR...)
	skeySeed := PRF(nonce, dhShared)

	// S = Ni | Nr | SPIi | SPIr
	s := append(nonce, spiI[:]...)
	s = append(s, spiR[:]...)

	// Generate 7 keys: SK_d(32) + SK_ai(32) + SK_ar(32) + SK_ei(32) + SK_er(32) + SK_pi(32) + SK_pr(32) = 224 bytes
	keyLen := 32 // SHA-256 output
	totalLen := 7 * keyLen
	keyMat := PRFPlus(skeySeed, s, totalLen)

	km := &IKEKeyMaterial{}
	offset := 0
	km.SK_d = keyMat[offset : offset+keyLen]
	offset += keyLen
	km.SK_ai = keyMat[offset : offset+keyLen]
	offset += keyLen
	km.SK_ar = keyMat[offset : offset+keyLen]
	offset += keyLen
	km.SK_ei = keyMat[offset : offset+keyLen]
	offset += keyLen
	km.SK_er = keyMat[offset : offset+keyLen]
	offset += keyLen
	km.SK_pi = keyMat[offset : offset+keyLen]
	offset += keyLen
	km.SK_pr = keyMat[offset : offset+keyLen]
	return km
}

// IKEKeyMaterial holds the derived IKEv2 SA keys.
type IKEKeyMaterial struct {
	SK_d  []byte // child SA key derivation
	SK_ai []byte // initiator integrity key
	SK_ar []byte // responder integrity key
	SK_ei []byte // initiator encryption key
	SK_er []byte // responder encryption key
	SK_pi []byte // initiator PRF key (for AUTH)
	SK_pr []byte // responder PRF key (for AUTH)
}

// DeriveChildKeys derives Child SA keys from SK_d.
func DeriveChildKeys(skD, nI, nR []byte, encKeyLen, integKeyLen int) *ChildKeyMaterial {
	seed := append(nI, nR...)
	totalLen := 2*encKeyLen + 2*integKeyLen
	keyMat := PRFPlus(skD, seed, totalLen)
	offset := 0
	ck := &ChildKeyMaterial{}
	ck.SK_ei = keyMat[offset : offset+encKeyLen]
	offset += encKeyLen
	ck.SK_ar_child = keyMat[offset : offset+integKeyLen]
	offset += integKeyLen
	ck.SK_er = keyMat[offset : offset+encKeyLen]
	offset += encKeyLen
	ck.SK_ai_child = keyMat[offset : offset+integKeyLen]
	return ck
}

// ChildKeyMaterial holds the derived Child SA keys.
type ChildKeyMaterial struct {
	SK_ei       []byte // initiator encryption key
	SK_er       []byte // responder encryption key
	SK_ai_child []byte // initiator integrity key
	SK_ar_child []byte // responder integrity key
}

// ---- Integrity (HMAC-SHA2-256-128) ----

// IntegrityHMACSHA256_128 computes a 16-byte HMAC-SHA256 truncated to 128 bits.
func IntegrityHMACSHA256_128(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)[:16]
}

// IntegrityHMACSHA512_256 computes a 32-byte HMAC-SHA512 truncated to 256 bits.
func IntegrityHMACSHA512_256(key, data []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	return mac.Sum(nil)[:32]
}

// VerifyIntegrity verifies an HMAC-SHA256-128 integrity check value.
func VerifyIntegrity(key, data, icv []byte) bool {
	expected := IntegrityHMACSHA256_128(key, data)
	return hmac.Equal(expected, icv)
}

// ---- Encryption (AES-CBC) ----

// EncryptAESCBC encrypts data using AES-CBC with PKCS#7 padding.
// Returns IV || ciphertext.
func EncryptAESCBC(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES-CBC encrypt: %w", err)
	}
	// PKCS#7 padding
	blockSize := block.BlockSize()
	padLen := blockSize - (len(plaintext) % blockSize)
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	// generate IV
	iv := make([]byte, blockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("AES-CBC IV: %w", err)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return append(iv, ciphertext...), nil
}

// DecryptAESCBC decrypts AES-CBC ciphertext (IV || ciphertext).
func DecryptAESCBC(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES-CBC decrypt: %w", err)
	}
	blockSize := block.BlockSize()
	if len(data) < blockSize || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("AES-CBC decrypt: invalid ciphertext length")
	}
	iv := data[:blockSize]
	ciphertext := data[blockSize:]
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	// remove PKCS#7 padding
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("AES-CBC decrypt: empty plaintext")
	}
	padLen := int(plaintext[len(plaintext)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, fmt.Errorf("AES-CBC decrypt: invalid padding")
	}
	return plaintext[:len(plaintext)-padLen], nil
}

// ---- AUTH payload computation (RFC 7296 §2.15) ----

// ComputeAuthPayload computes the AUTH payload data for shared-key authentication.
// signedOctets = message1 | nonce | prf(SK_px, IDx)
func ComputeAuthPayload(skPx, message1, nonce, idPayloadBody []byte) []byte {
	idHash := PRF(skPx, idPayloadBody)
	signed := append(message1, nonce...)
	signed = append(signed, idHash...)
	return PRF(skPx, signed)
}

// ---- Nonce generation ----

// GenerateNonce generates a cryptographically random nonce of the given length.
func GenerateNonce(length int) ([]byte, error) {
	nonce := make([]byte, length)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return nonce, nil
}

// ---- NAT Detection (RFC 7296 §3.10.1) ----

// NATDetectionHash computes the NAT detection hash:
// SHA1(SPIi | SPIr | IP | Port)
func NATDetectionHash(spiI, spiR [8]byte, ip []byte, port uint16) []byte {
	h := sha256.New()
	h.Write(spiI[:])
	h.Write(spiR[:])
	h.Write(ip)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	h.Write(portBytes)
	return h.Sum(nil)
}

// ---- HMAC helper ----

// HMAC computes HMAC with the given hash function.
func HMAC(h func() hash.Hash, key, data []byte) []byte {
	mac := hmac.New(h, key)
	mac.Write(data)
	return mac.Sum(nil)
}
