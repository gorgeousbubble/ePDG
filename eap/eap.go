// Package eap implements EAP-AKA and EAP-AKA' authentication.
// Based on RFC 4187 (EAP-AKA), RFC 5448 (EAP-AKA'), and 3GPP TS 33.402.
package eap

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// ---- EAP Code ----

// Code is the EAP message code (RFC 3748 §4).
type Code uint8

const (
	CodeRequest  Code = 1
	CodeResponse Code = 2
	CodeSuccess  Code = 3
	CodeFailure  Code = 4
)

// Type is the EAP method type.
type Type uint8

const (
	TypeIdentity Type = 1
	TypeNak      Type = 3
	TypeAKA      Type = 23  // EAP-AKA (RFC 4187)
	TypeAKAPrime Type = 50  // EAP-AKA' (RFC 5448)
)

// SubType is the EAP-AKA/AKA' subtype.
type SubType uint8

const (
	SubTypeAKAChallenge          SubType = 1
	SubTypeAKAAuthenticationReject SubType = 2
	SubTypeAKASynchronizationFailure SubType = 4
	SubTypeAKAIdentity           SubType = 5
	SubTypeAKANotification       SubType = 12
	SubTypeAKAReauthentication   SubType = 13
	SubTypeAKAClientError        SubType = 14
)

// AttrType is the EAP-AKA/AKA' attribute type.
// Values are defined in RFC 4187 §10.1 (EAP-AKA) and RFC 5448 §3 (EAP-AKA').
type AttrType uint8

const (
	// ---- Non-skippable attributes (1–127, RFC 4187 §10.1) ----

	AttrRAND            AttrType = 1  // Random challenge (16 bytes)
	AttrAUTN            AttrType = 2  // Authentication token (16 bytes)
	AttrRES             AttrType = 3  // Response value
	AttrAUTS            AttrType = 4  // Re-synchronisation token (14 bytes)
	AttrPaddingAttr     AttrType = 6  // Padding (for encryption alignment)
	AttrPermanentIDReq  AttrType = 10 // Request permanent identity
	AttrMAC             AttrType = 11 // Message authentication code (16 bytes)
	AttrNotification    AttrType = 12 // Notification code
	AttrAnyIDReq        AttrType = 13 // Request any identity
	AttrIdentity        AttrType = 14 // Identity value
	AttrResultInd       AttrType = 15 // Result indication
	AttrFullAuthIDReq   AttrType = 17 // Request full authentication identity
	AttrCounter         AttrType = 19 // Re-authentication counter
	AttrCounterTooSmall AttrType = 20 // Counter too small notification
	AttrNonceMT         AttrType = 21 // Nonce from mobile terminal (EAP-AKA re-auth, RFC 4187 §10.1)
	AttrClientErrorCode AttrType = 22 // Client error code

	// ---- EAP-AKA' specific non-skippable attributes (RFC 5448 §3) ----
	// AT_NONCE_S does not exist in EAP-AKA or EAP-AKA'; it belongs to EAP-SIM (RFC 4186).
	// It is intentionally omitted here to avoid confusion with AttrNonceMT.

	AttrKDFInput AttrType = 23 // Network name input to KDF (EAP-AKA' only, RFC 5448 §3.1)
	AttrKDF      AttrType = 24 // Key Derivation Function identifier (EAP-AKA' only, RFC 5448 §3.2)

	// ---- Skippable attributes (128–255, RFC 4187 §10.1) ----

	AttrIV        AttrType = 129 // Initialisation vector for AT_ENCR_DATA
	AttrEncData   AttrType = 130 // Encrypted data block
	AttrCheckCode AttrType = 134 // Integrity check over plaintext EAP packet
	AttrBidding   AttrType = 136 // Bidding-down prevention (EAP-AKA' only, RFC 5448 §4)
)

// Attribute is a single EAP-AKA TLV attribute.
type Attribute struct {
	Type   AttrType
	Value  []byte
}

// Message is a decoded EAP message.
type Message struct {
	Code       Code
	Identifier uint8
	Type       Type    // only for Request/Response
	SubType    SubType // only for AKA/AKA'
	Attributes []Attribute
}

// Encode serialises the EAP message.
func (m *Message) Encode() ([]byte, error) {
	var body []byte
	if m.Code == CodeRequest || m.Code == CodeResponse {
		body = append(body, uint8(m.Type))
		if m.Type == TypeAKA || m.Type == TypeAKAPrime {
			body = append(body, uint8(m.SubType))
			body = append(body, 0, 0) // reserved
			for _, attr := range m.Attributes {
				// EAP-AKA/AKA' attribute (RFC 4187 §8.1):
				//   Type(1) | Length(1, in 4-byte units) | Value
				// The whole attribute (2 + len(Value)) must be padded to a
				// multiple of 4 bytes. We append attr.Value into body directly
				// (never append into attr.Value, which would corrupt the
				// caller's backing array) and add zero padding separately.
				valLen := len(attr.Value)
				padLen := (4 - (2+valLen)%4) % 4
				attrLen := uint8((2 + valLen + padLen) / 4)
				body = append(body, uint8(attr.Type), attrLen)
				body = append(body, attr.Value...)
				if padLen > 0 {
					body = append(body, make([]byte, padLen)...)
				}
			}
		}
	}
	totalLen := 4 + len(body)
	out := make([]byte, 4)
	out[0] = uint8(m.Code)
	out[1] = m.Identifier
	binary.BigEndian.PutUint16(out[2:4], uint16(totalLen))
	return append(out, body...), nil
}

// Decode parses a raw EAP message.
func Decode(b []byte) (*Message, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("EAP: too short")
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if len(b) < length {
		return nil, fmt.Errorf("EAP: truncated (have %d, want %d)", len(b), length)
	}
	m := &Message{
		Code:       Code(b[0]),
		Identifier: b[1],
	}
	if m.Code != CodeRequest && m.Code != CodeResponse {
		return m, nil
	}
	if length < 5 {
		return nil, fmt.Errorf("EAP: request/response too short")
	}
	m.Type = Type(b[4])
	if m.Type != TypeAKA && m.Type != TypeAKAPrime {
		return m, nil
	}
	if length < 8 {
		return nil, fmt.Errorf("EAP-AKA: header too short")
	}
	m.SubType = SubType(b[5])
	// parse attributes starting at offset 8
	offset := 8
	for offset+2 <= length {
		aType := AttrType(b[offset])
		aLenUnits := int(b[offset+1])
		aLen := aLenUnits*4 - 2
		if aLen < 0 || offset+2+aLen > length {
			return nil, fmt.Errorf("EAP-AKA: attribute truncated at offset %d", offset)
		}
		m.Attributes = append(m.Attributes, Attribute{
			Type:  aType,
			Value: append([]byte{}, b[offset+2:offset+2+aLen]...),
		})
		offset += 2 + aLen
	}
	return m, nil
}

// FindAttr returns the first attribute of the given type, or nil.
func (m *Message) FindAttr(t AttrType) *Attribute {
	for i := range m.Attributes {
		if m.Attributes[i].Type == t {
			return &m.Attributes[i]
		}
	}
	return nil
}

// ---- EAP-AKA' Key Derivation (RFC 5448 §3.3) ----

// AKAPrimeKeys holds the keys derived from EAP-AKA'.
type AKAPrimeKeys struct {
	K_encr []byte // 16 bytes, encryption key
	K_aut  []byte // 32 bytes, authentication key (AKA')
	K_re   []byte // 32 bytes, re-authentication key
	MSK    []byte // 64 bytes, Master Session Key
	EMSK   []byte // 64 bytes, Extended MSK
}

// DeriveAKAPrimeKeys derives EAP-AKA' keys from CK' and IK'.
// Based on RFC 5448 §3.3 and 3GPP TS 33.402 §6.2.
func DeriveAKAPrimeKeys(ckPrime, ikPrime []byte, identity string) (*AKAPrimeKeys, error) {
	// PRF' = HMAC-SHA-256
	// MK = PRF'(IK'|CK', "EAP-AKA'" | identity)
	key := make([]byte, 0, len(ikPrime)+len(ckPrime))
	key = append(key, ikPrime...)
	key = append(key, ckPrime...)

	label := make([]byte, 0, len("EAP-AKA'")+len(identity))
	label = append(label, []byte("EAP-AKA'")...)
	label = append(label, []byte(identity)...)

	// Generate 208 bytes of keying material
	mk := prfPrime(key, label, 208)

	keys := &AKAPrimeKeys{
		K_encr: mk[0:16],
		K_aut:  mk[16:48],
		K_re:   mk[48:80],
		MSK:    mk[80:144],
		EMSK:   mk[144:208],
	}
	return keys, nil
}

// prfPrime implements the PRF' function from RFC 5448 §3.4.
func prfPrime(key, seed []byte, length int) []byte {
	var result []byte
	var prev []byte
	counter := uint8(1)
	for len(result) < length {
		// Fresh backing array to avoid append() aliasing prev/seed storage.
		input := make([]byte, 0, len(prev)+len(seed)+1)
		input = append(input, prev...)
		input = append(input, seed...)
		input = append(input, counter)
		mac := hmac.New(sha256.New, key)
		mac.Write(input)
		t := mac.Sum(nil)
		result = append(result, t...)
		prev = t
		counter++
	}
	return result[:length]
}

// ComputeMAC computes the AT_MAC attribute for EAP-AKA'.
// The MAC is computed over the entire EAP message with AT_MAC zeroed.
func ComputeMAC(kAut, eapMsg []byte) []byte {
	mac := hmac.New(sha256.New, kAut)
	mac.Write(eapMsg)
	return mac.Sum(nil)
}

// ---- MILENAGE Algorithm (3GPP TS 35.206) ----
// Simplified implementation for EAP-AKA authentication vector generation.

// MilenageOutput holds the output of the MILENAGE f1-f5 functions.
type MilenageOutput struct {
	MAC_A []byte // f1: 8 bytes
	RES   []byte // f2: 8 bytes
	CK    []byte // f3: 16 bytes
	IK    []byte // f4: 16 bytes
	AK    []byte // f5: 6 bytes
}

// GenerateNonce32 generates a 32-byte random nonce.
func GenerateNonce32() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

// GenerateRAND generates a 16-byte random RAND value.
func GenerateRAND() ([]byte, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return b, err
}

// CKPrimeIKPrime derives CK' and IK' from CK, IK, the serving network name,
// and SQN⊕AK, per 3GPP TS 33.402 Annex A (which uses the generic KDF defined
// in TS 33.220 Annex B).
//
// The KDF is:
//
//	derived = HMAC-SHA-256(CK || IK, S)
//	S       = FC || P0 || L0 || P1 || L1
//	FC      = 0x20
//	P0      = serving network name,  L0 = len(P0)   (2-byte big-endian)
//	P1      = SQN XOR AK (6 bytes),  L1 = len(P1)=6 (2-byte big-endian)
//
// The 256-bit output is split directly: CK' = derived[0:16], IK' = derived[16:32].
// There is NO XOR with the original CK/IK (that was a bug in the previous
// implementation and would have produced wrong keys).
func CKPrimeIKPrime(ck, ik []byte, servingNetworkName string, sqnXorAK []byte) (ckPrime, ikPrime []byte) {
	key := make([]byte, 0, len(ck)+len(ik))
	key = append(key, ck...)
	key = append(key, ik...)

	snName := []byte(servingNetworkName)
	l0 := make([]byte, 2)
	binary.BigEndian.PutUint16(l0, uint16(len(snName)))
	l1 := make([]byte, 2)
	binary.BigEndian.PutUint16(l1, uint16(len(sqnXorAK)))

	// S = FC || P0 || L0 || P1 || L1
	s := make([]byte, 0, 1+len(snName)+2+len(sqnXorAK)+2)
	s = append(s, 0x20) // FC
	s = append(s, snName...)
	s = append(s, l0...)
	s = append(s, sqnXorAK...)
	s = append(s, l1...)

	mac := hmac.New(sha256.New, key)
	mac.Write(s)
	derived := mac.Sum(nil) // 32 bytes

	ckPrime = append([]byte{}, derived[0:16]...)
	ikPrime = append([]byte{}, derived[16:32]...)
	return ckPrime, ikPrime
}
