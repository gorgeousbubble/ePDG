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

// AttrType is the EAP-AKA attribute type.
type AttrType uint8

const (
	AttrRAND              AttrType = 1
	AttrAUTN              AttrType = 2
	AttrRES               AttrType = 3
	AttrAUTS              AttrType = 4
	AttrPermanentIDReq    AttrType = 10
	AttrMAC               AttrType = 11
	AttrNotification      AttrType = 12
	AttrAnyIDReq          AttrType = 13
	AttrIdentity          AttrType = 14
	AttrClientErrorCode   AttrType = 22
	AttrFullAuthIDReq     AttrType = 17
	AttrCounter           AttrType = 19
	AttrCounterTooSmall   AttrType = 20
	AttrNonceMT           AttrType = 21
	AttrNonceS            AttrType = 21
	AttrKDF               AttrType = 24  // EAP-AKA' only
	AttrKDFInput          AttrType = 23  // EAP-AKA' only
	AttrBidding           AttrType = 136 // EAP-AKA' only
	AttrIV                AttrType = 129
	AttrEncData           AttrType = 130
	AttrPaddingAttr       AttrType = 6
	AttrResultInd         AttrType = 15
	AttrCheckCode         AttrType = 134
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
				// each attribute: type(1) + length(1, in 4-byte units) + value
				padded := attr.Value
				// pad to 4-byte boundary
				if rem := len(padded) % 4; rem != 0 {
					padded = append(padded, make([]byte, 4-rem)...)
				}
				attrLen := uint8((2 + len(padded)) / 4)
				body = append(body, uint8(attr.Type), attrLen)
				body = append(body, padded...)
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
	key := append(ikPrime, ckPrime...)
	label := []byte("EAP-AKA'")
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
		input := append(prev, seed...)
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

// CKPrimeIKPrime derives CK' and IK' from CK, IK, and the serving network name.
// Based on 3GPP TS 33.402 Annex A.
func CKPrimeIKPrime(ck, ik []byte, servingNetworkName string) (ckPrime, ikPrime []byte) {
	// FC = 0x20, P0 = serving network name, L0 = len(serving network name)
	// Key = CK || IK
	// S = FC || P0 || L0 || P1 || L1
	key := append(ck, ik...)
	fc := []byte{0x20}
	snName := []byte(servingNetworkName)
	snLen := make([]byte, 2)
	binary.BigEndian.PutUint16(snLen, uint16(len(snName)))

	s := append(fc, snName...)
	s = append(s, snLen...)

	mac := hmac.New(sha256.New, key)
	mac.Write(s)
	derived := mac.Sum(nil)

	// CK' = first 16 bytes XOR with CK, IK' = next 16 bytes XOR with IK
	ckPrime = make([]byte, 16)
	ikPrime = make([]byte, 16)
	for i := 0; i < 16; i++ {
		ckPrime[i] = derived[i] ^ ck[i]
		ikPrime[i] = derived[16+i] ^ ik[i]
	}
	return ckPrime, ikPrime
}
