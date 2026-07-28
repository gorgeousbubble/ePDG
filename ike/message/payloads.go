// payloads.go implements IKEv2 payload encoding/decoding (RFC 7296).
package message

import (
	"encoding/binary"
	"fmt"
)

// ---- Transform Types and IDs (RFC 7296 §3.3.2) ----

type TransformType uint8

const (
	TransformTypeEncr  TransformType = 1 // Encryption Algorithm
	TransformTypePRF   TransformType = 2 // Pseudo-Random Function
	TransformTypeInteg TransformType = 3 // Integrity Algorithm
	TransformTypeDH    TransformType = 4 // Diffie-Hellman Group
	TransformTypeESN   TransformType = 5 // Extended Sequence Numbers
)

// Encryption algorithm transform IDs (RFC 7296 §3.3.2 / IANA IKEv2 registry).
// AES key length (128/192/256) is NOT encoded in the transform ID; it is carried
// in a separate KEY_LENGTH transform attribute (see KeyLengthAttribute), so a
// single ID is shared by all AES-CBC / AES-GCM key sizes.
const (
	EncrDES     uint16 = 2  // ENCR_DES (56-bit, insecure, do not use)
	Encr3DES    uint16 = 3  // ENCR_3DES
	EncrNull    uint16 = 11 // ENCR_NULL (no encryption)
	EncrAESCBC  uint16 = 12 // ENCR_AES_CBC   (key length via KEY_LENGTH attr)
	EncrAESCTR  uint16 = 13 // ENCR_AES_CTR
	EncrAESGCM8 uint16 = 18 // ENCR_AES_GCM with 8-octet ICV
	EncrAESGCM12 uint16 = 19 // ENCR_AES_GCM with 12-octet ICV
	EncrAESGCM16 uint16 = 20 // ENCR_AES_GCM with 16-octet ICV
	EncrChaCha20Poly1305 uint16 = 28 // ENCR_CHACHA20_POLY1305
)

// Integrity algorithm IDs
const (
	IntegHMACSHA1_96      uint16 = 2
	IntegHMACSHA2_256_128 uint16 = 12
	IntegHMACSHA2_384_192 uint16 = 13
	IntegHMACSHA2_512_256 uint16 = 14
)

// PRF algorithm IDs
const (
	PRFHMACSha1   uint16 = 2
	PRFHMACSha256 uint16 = 5
	PRFHMACSha384 uint16 = 6
	PRFHMACSha512 uint16 = 7
)

// DH group IDs
const (
	DHGroup2    uint16 = 2  // MODP-1024
	DHGroup14   uint16 = 14 // MODP-2048
	DHGroup19   uint16 = 19 // ECP-256
	DHGroup20   uint16 = 20 // ECP-384
	DHGroup21   uint16 = 21 // ECP-521
)

// ESN values
const (
	ESNNo  uint16 = 0
	ESNYes uint16 = 1
)

// ---- Transform (RFC 7296 §3.3.2) ----

// Transform represents a single IKEv2 transform.
type Transform struct {
	Type        TransformType
	ID          uint16
	Attributes  []TransformAttribute // variable-length attributes (e.g. key length)
}

// TransformAttribute is a transform attribute (RFC 7296 §3.3.5).
type TransformAttribute struct {
	Type  uint16
	Value []byte // for TLV; or 2-byte value for TV
}

// KeyLengthAttribute returns a TV-format key-length attribute.
func KeyLengthAttribute(bits uint16) TransformAttribute {
	v := make([]byte, 2)
	binary.BigEndian.PutUint16(v, bits)
	return TransformAttribute{Type: 0x800E, Value: v} // bit 15 set = TV format
}

// Proposal represents an IKEv2 SA proposal (RFC 7296 §3.3.1).
type Proposal struct {
	Number     uint8
	ProtocolID uint8 // 1=IKE, 2=AH, 3=ESP
	SPI        []byte
	Transforms []Transform
}

// SAPayload is the Security Association payload (RFC 7296 §3.3).
type SAPayload struct {
	Proposals []Proposal
}

func (s *SAPayload) Type() PayloadType { return PayloadTypeSA }

func (s *SAPayload) Encode() ([]byte, error) {
	var out []byte
	for i, prop := range s.Proposals {
		var transforms []byte
		for j, t := range prop.Transforms {
			var attrs []byte
			for _, a := range t.Attributes {
				if a.Type&0x8000 != 0 {
					// TV format
					b := make([]byte, 4)
					binary.BigEndian.PutUint16(b[0:2], a.Type)
					copy(b[2:4], a.Value)
					attrs = append(attrs, b...)
				} else {
					// TLV format
					b := make([]byte, 4+len(a.Value))
					binary.BigEndian.PutUint16(b[0:2], a.Type)
					binary.BigEndian.PutUint16(b[2:4], uint16(len(a.Value)))
					copy(b[4:], a.Value)
					attrs = append(attrs, b...)
				}
			}
			tLen := 8 + len(attrs)
			tb := make([]byte, 8)
			if j < len(prop.Transforms)-1 {
				tb[0] = 3 // more transforms
			}
			tb[1] = 0
			binary.BigEndian.PutUint16(tb[2:4], uint16(tLen))
			tb[4] = uint8(t.Type)
			tb[5] = 0
			binary.BigEndian.PutUint16(tb[6:8], t.ID)
			transforms = append(transforms, append(tb, attrs...)...)
		}
		propLen := 8 + len(prop.SPI) + len(transforms)
		pb := make([]byte, 8)
		if i < len(s.Proposals)-1 {
			pb[0] = 2 // more proposals
		}
		pb[1] = 0
		binary.BigEndian.PutUint16(pb[2:4], uint16(propLen))
		pb[4] = prop.Number
		pb[5] = prop.ProtocolID
		pb[6] = uint8(len(prop.SPI))
		pb[7] = uint8(len(prop.Transforms))
		out = append(out, pb...)
		out = append(out, prop.SPI...)
		out = append(out, transforms...)
	}
	return out, nil
}

// DecodeSAPayload parses an SA payload body.
func DecodeSAPayload(b []byte) (*SAPayload, error) {
	sa := &SAPayload{}
	offset := 0
	for offset < len(b) {
		if offset+8 > len(b) {
			return nil, fmt.Errorf("SA: proposal header truncated")
		}
		more := b[offset]
		propLen := int(binary.BigEndian.Uint16(b[offset+2 : offset+4]))
		if offset+propLen > len(b) {
			return nil, fmt.Errorf("SA: proposal extends beyond payload")
		}
		prop := Proposal{
			Number:     b[offset+4],
			ProtocolID: b[offset+5],
		}
		spiLen := int(b[offset+6])
		numTransforms := int(b[offset+7])
		tOffset := offset + 8 + spiLen
		prop.SPI = make([]byte, spiLen)
		copy(prop.SPI, b[offset+8:offset+8+spiLen])
		for i := 0; i < numTransforms; i++ {
			if tOffset+8 > offset+propLen {
				return nil, fmt.Errorf("SA: transform header truncated")
			}
			tLen := int(binary.BigEndian.Uint16(b[tOffset+2 : tOffset+4]))
			t := Transform{
				Type: TransformType(b[tOffset+4]),
				ID:   binary.BigEndian.Uint16(b[tOffset+6 : tOffset+8]),
			}
			attrOffset := tOffset + 8
			for attrOffset < tOffset+tLen {
				if attrOffset+4 > tOffset+tLen {
					break
				}
				aType := binary.BigEndian.Uint16(b[attrOffset : attrOffset+2])
				if aType&0x8000 != 0 {
					// TV
					t.Attributes = append(t.Attributes, TransformAttribute{
						Type:  aType,
						Value: b[attrOffset+2 : attrOffset+4],
					})
					attrOffset += 4
				} else {
					// TLV
					aLen := int(binary.BigEndian.Uint16(b[attrOffset+2 : attrOffset+4]))
					t.Attributes = append(t.Attributes, TransformAttribute{
						Type:  aType,
						Value: b[attrOffset+4 : attrOffset+4+aLen],
					})
					attrOffset += 4 + aLen
				}
			}
			prop.Transforms = append(prop.Transforms, t)
			tOffset += tLen
		}
		sa.Proposals = append(sa.Proposals, prop)
		offset += propLen
		if more != 2 {
			break
		}
	}
	return sa, nil
}

// ---- KE Payload (RFC 7296 §3.4) ----

// KEPayload is the Key Exchange payload.
type KEPayload struct {
	DHGroupNum uint16
	KeyData    []byte
}

func (k *KEPayload) Type() PayloadType { return PayloadTypeKE }

func (k *KEPayload) Encode() ([]byte, error) {
	b := make([]byte, 4+len(k.KeyData))
	binary.BigEndian.PutUint16(b[0:2], k.DHGroupNum)
	// b[2:4] reserved
	copy(b[4:], k.KeyData)
	return b, nil
}

func DecodeKEPayload(b []byte) (*KEPayload, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("KE: too short")
	}
	return &KEPayload{
		DHGroupNum: binary.BigEndian.Uint16(b[0:2]),
		KeyData:    append([]byte{}, b[4:]...),
	}, nil
}

// ---- ID Payload (RFC 7296 §3.5) ----

// IDType identifies the ID payload type.
type IDType uint8

const (
	IDTypeIPv4Addr  IDType = 1
	IDTypeFQDN      IDType = 2
	IDTypeRFC822    IDType = 3
	IDTypeIPv6Addr  IDType = 5
	IDTypeDERASN1DN IDType = 9
	IDTypeKeyID     IDType = 11
)

// IDPayload is the Identification payload (IDi or IDr).
type IDPayload struct {
	payloadType PayloadType
	IDType      IDType
	IDData      []byte
}

// NewIDPayload constructs an ID payload with the correct payload type
// (PayloadTypeIDi or PayloadTypeIDr). This is required because payloadType
// is unexported and must be set for correct payload chaining during encode.
func NewIDPayload(t PayloadType, idType IDType, data []byte) *IDPayload {
	return &IDPayload{
		payloadType: t,
		IDType:      idType,
		IDData:      data,
	}
}

func (id *IDPayload) Type() PayloadType { return id.payloadType }

func (id *IDPayload) Encode() ([]byte, error) {
	b := make([]byte, 4+len(id.IDData))
	b[0] = uint8(id.IDType)
	// b[1:4] reserved
	copy(b[4:], id.IDData)
	return b, nil
}

func DecodeIDPayload(t PayloadType, b []byte) (*IDPayload, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("ID: too short")
	}
	return &IDPayload{
		payloadType: t,
		IDType:      IDType(b[0]),
		IDData:      append([]byte{}, b[4:]...),
	}, nil
}

// ---- CERT Payload (RFC 7296 §3.6) ----

// CERTPayload is the Certificate payload.
type CERTPayload struct {
	CertEncoding uint8
	CertData     []byte
}

func (c *CERTPayload) Type() PayloadType { return PayloadTypeCERT }

func (c *CERTPayload) Encode() ([]byte, error) {
	b := make([]byte, 1+len(c.CertData))
	b[0] = c.CertEncoding
	copy(b[1:], c.CertData)
	return b, nil
}

func DecodeCERTPayload(b []byte) (*CERTPayload, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("CERT: too short")
	}
	return &CERTPayload{
		CertEncoding: b[0],
		CertData:     append([]byte{}, b[1:]...),
	}, nil
}

// ---- CERTREQ Payload (RFC 7296 §3.7) ----

// CERTREQPayload is the Certificate Request payload.
type CERTREQPayload struct {
	CertEncoding uint8
	CertAuthority []byte
}

func (c *CERTREQPayload) Type() PayloadType { return PayloadTypeCERTREQ }

func (c *CERTREQPayload) Encode() ([]byte, error) {
	b := make([]byte, 1+len(c.CertAuthority))
	b[0] = c.CertEncoding
	copy(b[1:], c.CertAuthority)
	return b, nil
}

func DecodeCERTREQPayload(b []byte) (*CERTREQPayload, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("CERTREQ: too short")
	}
	return &CERTREQPayload{
		CertEncoding:  b[0],
		CertAuthority: append([]byte{}, b[1:]...),
	}, nil
}

// ---- AUTH Payload (RFC 7296 §3.8) ----

// AuthMethod identifies the authentication method.
type AuthMethod uint8

const (
	AuthMethodRSA         AuthMethod = 1
	AuthMethodSharedKey   AuthMethod = 2
	AuthMethodDSS         AuthMethod = 3
	AuthMethodECDSA256    AuthMethod = 9
	AuthMethodECDSA384    AuthMethod = 10
	AuthMethodECDSA521    AuthMethod = 11
	AuthMethodGenericSig  AuthMethod = 14
)

// AUTHPayload is the Authentication payload.
type AUTHPayload struct {
	AuthMethod AuthMethod
	AuthData   []byte
}

func (a *AUTHPayload) Type() PayloadType { return PayloadTypeAUTH }

func (a *AUTHPayload) Encode() ([]byte, error) {
	b := make([]byte, 4+len(a.AuthData))
	b[0] = uint8(a.AuthMethod)
	// b[1:4] reserved
	copy(b[4:], a.AuthData)
	return b, nil
}

func DecodeAUTHPayload(b []byte) (*AUTHPayload, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("AUTH: too short")
	}
	return &AUTHPayload{
		AuthMethod: AuthMethod(b[0]),
		AuthData:   append([]byte{}, b[4:]...),
	}, nil
}

// ---- Nonce Payload (RFC 7296 §3.9) ----

// NoncePayload is the Nonce payload.
type NoncePayload struct {
	NonceData []byte
}

func (n *NoncePayload) Type() PayloadType { return PayloadTypeNonce }

func (n *NoncePayload) Encode() ([]byte, error) {
	return append([]byte{}, n.NonceData...), nil
}

func DecodeNoncePayload(b []byte) (*NoncePayload, error) {
	return &NoncePayload{NonceData: append([]byte{}, b...)}, nil
}

// ---- Notify Payload (RFC 7296 §3.10) ----

// NotifyType identifies the notification type.
type NotifyType uint16

const (
	// Error notifications
	NotifyUnsupportedCriticalPayload NotifyType = 1
	NotifyInvalidIKESPI              NotifyType = 4
	NotifyInvalidMajorVersion        NotifyType = 5
	NotifyInvalidSyntax              NotifyType = 7
	NotifyInvalidMessageID           NotifyType = 9
	NotifyInvalidSPI                 NotifyType = 11
	NotifyNoProposalChosen           NotifyType = 14
	NotifyInvalidKESyntax            NotifyType = 17
	NotifyAuthenticationFailed       NotifyType = 24
	NotifySinglePairRequired         NotifyType = 34
	NotifyNoAdditionalSAS            NotifyType = 35
	NotifyInternalAddressFailure     NotifyType = 36
	NotifyFailedCPRequired           NotifyType = 37
	NotifyTSUnacceptable             NotifyType = 38
	NotifyInvalidSelectors           NotifyType = 39
	NotifyTemporaryFailure           NotifyType = 43
	NotifyChildSANotFound            NotifyType = 44
	// Status notifications
	NotifyInitialContact             NotifyType = 16384
	NotifySetWindowSize              NotifyType = 16385
	NotifyAdditionalTSPossible       NotifyType = 16386
	NotifyIPCOMPSupported            NotifyType = 16387
	NotifyNATDetectionSourceIP       NotifyType = 16388
	NotifyNATDetectionDestinationIP  NotifyType = 16389
	NotifyCookieNotify               NotifyType = 16390
	NotifyUseTransportMode           NotifyType = 16391
	NotifyHTTPCertLookupSupported    NotifyType = 16392
	NotifyRekeySupported             NotifyType = 16393
	NotifyESPTFCPaddingNotSupported  NotifyType = 16394
	NotifyNonFirstFragmentsAlso      NotifyType = 16395
	NotifyMobIKESupported            NotifyType = 16396
	NotifyAdditionalIPv4Address      NotifyType = 16400
	NotifyAdditionalIPv6Address      NotifyType = 16401
	NotifyNoAdditionalAddresses      NotifyType = 16402
	NotifyUpdateSAAddresses          NotifyType = 16403
	NotifyCookieV2                   NotifyType = 16404
	NotifyNATPrevention              NotifyType = 16405
	// 3GPP specific (TS 24.302)
	NotifyEAPOnlyAuthentication      NotifyType = 16417
	Notify3GPPBackoffTimer           NotifyType = 40969
	NotifyDeviceIdentity             NotifyType = 16420
)

// NotifyPayload is the Notify payload.
type NotifyPayload struct {
	ProtocolID   uint8
	SPISize      uint8
	NotifyType   NotifyType
	SPI          []byte
	NotifyData   []byte
}

func (n *NotifyPayload) Type() PayloadType { return PayloadTypeN }

func (n *NotifyPayload) Encode() ([]byte, error) {
	b := make([]byte, 4+len(n.SPI)+len(n.NotifyData))
	b[0] = n.ProtocolID
	b[1] = uint8(len(n.SPI))
	binary.BigEndian.PutUint16(b[2:4], uint16(n.NotifyType))
	copy(b[4:], n.SPI)
	copy(b[4+len(n.SPI):], n.NotifyData)
	return b, nil
}

func DecodeNotifyPayload(b []byte) (*NotifyPayload, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("Notify: too short")
	}
	spiSize := int(b[1])
	if 4+spiSize > len(b) {
		return nil, fmt.Errorf("Notify: SPI extends beyond payload")
	}
	return &NotifyPayload{
		ProtocolID: b[0],
		SPISize:    b[1],
		NotifyType: NotifyType(binary.BigEndian.Uint16(b[2:4])),
		SPI:        append([]byte{}, b[4:4+spiSize]...),
		NotifyData: append([]byte{}, b[4+spiSize:]...),
	}, nil
}

// ---- Delete Payload (RFC 7296 §3.11) ----

// DeletePayload is the Delete payload.
type DeletePayload struct {
	ProtocolID uint8
	SPISize    uint8
	SPIs       [][]byte
}

func (d *DeletePayload) Type() PayloadType { return PayloadTypeD }

func (d *DeletePayload) Encode() ([]byte, error) {
	b := make([]byte, 4)
	b[0] = d.ProtocolID
	b[1] = d.SPISize
	binary.BigEndian.PutUint16(b[2:4], uint16(len(d.SPIs)))
	for _, spi := range d.SPIs {
		b = append(b, spi...)
	}
	return b, nil
}

func DecodeDeletePayload(b []byte) (*DeletePayload, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("Delete: too short")
	}
	d := &DeletePayload{
		ProtocolID: b[0],
		SPISize:    b[1],
	}
	numSPIs := int(binary.BigEndian.Uint16(b[2:4]))
	offset := 4
	for i := 0; i < numSPIs; i++ {
		end := offset + int(d.SPISize)
		if end > len(b) {
			return nil, fmt.Errorf("Delete: SPI truncated")
		}
		d.SPIs = append(d.SPIs, append([]byte{}, b[offset:end]...))
		offset = end
	}
	return d, nil
}

// ---- Vendor ID Payload (RFC 7296 §3.12) ----

// VendorIDPayload is the Vendor ID payload.
type VendorIDPayload struct {
	VendorID []byte
}

func (v *VendorIDPayload) Type() PayloadType { return PayloadTypeV }

func (v *VendorIDPayload) Encode() ([]byte, error) {
	return append([]byte{}, v.VendorID...), nil
}

func DecodeVendorIDPayload(b []byte) (*VendorIDPayload, error) {
	return &VendorIDPayload{VendorID: append([]byte{}, b...)}, nil
}

// ---- Traffic Selector Payload (RFC 7296 §3.13) ----

// TSType identifies the traffic selector type.
type TSType uint8

const (
	TSTypeIPv4AddrRange TSType = 7
	TSTypeIPv6AddrRange TSType = 8
)

// TrafficSelector is a single traffic selector entry.
type TrafficSelector struct {
	TSType   TSType
	IPProto  uint8
	StartPort uint16
	EndPort   uint16
	StartAddr []byte // 4 or 16 bytes
	EndAddr   []byte // 4 or 16 bytes
}

// TSPayload is the Traffic Selector payload (TSi or TSr).
type TSPayload struct {
	payloadType PayloadType
	Selectors   []TrafficSelector
}

func (t *TSPayload) Type() PayloadType { return t.payloadType }

func (t *TSPayload) Encode() ([]byte, error) {
	b := make([]byte, 4)
	b[0] = uint8(len(t.Selectors))
	// b[1:4] reserved
	for _, ts := range t.Selectors {
		addrLen := len(ts.StartAddr)
		tsLen := 8 + 2*addrLen
		tb := make([]byte, tsLen)
		tb[0] = uint8(ts.TSType)
		tb[1] = ts.IPProto
		binary.BigEndian.PutUint16(tb[2:4], uint16(tsLen))
		binary.BigEndian.PutUint16(tb[4:6], ts.StartPort)
		binary.BigEndian.PutUint16(tb[6:8], ts.EndPort)
		copy(tb[8:8+addrLen], ts.StartAddr)
		copy(tb[8+addrLen:], ts.EndAddr)
		b = append(b, tb...)
	}
	return b, nil
}

func DecodeTSPayload(t PayloadType, b []byte) (*TSPayload, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("TS: too short")
	}
	numTS := int(b[0])
	ts := &TSPayload{payloadType: t}
	offset := 4
	for i := 0; i < numTS; i++ {
		if offset+8 > len(b) {
			return nil, fmt.Errorf("TS: selector header truncated")
		}
		tsType := TSType(b[offset])
		tsLen := int(binary.BigEndian.Uint16(b[offset+2 : offset+4]))
		var addrLen int
		if tsType == TSTypeIPv4AddrRange {
			addrLen = 4
		} else {
			addrLen = 16
		}
		if offset+tsLen > len(b) || tsLen < 8+2*addrLen {
			return nil, fmt.Errorf("TS: selector truncated")
		}
		sel := TrafficSelector{
			TSType:    tsType,
			IPProto:   b[offset+1],
			StartPort: binary.BigEndian.Uint16(b[offset+4 : offset+6]),
			EndPort:   binary.BigEndian.Uint16(b[offset+6 : offset+8]),
			StartAddr: append([]byte{}, b[offset+8:offset+8+addrLen]...),
			EndAddr:   append([]byte{}, b[offset+8+addrLen:offset+8+2*addrLen]...),
		}
		ts.Selectors = append(ts.Selectors, sel)
		offset += tsLen
	}
	return ts, nil
}

// ---- SK (Encrypted) Payload (RFC 7296 §3.14) ----

// SKPayload is the Encrypted and Authenticated payload.
// The body is the raw ciphertext+IV+ICV; decryption is handled by the crypto layer.
type SKPayload struct {
	EncryptedData []byte
}

func (s *SKPayload) Type() PayloadType { return PayloadTypeSK }

func (s *SKPayload) Encode() ([]byte, error) {
	return append([]byte{}, s.EncryptedData...), nil
}

func DecodeSKPayload(b []byte) (*SKPayload, error) {
	return &SKPayload{EncryptedData: append([]byte{}, b...)}, nil
}

// ---- CP (Configuration) Payload (RFC 7296 §3.15) ----

// CPType identifies the configuration payload type.
type CPType uint8

const (
	CPTypeRequest CPType = 1
	CPTypeReply   CPType = 2
	CPTypeSet     CPType = 3
	CPTypeAck     CPType = 4
)

// CPAttrType identifies a configuration attribute.
type CPAttrType uint16

const (
	CPAttrInternalIPv4Address  CPAttrType = 1
	CPAttrInternalIPv4Netmask  CPAttrType = 2
	CPAttrInternalIPv4DNS      CPAttrType = 3
	CPAttrInternalIPv4NBNS     CPAttrType = 4
	CPAttrInternalIPv4DHCP     CPAttrType = 6
	CPAttrApplicationVersion   CPAttrType = 7
	CPAttrInternalIPv6Address  CPAttrType = 8
	CPAttrInternalIPv6DNS      CPAttrType = 10
	CPAttrInternalIPv6DHCP     CPAttrType = 12
	CPAttrInternalIPv4Subnet   CPAttrType = 13
	CPAttrSupportedAttributes  CPAttrType = 14
	CPAttrInternalIPv6Subnet   CPAttrType = 15
	CPAttrMIPv6HomePrefix      CPAttrType = 16
	CPAttrInternalIPv6Link     CPAttrType = 17
	CPAttrInternalIPv6Prefix   CPAttrType = 18
	CPAttrHomeAgentAddress     CPAttrType = 19
	CPAttrP_CSCF_IPv4Address   CPAttrType = 20
	CPAttrP_CSCF_IPv6Address   CPAttrType = 21
	CPAttrFTT                  CPAttrType = 22
)

// CPAttribute is a single configuration attribute.
type CPAttribute struct {
	Type  CPAttrType
	Value []byte
}

// CPPayload is the Configuration payload.
type CPPayload struct {
	CFGType    CPType
	Attributes []CPAttribute
}

func (c *CPPayload) Type() PayloadType { return PayloadTypeCP }

func (c *CPPayload) Encode() ([]byte, error) {
	b := make([]byte, 4)
	b[0] = uint8(c.CFGType)
	for _, attr := range c.Attributes {
		ab := make([]byte, 4+len(attr.Value))
		binary.BigEndian.PutUint16(ab[0:2], uint16(attr.Type))
		binary.BigEndian.PutUint16(ab[2:4], uint16(len(attr.Value)))
		copy(ab[4:], attr.Value)
		b = append(b, ab...)
	}
	return b, nil
}

func DecodeCPPayload(b []byte) (*CPPayload, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("CP: too short")
	}
	cp := &CPPayload{CFGType: CPType(b[0])}
	offset := 4
	for offset+4 <= len(b) {
		aType := CPAttrType(binary.BigEndian.Uint16(b[offset : offset+2]))
		aLen := int(binary.BigEndian.Uint16(b[offset+2 : offset+4]))
		if offset+4+aLen > len(b) {
			return nil, fmt.Errorf("CP: attribute truncated")
		}
		cp.Attributes = append(cp.Attributes, CPAttribute{
			Type:  aType,
			Value: append([]byte{}, b[offset+4:offset+4+aLen]...),
		})
		offset += 4 + aLen
	}
	return cp, nil
}

// ---- EAP Payload (RFC 7296 §3.16) ----

// EAPPayload wraps a raw EAP message inside an IKEv2 payload.
type EAPPayload struct {
	EAPMessage []byte
}

func (e *EAPPayload) Type() PayloadType { return PayloadTypeEAP }

func (e *EAPPayload) Encode() ([]byte, error) {
	return append([]byte{}, e.EAPMessage...), nil
}

func DecodeEAPPayload(b []byte) (*EAPPayload, error) {
	return &EAPPayload{EAPMessage: append([]byte{}, b...)}, nil
}
