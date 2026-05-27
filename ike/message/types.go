// Package message implements IKEv2 message encoding and decoding.
// Based on RFC 7296 and 3GPP TS 24.302.
package message

import (
	"encoding/binary"
	"fmt"
)

// ---- IKEv2 Exchange Types (RFC 7296 §3.1) ----

// ExchangeType identifies the IKEv2 exchange type.
type ExchangeType uint8

const (
	IKE_SA_INIT     ExchangeType = 34
	IKE_AUTH        ExchangeType = 35
	CREATE_CHILD_SA ExchangeType = 36
	INFORMATIONAL   ExchangeType = 37
)

func (e ExchangeType) String() string {
	switch e {
	case IKE_SA_INIT:
		return "IKE_SA_INIT"
	case IKE_AUTH:
		return "IKE_AUTH"
	case CREATE_CHILD_SA:
		return "CREATE_CHILD_SA"
	case INFORMATIONAL:
		return "INFORMATIONAL"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(e))
	}
}

// ---- IKEv2 Payload Types (RFC 7296 §3.2) ----

// PayloadType identifies an IKEv2 payload.
type PayloadType uint8

const (
	PayloadTypeNone        PayloadType = 0
	PayloadTypeSA          PayloadType = 33 // Security Association
	PayloadTypeKE          PayloadType = 34 // Key Exchange
	PayloadTypeIDi         PayloadType = 35 // Identification - Initiator
	PayloadTypeIDr         PayloadType = 36 // Identification - Responder
	PayloadTypeCERT        PayloadType = 37 // Certificate
	PayloadTypeCERTREQ     PayloadType = 38 // Certificate Request
	PayloadTypeAUTH        PayloadType = 39 // Authentication
	PayloadTypeNonce       PayloadType = 40 // Nonce
	PayloadTypeN           PayloadType = 41 // Notify
	PayloadTypeD           PayloadType = 42 // Delete
	PayloadTypeV           PayloadType = 43 // Vendor ID
	PayloadTypeTSi         PayloadType = 44 // Traffic Selector - Initiator
	PayloadTypeTSr         PayloadType = 45 // Traffic Selector - Responder
	PayloadTypeSK          PayloadType = 46 // Encrypted and Authenticated
	PayloadTypeCP          PayloadType = 47 // Configuration
	PayloadTypeEAP         PayloadType = 48 // Extensible Authentication
)

func (p PayloadType) String() string {
	names := map[PayloadType]string{
		PayloadTypeSA:      "SA",
		PayloadTypeKE:      "KE",
		PayloadTypeIDi:     "IDi",
		PayloadTypeIDr:     "IDr",
		PayloadTypeCERT:    "CERT",
		PayloadTypeCERTREQ: "CERTREQ",
		PayloadTypeAUTH:    "AUTH",
		PayloadTypeNonce:   "Nonce",
		PayloadTypeN:       "Notify",
		PayloadTypeD:       "Delete",
		PayloadTypeV:       "VendorID",
		PayloadTypeTSi:     "TSi",
		PayloadTypeTSr:     "TSr",
		PayloadTypeSK:      "SK",
		PayloadTypeCP:      "CP",
		PayloadTypeEAP:     "EAP",
	}
	if s, ok := names[p]; ok {
		return s
	}
	return fmt.Sprintf("Unknown(%d)", uint8(p))
}

// ---- IKEv2 Header (RFC 7296 §3.1) ----

// IKEHeader is the fixed 28-byte IKEv2 header.
type IKEHeader struct {
	InitiatorSPI [8]byte      // IKE SA initiator SPI
	ResponderSPI [8]byte      // IKE SA responder SPI
	NextPayload  PayloadType  // first payload type
	MajorVersion uint8        // must be 2
	MinorVersion uint8        // must be 0
	ExchangeType ExchangeType // exchange type
	Flags        uint8        // flags byte
	MessageID    uint32       // message ID
	Length       uint32       // total length including header
}

// IKE header flags (RFC 7296 §3.1).
const (
	FlagInitiator uint8 = 0x08 // set by initiator
	FlagVersion   uint8 = 0x10 // higher version available
	FlagResponse  uint8 = 0x20 // this is a response
)

// IsInitiator returns true if the Initiator flag is set.
func (h *IKEHeader) IsInitiator() bool { return h.Flags&FlagInitiator != 0 }

// IsResponse returns true if the Response flag is set.
func (h *IKEHeader) IsResponse() bool { return h.Flags&FlagResponse != 0 }

// IKEHeaderLen is the fixed IKEv2 header length in bytes.
const IKEHeaderLen = 28

// Encode serialises the IKEv2 header into a 28-byte slice.
func (h *IKEHeader) Encode() []byte {
	b := make([]byte, IKEHeaderLen)
	copy(b[0:8], h.InitiatorSPI[:])
	copy(b[8:16], h.ResponderSPI[:])
	b[16] = uint8(h.NextPayload)
	b[17] = (h.MajorVersion << 4) | (h.MinorVersion & 0x0F)
	b[18] = uint8(h.ExchangeType)
	b[19] = h.Flags
	binary.BigEndian.PutUint32(b[20:24], h.MessageID)
	binary.BigEndian.PutUint32(b[24:28], h.Length)
	return b
}

// DecodeIKEHeader parses a 28-byte IKEv2 header.
func DecodeIKEHeader(b []byte) (*IKEHeader, error) {
	if len(b) < IKEHeaderLen {
		return nil, fmt.Errorf("ike header: too short (%d < %d)", len(b), IKEHeaderLen)
	}
	h := &IKEHeader{}
	copy(h.InitiatorSPI[:], b[0:8])
	copy(h.ResponderSPI[:], b[8:16])
	h.NextPayload = PayloadType(b[16])
	h.MajorVersion = b[17] >> 4
	h.MinorVersion = b[17] & 0x0F
	h.ExchangeType = ExchangeType(b[18])
	h.Flags = b[19]
	h.MessageID = binary.BigEndian.Uint32(b[20:24])
	h.Length = binary.BigEndian.Uint32(b[24:28])
	if h.MajorVersion != 2 {
		return nil, fmt.Errorf("ike header: unsupported version %d.%d", h.MajorVersion, h.MinorVersion)
	}
	return h, nil
}

// ---- Generic Payload Header (RFC 7296 §3.2) ----

// PayloadHeader is the 4-byte generic payload header.
type PayloadHeader struct {
	NextPayload  PayloadType // next payload type (0 = none)
	Critical     bool        // critical bit
	PayloadLength uint16     // length including this header
}

const PayloadHeaderLen = 4

// Encode serialises the generic payload header.
func (ph *PayloadHeader) Encode() []byte {
	b := make([]byte, PayloadHeaderLen)
	b[0] = uint8(ph.NextPayload)
	if ph.Critical {
		b[1] = 0x80
	}
	binary.BigEndian.PutUint16(b[2:4], ph.PayloadLength)
	return b
}

// DecodePayloadHeader parses a 4-byte generic payload header.
func DecodePayloadHeader(b []byte) (*PayloadHeader, error) {
	if len(b) < PayloadHeaderLen {
		return nil, fmt.Errorf("payload header: too short")
	}
	return &PayloadHeader{
		NextPayload:   PayloadType(b[0]),
		Critical:      b[1]&0x80 != 0,
		PayloadLength: binary.BigEndian.Uint16(b[2:4]),
	}, nil
}

// ---- IKEv2 Message ----

// IKEMessage is a decoded IKEv2 message.
type IKEMessage struct {
	Header   *IKEHeader
	Payloads []IKEPayload
}

// IKEPayload is the interface implemented by all IKEv2 payloads.
type IKEPayload interface {
	// Type returns the payload type.
	Type() PayloadType
	// Encode serialises the payload body (without the generic header).
	Encode() ([]byte, error)
}

// Encode serialises the full IKEv2 message.
func (m *IKEMessage) Encode() ([]byte, error) {
	// encode payloads in reverse to chain NextPayload fields
	var payloadBytes [][]byte
	nextType := PayloadTypeNone
	for i := len(m.Payloads) - 1; i >= 0; i-- {
		p := m.Payloads[i]
		body, err := p.Encode()
		if err != nil {
			return nil, fmt.Errorf("encode payload %s: %w", p.Type(), err)
		}
		ph := &PayloadHeader{
			NextPayload:   nextType,
			PayloadLength: uint16(PayloadHeaderLen + len(body)),
		}
		chunk := append(ph.Encode(), body...)
		payloadBytes = append([][]byte{chunk}, payloadBytes...)
		nextType = p.Type()
	}
	// flatten payloads
	var flat []byte
	for _, chunk := range payloadBytes {
		flat = append(flat, chunk...)
	}
	// update header
	m.Header.NextPayload = nextType
	m.Header.Length = uint32(IKEHeaderLen + len(flat))
	return append(m.Header.Encode(), flat...), nil
}

// DecodeIKEMessage parses a raw IKEv2 message (header + payloads).
// The caller is responsible for decrypting SK payloads before calling this.
func DecodeIKEMessage(b []byte) (*IKEMessage, error) {
	hdr, err := DecodeIKEHeader(b)
	if err != nil {
		return nil, err
	}
	if uint32(len(b)) < hdr.Length {
		return nil, fmt.Errorf("ike message: truncated (have %d, want %d)", len(b), hdr.Length)
	}
	msg := &IKEMessage{Header: hdr}
	offset := IKEHeaderLen
	nextType := hdr.NextPayload
	for nextType != PayloadTypeNone && offset < int(hdr.Length) {
		if offset+PayloadHeaderLen > int(hdr.Length) {
			return nil, fmt.Errorf("ike message: payload header truncated at offset %d", offset)
		}
		ph, err := DecodePayloadHeader(b[offset:])
		if err != nil {
			return nil, err
		}
		if int(ph.PayloadLength) < PayloadHeaderLen {
			return nil, fmt.Errorf("ike message: payload length %d too small", ph.PayloadLength)
		}
		end := offset + int(ph.PayloadLength)
		if end > int(hdr.Length) {
			return nil, fmt.Errorf("ike message: payload extends beyond message")
		}
		body := b[offset+PayloadHeaderLen : end]
		payload, err := decodePayload(nextType, body)
		if err != nil {
			if ph.Critical {
				return nil, fmt.Errorf("ike message: critical payload %s: %w", nextType, err)
			}
			// non-critical unknown payload: skip
		} else {
			msg.Payloads = append(msg.Payloads, payload)
		}
		nextType = ph.NextPayload
		offset = end
	}
	return msg, nil
}

// decodePayload dispatches to the appropriate payload decoder.
func decodePayload(t PayloadType, body []byte) (IKEPayload, error) {
	switch t {
	case PayloadTypeSA:
		return DecodeSAPayload(body)
	case PayloadTypeKE:
		return DecodeKEPayload(body)
	case PayloadTypeIDi, PayloadTypeIDr:
		return DecodeIDPayload(t, body)
	case PayloadTypeCERT:
		return DecodeCERTPayload(body)
	case PayloadTypeCERTREQ:
		return DecodeCERTREQPayload(body)
	case PayloadTypeAUTH:
		return DecodeAUTHPayload(body)
	case PayloadTypeNonce:
		return DecodeNoncePayload(body)
	case PayloadTypeN:
		return DecodeNotifyPayload(body)
	case PayloadTypeD:
		return DecodeDeletePayload(body)
	case PayloadTypeV:
		return DecodeVendorIDPayload(body)
	case PayloadTypeTSi, PayloadTypeTSr:
		return DecodeTSPayload(t, body)
	case PayloadTypeSK:
		return DecodeSKPayload(body)
	case PayloadTypeCP:
		return DecodeCPPayload(body)
	case PayloadTypeEAP:
		return DecodeEAPPayload(body)
	default:
		return nil, fmt.Errorf("unknown payload type %d", uint8(t))
	}
}

// FindPayload returns the first payload of the given type, or nil.
func (m *IKEMessage) FindPayload(t PayloadType) IKEPayload {
	for _, p := range m.Payloads {
		if p.Type() == t {
			return p
		}
	}
	return nil
}

// FindAllPayloads returns all payloads of the given type.
func (m *IKEMessage) FindAllPayloads(t PayloadType) []IKEPayload {
	var result []IKEPayload
	for _, p := range m.Payloads {
		if p.Type() == t {
			result = append(result, p)
		}
	}
	return result
}
