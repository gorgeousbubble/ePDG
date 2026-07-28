// Package diameter implements the SWm interface between ePDG and 3GPP AAA Server.
// Based on 3GPP TS 29.273 and RFC 6733 (Diameter Base Protocol).
package diameter

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"ePDG/logger"
)

// ---- Diameter Constants ----

// Application IDs
const (
	AppID3GPPSWm uint32 = 16777264 // 3GPP SWm (TS 29.273)
	AppIDBase    uint32 = 0        // Diameter Base
)

// Command Codes (3GPP TS 29.273 / RFC 6733).
// In Diameter a Request and its Answer share the same Command Code; they are
// distinguished by the R (Request) bit in the header flags. Hence only one
// constant per command is defined here (e.g. the DEA answer to a DER also uses
// CmdDER = 268).
const (
	CmdDER uint32 = 268 // Diameter-EAP-Request / Answer
	CmdAA  uint32 = 265 // AA-Request / Answer
	CmdSTR uint32 = 275 // Session-Termination-Request / Answer
	CmdASR uint32 = 274 // Abort-Session-Request / Answer
)

// Result codes (RFC 6733 §7.1)
const (
	ResultSuccess            uint32 = 2001
	ResultLimitedSuccess     uint32 = 2002
	ResultCommandUnsupported uint32 = 3001
	ResultUnableToDeliver    uint32 = 3002
	ResultRealmNotServed     uint32 = 3003
	ResultTooBusy            uint32 = 3004
	ResultLoopDetected       uint32 = 3005
	ResultRedirectIndication uint32 = 3006
	ResultApplicationUnsupported uint32 = 3007
	ResultInvalidHDRBits     uint32 = 3008
	ResultInvalidAVPBits     uint32 = 3009
	ResultUnknownPeer        uint32 = 3010
	ResultAuthenticationRejected uint32 = 4001
	ResultOutOfSpace         uint32 = 4002
	ResultElectionLost       uint32 = 4003
	ResultAVPUnsupported     uint32 = 5001
	ResultUnknownSessionID   uint32 = 5002
	ResultAuthorizationRejected uint32 = 5003
	ResultInvalidAVPValue    uint32 = 5004
	ResultMissingAVP         uint32 = 5005
	ResultResourcesExceeded  uint32 = 5006
	ResultContradictingAVPs  uint32 = 5007
	ResultAVPNotAllowed      uint32 = 5008
	ResultAVPOccursTooManyTimes uint32 = 5009
	ResultNoCommonApplication uint32 = 5010
	ResultUnsupportedVersion uint32 = 5011
	ResultUnableToComply     uint32 = 5012
	ResultInvalidBitInHeader uint32 = 5013
	ResultInvalidAVPLength   uint32 = 5014
	ResultInvalidMessageLength uint32 = 5015
	ResultInvalidAVPBitCombo uint32 = 5016
	ResultNoCommonSecurity   uint32 = 5017
)

// ---- AVP Codes (RFC 6733 + 3GPP TS 29.273) ----

const (
	AVPSessionID          uint32 = 263
	AVPResultCode         uint32 = 268
	AVPOriginHost         uint32 = 264
	AVPOriginRealm        uint32 = 296
	AVPDestinationRealm   uint32 = 283
	AVPDestinationHost    uint32 = 293
	AVPAuthApplicationID  uint32 = 258
	AVPAuthSessionState   uint32 = 277
	AVPEAPPayload         uint32 = 462
	AVPEAPReissuedPayload uint32 = 463
	AVPEAPMasterSessionKey uint32 = 464
	AVPUserName           uint32 = 1
	AVPNASIPAddress       uint32 = 4
	AVPNASPort            uint32 = 5
	AVPServiceType        uint32 = 6
	AVPFramedIPAddress    uint32 = 8
	AVPFramedIPv6Prefix   uint32 = 97
	AVPCalledStationID    uint32 = 30
	AVPCallingStationID   uint32 = 31
	AVPNASIdentifier      uint32 = 32
	AVPAcctSessionID      uint32 = 44
	AVPNASIPv6Address     uint32 = 95
	AVPFramedInterfaceID  uint32 = 96
	AVPTerminationCause   uint32 = 295
	AVPMIPHomeAgentAddress uint32 = 334
	// 3GPP specific
	AVP3GPPIMSIGroupID    uint32 = 1400
	AVPVisitedNetworkID   uint32 = 600
	AVPServiceSelection   uint32 = 493
	AVPMobileNodeIdentifier uint32 = 506
	AVPQoSInformation     uint32 = 1016
	AVPAMBRULinkage       uint32 = 1041
	AVPAMBRDLinkage       uint32 = 1040
	AVPANTrusted          uint32 = 1503
	AVPFullNetworkName    uint32 = 1516
	AVPShortNetworkName   uint32 = 1517
)

// ---- Diameter Message ----

// DiameterHeader is the 20-byte Diameter message header (RFC 6733 §3).
type DiameterHeader struct {
	Version       uint8
	MessageLength uint32 // 24-bit
	Flags         uint8
	CommandCode   uint32 // 24-bit
	ApplicationID uint32
	HopByHopID    uint32
	EndToEndID    uint32
}

const (
	FlagRequest  uint8 = 0x80
	FlagProxiable uint8 = 0x40
	FlagError    uint8 = 0x20
	FlagRetransmit uint8 = 0x10
)

const DiameterHeaderLen = 20

// AVP is a Diameter Attribute-Value Pair (RFC 6733 §4).
type AVP struct {
	Code     uint32
	Flags    uint8
	VendorID uint32 // only if V flag set
	Data     []byte
}

const (
	AVPFlagVendor    uint8 = 0x80
	AVPFlagMandatory uint8 = 0x40
	AVPFlagProtected uint8 = 0x20
)

// DiameterMessage is a decoded Diameter message.
type DiameterMessage struct {
	Header *DiameterHeader
	AVPs   []*AVP
}

// EncodeAVP serialises a single AVP.
func EncodeAVP(code uint32, flags uint8, vendorID uint32, data []byte) []byte {
	hasVendor := flags&AVPFlagVendor != 0
	headerLen := 8
	if hasVendor {
		headerLen = 12
	}
	totalLen := headerLen + len(data)
	// pad to 4-byte boundary
	padLen := 0
	if totalLen%4 != 0 {
		padLen = 4 - (totalLen % 4)
	}
	b := make([]byte, totalLen+padLen)
	binary.BigEndian.PutUint32(b[0:4], code)
	b[4] = flags
	// 3-byte length
	b[5] = uint8(totalLen >> 16)
	b[6] = uint8(totalLen >> 8)
	b[7] = uint8(totalLen)
	if hasVendor {
		binary.BigEndian.PutUint32(b[8:12], vendorID)
		copy(b[12:], data)
	} else {
		copy(b[8:], data)
	}
	return b
}

// EncodeUint32AVP encodes a uint32 AVP value.
func EncodeUint32AVP(code uint32, flags uint8, value uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return EncodeAVP(code, flags, 0, data)
}

// EncodeStringAVP encodes a string AVP value.
func EncodeStringAVP(code uint32, flags uint8, value string) []byte {
	return EncodeAVP(code, flags, 0, []byte(value))
}

// EncodeOctetAVP encodes an octet-string AVP value.
func EncodeOctetAVP(code uint32, flags uint8, value []byte) []byte {
	return EncodeAVP(code, flags, 0, value)
}

// EncodeDiameterMessage serialises a Diameter message.
func EncodeDiameterMessage(hdr *DiameterHeader, avps [][]byte) []byte {
	var avpBytes []byte
	for _, a := range avps {
		avpBytes = append(avpBytes, a...)
	}
	totalLen := DiameterHeaderLen + len(avpBytes)
	b := make([]byte, DiameterHeaderLen)
	b[0] = hdr.Version
	// 3-byte message length
	b[1] = uint8(totalLen >> 16)
	b[2] = uint8(totalLen >> 8)
	b[3] = uint8(totalLen)
	b[4] = hdr.Flags
	// 3-byte command code
	b[5] = uint8(hdr.CommandCode >> 16)
	b[6] = uint8(hdr.CommandCode >> 8)
	b[7] = uint8(hdr.CommandCode)
	binary.BigEndian.PutUint32(b[8:12], hdr.ApplicationID)
	binary.BigEndian.PutUint32(b[12:16], hdr.HopByHopID)
	binary.BigEndian.PutUint32(b[16:20], hdr.EndToEndID)
	return append(b, avpBytes...)
}

// DecodeDiameterMessage parses a raw Diameter message.
func DecodeDiameterMessage(b []byte) (*DiameterMessage, error) {
	if len(b) < DiameterHeaderLen {
		return nil, fmt.Errorf("diameter: header too short")
	}
	msgLen := int(uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]))
	if len(b) < msgLen {
		return nil, fmt.Errorf("diameter: message truncated")
	}
	hdr := &DiameterHeader{
		Version:       b[0],
		MessageLength: uint32(msgLen),
		Flags:         b[4],
		CommandCode:   uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7]),
		ApplicationID: binary.BigEndian.Uint32(b[8:12]),
		HopByHopID:    binary.BigEndian.Uint32(b[12:16]),
		EndToEndID:    binary.BigEndian.Uint32(b[16:20]),
	}
	msg := &DiameterMessage{Header: hdr}
	offset := DiameterHeaderLen
	for offset < msgLen {
		if offset+8 > msgLen {
			return nil, fmt.Errorf("diameter: AVP header truncated")
		}
		avpCode := binary.BigEndian.Uint32(b[offset : offset+4])
		avpFlags := b[offset+4]
		avpLen := int(uint32(b[offset+5])<<16 | uint32(b[offset+6])<<8 | uint32(b[offset+7]))
		if avpLen < 8 || offset+avpLen > msgLen {
			return nil, fmt.Errorf("diameter: AVP length invalid")
		}
		avp := &AVP{Code: avpCode, Flags: avpFlags}
		dataOffset := offset + 8
		if avpFlags&AVPFlagVendor != 0 {
			if offset+12 > msgLen {
				return nil, fmt.Errorf("diameter: AVP vendor ID truncated")
			}
			avp.VendorID = binary.BigEndian.Uint32(b[offset+8 : offset+12])
			dataOffset = offset + 12
		}
		avp.Data = append([]byte{}, b[dataOffset:offset+avpLen]...)
		msg.AVPs = append(msg.AVPs, avp)
		// advance past padding
		padded := avpLen
		if avpLen%4 != 0 {
			padded += 4 - (avpLen % 4)
		}
		offset += padded
	}
	return msg, nil
}

// FindAVP returns the first AVP with the given code, or nil.
func (m *DiameterMessage) FindAVP(code uint32) *AVP {
	for _, a := range m.AVPs {
		if a.Code == code {
			return a
		}
	}
	return nil
}

// GetResultCode extracts the Result-Code AVP value.
func (m *DiameterMessage) GetResultCode() (uint32, bool) {
	a := m.FindAVP(AVPResultCode)
	if a == nil || len(a.Data) < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(a.Data), true
}

// ---- SWm Client ----

// Client is a Diameter SWm client connecting to the 3GPP AAA Server.
type Client struct {
	mu          sync.Mutex
	conn        net.Conn
	addr        string
	originHost  string
	originRealm string
	destRealm   string
	hopByHop    uint32
	endToEnd    uint32
	timeout     time.Duration
	retryCount  int
	pending     map[uint32]chan *DiameterMessage
	pendingMu   sync.Mutex
}

// NewClient creates a new Diameter SWm client.
func NewClient(addr, originHost, originRealm, destRealm string, timeout time.Duration, retryCount int) *Client {
	return &Client{
		addr:        addr,
		originHost:  originHost,
		originRealm: originRealm,
		destRealm:   destRealm,
		timeout:     timeout,
		retryCount:  retryCount,
		pending:     make(map[uint32]chan *DiameterMessage),
	}
}

// Connect establishes a TCP connection to the AAA server.
func (c *Client) Connect() error {
	conn, err := net.DialTimeout("tcp", c.addr, c.timeout)
	if err != nil {
		return fmt.Errorf("diameter: connect to %s: %w", c.addr, err)
	}
	// Publish the connection under the lock, then release it before starting
	// readLoop so the goroutine does not contend with this method for c.mu.
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	go c.readLoop()
	logger.Infof("Diameter SWm connected to %s", c.addr)
	return nil
}

// Close closes the Diameter connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// nextHopByHop atomically increments and returns the hop-by-hop ID.
func (c *Client) nextHopByHop() uint32 {
	return atomic.AddUint32(&c.hopByHop, 1)
}

// nextEndToEnd atomically increments and returns the end-to-end ID.
func (c *Client) nextEndToEnd() uint32 {
	return atomic.AddUint32(&c.endToEnd, 1)
}

// sendRequest sends a Diameter request and waits for the answer, retrying on
// timeout up to retryCount times. The hop-by-hop ID is constant across retries
// so the same pending channel matches the answer, and retransmissions carry the
// T (potentially re-transmitted) flag per RFC 6733 §6.1.
func (c *Client) sendRequest(msg []byte, hopByHop uint32) (*DiameterMessage, error) {
	ch := make(chan *DiameterMessage, 1)
	c.pendingMu.Lock()
	c.pending[hopByHop] = ch
	c.pendingMu.Unlock()
	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, hopByHop)
		c.pendingMu.Unlock()
	}()

	attempts := c.retryCount + 1
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		// On retransmissions set the T flag (bit 0x10 of the flags byte at
		// header offset 4). Work on a copy to avoid mutating the caller's slice.
		out := msg
		if attempt > 0 {
			out = append([]byte(nil), msg...)
			out[4] |= FlagRetransmit
		}

		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		if conn == nil {
			return nil, fmt.Errorf("diameter: not connected")
		}
		if _, err := conn.Write(out); err != nil {
			// A write error means the connection is broken; retrying on the
			// same connection will not help, so fail fast.
			return nil, fmt.Errorf("diameter: send: %w", err)
		}

		select {
		case resp := <-ch:
			return resp, nil
		case <-time.After(c.timeout):
			lastErr = fmt.Errorf("diameter: request timeout (attempt %d/%d)", attempt+1, attempts)
			logger.Warnf("Diameter: %v, hop-by-hop=%d", lastErr, hopByHop)
		}
	}
	return nil, lastErr
}

// readLoop reads incoming Diameter messages and dispatches them.
func (c *Client) readLoop() {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return
	}
	for {
		raw, err := readDiameterFrame(conn)
		if err != nil {
			// Stop the loop on any read error (connection closed/reset).
			if err != io.EOF {
				logger.Errorf("Diameter read error: %v", err)
			}
			return
		}
		msg, err := DecodeDiameterMessage(raw)
		if err != nil {
			logger.Errorf("Diameter decode error: %v", err)
			continue
		}
		// dispatch to waiting request
		c.pendingMu.Lock()
		ch, ok := c.pending[msg.Header.HopByHopID]
		c.pendingMu.Unlock()
		if ok {
			ch <- msg
		}
	}
}

// readDiameterFrame reads exactly one complete Diameter message from the TCP
// stream. Because TCP is a byte stream, a single Read may return partial data
// or several coalesced messages, so we first read the fixed 20-byte header,
// extract the 24-bit Message Length field, then read the remainder with
// io.ReadFull.
func readDiameterFrame(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, DiameterHeaderLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	// Message Length is a 24-bit big-endian field at bytes 1..3.
	msgLen := int(uint32(hdr[1])<<16 | uint32(hdr[2])<<8 | uint32(hdr[3]))
	if msgLen < DiameterHeaderLen {
		return nil, fmt.Errorf("diameter: invalid message length %d", msgLen)
	}
	full := make([]byte, msgLen)
	copy(full, hdr)
	if msgLen > DiameterHeaderLen {
		if _, err := io.ReadFull(conn, full[DiameterHeaderLen:]); err != nil {
			return nil, err
		}
	}
	return full, nil
}

// ---- DER/DEA (Diameter EAP Request/Answer) ----

// DERRequest holds the parameters for a Diameter-EAP-Request.
type DERRequest struct {
	SessionID   string
	UserName    string // IMSI or NAI
	EAPPayload  []byte // EAP-Response from UE
	CalledStationID string // APN
	ANTrusted   bool
	VisitedNetworkID []byte
}

// DEAResponse holds the decoded Diameter-EAP-Answer.
type DEAResponse struct {
	ResultCode  uint32
	EAPPayload  []byte // EAP-Request to forward to UE
	MSK         []byte // EAP-Master-Session-Key
	UserName    string
	FramedIPv4  net.IP
	FramedIPv6Prefix []byte
}

// SendDER sends a Diameter-EAP-Request and returns the DEA.
func (c *Client) SendDER(req *DERRequest) (*DEAResponse, error) {
	hopByHop := c.nextHopByHop()
	endToEnd := c.nextEndToEnd()

	hdr := &DiameterHeader{
		Version:       1,
		Flags:         FlagRequest | FlagProxiable,
		CommandCode:   CmdDER,
		ApplicationID: AppID3GPPSWm,
		HopByHopID:    hopByHop,
		EndToEndID:    endToEnd,
	}

	avps := [][]byte{
		EncodeStringAVP(AVPSessionID, AVPFlagMandatory, req.SessionID),
		EncodeStringAVP(AVPOriginHost, AVPFlagMandatory, c.originHost),
		EncodeStringAVP(AVPOriginRealm, AVPFlagMandatory, c.originRealm),
		EncodeStringAVP(AVPDestinationRealm, AVPFlagMandatory, c.destRealm),
		EncodeUint32AVP(AVPAuthApplicationID, AVPFlagMandatory, AppID3GPPSWm),
		EncodeUint32AVP(AVPAuthSessionState, AVPFlagMandatory, 1), // NO_STATE_MAINTAINED
		EncodeStringAVP(AVPUserName, AVPFlagMandatory, req.UserName),
		EncodeOctetAVP(AVPEAPPayload, AVPFlagMandatory, req.EAPPayload),
		EncodeStringAVP(AVPCalledStationID, AVPFlagMandatory, req.CalledStationID),
	}
	if req.ANTrusted {
		avps = append(avps, EncodeUint32AVP(AVPANTrusted, AVPFlagMandatory, 1))
	} else {
		avps = append(avps, EncodeUint32AVP(AVPANTrusted, AVPFlagMandatory, 0))
	}
	if len(req.VisitedNetworkID) > 0 {
		avps = append(avps, EncodeOctetAVP(AVPVisitedNetworkID, AVPFlagMandatory, req.VisitedNetworkID))
	}

	raw := EncodeDiameterMessage(hdr, avps)
	resp, err := c.sendRequest(raw, hopByHop)
	if err != nil {
		return nil, fmt.Errorf("DER: %w", err)
	}
	return parseDEA(resp)
}

// parseDEA extracts the DEA fields from a Diameter message.
func parseDEA(msg *DiameterMessage) (*DEAResponse, error) {
	dea := &DEAResponse{}
	if rc, ok := msg.GetResultCode(); ok {
		dea.ResultCode = rc
	}
	if a := msg.FindAVP(AVPEAPPayload); a != nil {
		dea.EAPPayload = a.Data
	}
	if a := msg.FindAVP(AVPEAPMasterSessionKey); a != nil {
		dea.MSK = a.Data
	}
	if a := msg.FindAVP(AVPUserName); a != nil {
		dea.UserName = string(a.Data)
	}
	if a := msg.FindAVP(AVPFramedIPAddress); a != nil && len(a.Data) == 4 {
		dea.FramedIPv4 = net.IP(a.Data)
	}
	if a := msg.FindAVP(AVPFramedIPv6Prefix); a != nil {
		dea.FramedIPv6Prefix = a.Data
	}
	return dea, nil
}

// ---- STR/STA (Session-Termination-Request/Answer) ----

// SendSTR sends a Session-Termination-Request to the AAA server.
func (c *Client) SendSTR(sessionID, userName string, terminationCause uint32) error {
	hopByHop := c.nextHopByHop()
	endToEnd := c.nextEndToEnd()

	hdr := &DiameterHeader{
		Version:       1,
		Flags:         FlagRequest | FlagProxiable,
		CommandCode:   CmdSTR,
		ApplicationID: AppID3GPPSWm,
		HopByHopID:    hopByHop,
		EndToEndID:    endToEnd,
	}
	avps := [][]byte{
		EncodeStringAVP(AVPSessionID, AVPFlagMandatory, sessionID),
		EncodeStringAVP(AVPOriginHost, AVPFlagMandatory, c.originHost),
		EncodeStringAVP(AVPOriginRealm, AVPFlagMandatory, c.originRealm),
		EncodeStringAVP(AVPDestinationRealm, AVPFlagMandatory, c.destRealm),
		EncodeUint32AVP(AVPAuthApplicationID, AVPFlagMandatory, AppID3GPPSWm),
		EncodeStringAVP(AVPUserName, AVPFlagMandatory, userName),
		EncodeUint32AVP(AVPTerminationCause, AVPFlagMandatory, terminationCause),
	}
	raw := EncodeDiameterMessage(hdr, avps)
	_, err := c.sendRequest(raw, hopByHop)
	return err
}
