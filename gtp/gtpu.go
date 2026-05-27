// Package gtp implements GTP-U (GPRS Tunnelling Protocol - User Plane).
// Based on 3GPP TS 29.281 and TS 29.274 (GTPv2-C for S2b).
package gtp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"ePDG/logger"
)

// ---- GTP-U Header (3GPP TS 29.281 §5.1) ----

// GTPUHeader is the GTP-U packet header.
type GTPUHeader struct {
	Version         uint8  // must be 1
	ProtocolType    uint8  // 1 = GTP
	ExtensionHeader bool   // E flag
	SequenceNumber  bool   // S flag
	NPDUNumber      bool   // PN flag
	MessageType     uint8
	Length          uint16 // length after mandatory header
	TEID            uint32 // Tunnel Endpoint Identifier
	// Optional fields (present if S, PN, or E flags set)
	SeqNum    uint16
	NPDUNum   uint8
	NextExtHdrType uint8
}

// GTP-U Message Types (TS 29.281 §8.1)
const (
	MsgTypeEchoRequest    uint8 = 1
	MsgTypeEchoResponse   uint8 = 2
	MsgTypeErrorIndication uint8 = 26
	MsgTypeSupportedExtHdrNotification uint8 = 31
	MsgTypeEndMarker      uint8 = 254
	MsgTypeGPDU           uint8 = 255 // G-PDU (user data)
)

const GTPUMandatoryHeaderLen = 8
const GTPUOptionalHeaderLen = 4 // SeqNum(2) + NPDUNum(1) + NextExtHdr(1)

// Encode serialises the GTP-U header.
func (h *GTPUHeader) Encode() []byte {
	hasOptional := h.ExtensionHeader || h.SequenceNumber || h.NPDUNumber
	headerLen := GTPUMandatoryHeaderLen
	if hasOptional {
		headerLen += GTPUOptionalHeaderLen
	}
	b := make([]byte, headerLen)
	flags := uint8(0x20) // version=1, PT=0 (GTP')
	flags |= 0x10        // PT=1 (GTP)
	if h.ExtensionHeader {
		flags |= 0x04
	}
	if h.SequenceNumber {
		flags |= 0x02
	}
	if h.NPDUNumber {
		flags |= 0x01
	}
	b[0] = flags
	b[1] = h.MessageType
	binary.BigEndian.PutUint16(b[2:4], h.Length)
	binary.BigEndian.PutUint32(b[4:8], h.TEID)
	if hasOptional {
		binary.BigEndian.PutUint16(b[8:10], h.SeqNum)
		b[10] = h.NPDUNum
		b[11] = h.NextExtHdrType
	}
	return b
}

// DecodeGTPUHeader parses a GTP-U header from a byte slice.
func DecodeGTPUHeader(b []byte) (*GTPUHeader, int, error) {
	if len(b) < GTPUMandatoryHeaderLen {
		return nil, 0, fmt.Errorf("GTP-U: header too short")
	}
	flags := b[0]
	version := (flags >> 5) & 0x07
	if version != 1 {
		return nil, 0, fmt.Errorf("GTP-U: unsupported version %d", version)
	}
	h := &GTPUHeader{
		Version:         version,
		ProtocolType:    (flags >> 4) & 0x01,
		ExtensionHeader: flags&0x04 != 0,
		SequenceNumber:  flags&0x02 != 0,
		NPDUNumber:      flags&0x01 != 0,
		MessageType:     b[1],
		Length:          binary.BigEndian.Uint16(b[2:4]),
		TEID:            binary.BigEndian.Uint32(b[4:8]),
	}
	headerLen := GTPUMandatoryHeaderLen
	if h.ExtensionHeader || h.SequenceNumber || h.NPDUNumber {
		if len(b) < GTPUMandatoryHeaderLen+GTPUOptionalHeaderLen {
			return nil, 0, fmt.Errorf("GTP-U: optional header truncated")
		}
		h.SeqNum = binary.BigEndian.Uint16(b[8:10])
		h.NPDUNum = b[10]
		h.NextExtHdrType = b[11]
		headerLen += GTPUOptionalHeaderLen
	}
	return h, headerLen, nil
}

// ---- TEID Allocator ----

var teidCounter uint32 = 0x10000000

// AllocateTEID allocates a new unique TEID.
func AllocateTEID() uint32 {
	return atomic.AddUint32(&teidCounter, 1)
}

// ---- GTP-U Tunnel ----

// Tunnel represents a GTP-U tunnel between ePDG and P-GW.
type Tunnel struct {
	LocalTEID  uint32
	RemoteTEID uint32
	RemoteAddr *net.UDPAddr
	SessionID  string // associated ePDG session ID
}

// ---- GTP-U Server ----

// PacketHandler is called for each received G-PDU.
type PacketHandler func(teid uint32, payload []byte, src *net.UDPAddr)

// Server is the GTP-U UDP server.
type Server struct {
	mu       sync.RWMutex
	conn     *net.UDPConn
	addr     string
	tunnels  map[uint32]*Tunnel // keyed by local TEID
	handler  PacketHandler
	bufSize  int
	stopCh   chan struct{}
}

// NewServer creates a new GTP-U server.
func NewServer(addr string, bufSize int, handler PacketHandler) *Server {
	if bufSize <= 0 {
		bufSize = 65535
	}
	return &Server{
		addr:    addr,
		tunnels: make(map[uint32]*Tunnel),
		handler: handler,
		bufSize: bufSize,
		stopCh:  make(chan struct{}),
	}
}

// Start binds the UDP socket and starts the receive loop.
func (s *Server) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp4", s.addr)
	if err != nil {
		return fmt.Errorf("GTP-U: resolve addr %s: %w", s.addr, err)
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return fmt.Errorf("GTP-U: listen %s: %w", s.addr, err)
	}
	s.conn = conn
	logger.Infof("GTP-U server listening on %s", s.addr)
	go s.receiveLoop()
	return nil
}

// Stop shuts down the GTP-U server.
func (s *Server) Stop() {
	close(s.stopCh)
	if s.conn != nil {
		s.conn.Close()
	}
}

// AddTunnel registers a GTP-U tunnel.
func (s *Server) AddTunnel(t *Tunnel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnels[t.LocalTEID] = t
}

// RemoveTunnel removes a GTP-U tunnel by local TEID.
func (s *Server) RemoveTunnel(localTEID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tunnels, localTEID)
}

// GetTunnel returns a tunnel by local TEID.
func (s *Server) GetTunnel(localTEID uint32) (*Tunnel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tunnels[localTEID]
	return t, ok
}

// SendGPDU sends a G-PDU through the specified tunnel.
func (s *Server) SendGPDU(tunnel *Tunnel, payload []byte) error {
	hdr := &GTPUHeader{
		Version:     1,
		MessageType: MsgTypeGPDU,
		Length:      uint16(len(payload)),
		TEID:        tunnel.RemoteTEID,
	}
	packet := append(hdr.Encode(), payload...)
	_, err := s.conn.WriteToUDP(packet, tunnel.RemoteAddr)
	if err != nil {
		return fmt.Errorf("GTP-U send: %w", err)
	}
	return nil
}

// receiveLoop reads GTP-U packets and dispatches them.
func (s *Server) receiveLoop() {
	buf := make([]byte, s.bufSize)
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				logger.Errorf("GTP-U receive error: %v", err)
				continue
			}
		}
		s.handlePacket(buf[:n], src)
	}
}

// handlePacket processes a received GTP-U packet.
func (s *Server) handlePacket(b []byte, src *net.UDPAddr) {
	hdr, headerLen, err := DecodeGTPUHeader(b)
	if err != nil {
		logger.Warnf("GTP-U: decode header from %s: %v", src, err)
		return
	}
	switch hdr.MessageType {
	case MsgTypeGPDU:
		payload := b[headerLen:]
		if s.handler != nil {
			s.handler(hdr.TEID, payload, src)
		}
	case MsgTypeEchoRequest:
		s.sendEchoResponse(src, hdr.SeqNum)
	case MsgTypeEndMarker:
		logger.Infof("GTP-U: End Marker received from %s, TEID=0x%08x", src, hdr.TEID)
	default:
		logger.Debugf("GTP-U: unhandled message type %d from %s", hdr.MessageType, src)
	}
}

// sendEchoResponse sends a GTP-U Echo Response.
func (s *Server) sendEchoResponse(dst *net.UDPAddr, seqNum uint16) {
	hdr := &GTPUHeader{
		Version:        1,
		MessageType:    MsgTypeEchoResponse,
		Length:         4,
		TEID:           0,
		SequenceNumber: true,
		SeqNum:         seqNum,
	}
	// Recovery IE (type=14, value=0)
	recovery := []byte{14, 0, 0, 1, 0}
	packet := append(hdr.Encode(), recovery...)
	s.conn.WriteToUDP(packet, dst)
}
