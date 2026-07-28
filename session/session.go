// Package session manages ePDG UE sessions.
// Based on 3GPP TS 23.402 §4.8 and TS 24.302.
package session

import (
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"ePDG/eap"
	"ePDG/ike/crypto"

	"github.com/google/uuid"
)

// State represents the ePDG session state machine.
type State int

const (
	StateIdle          State = iota // no session
	StateIKEInit                    // IKE_SA_INIT exchanged
	StateEAPIdentity                // waiting for EAP Identity
	StateEAPChallenge               // EAP-AKA challenge sent
	StateIKEAuth                    // IKE_AUTH in progress
	StateConnected                  // fully established
	StateReauthPending              // re-authentication in progress
	StateDisconnecting              // teardown in progress
	StateDisconnected               // session terminated
)

func (s State) String() string {
	names := []string{
		"Idle", "IKEInit", "EAPIdentity", "EAPChallenge",
		"IKEAuth", "Connected", "ReauthPending", "Disconnecting", "Disconnected",
	}
	if int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("State(%d)", int(s))
}

// Session represents a single UE ePDG session.
type Session struct {
	mu sync.RWMutex

	// procMu serialises message processing for this session. IKEv2 is a
	// sequential state machine per SA, so the handler holds this lock for the
	// whole duration of handling one message, which protects all the fields
	// below from concurrent access by multiple receive goroutines. It is kept
	// separate from mu (used by SetState/GetState) so that SetState calls made
	// while processing do not deadlock.
	procMu sync.Mutex

	// Identifiers
	ID        string    // internal UUID
	IMSI      string    // UE IMSI (from EAP identity)
	MSISDN    string    // UE MSISDN (from AAA)
	APN       string    // requested APN
	CreatedAt time.Time
	UpdatedAt time.Time

	// State
	State State

	// IKEv2 SA parameters
	InitiatorSPI [8]byte
	ResponderSPI [8]byte
	// MessageIDi is the next expected Message ID for requests originated by the
	// initiator (UE). Used to detect retransmissions/replays. Responses always
	// echo the request's Message ID (RFC 7296 §2.2) and do NOT use a counter.
	MessageIDi uint32
	// MessageIDr is the next Message ID for requests the ePDG itself originates
	// (e.g. DPD or Delete INFORMATIONAL exchanges), per RFC 7296 §2.2.
	MessageIDr uint32

	// DH key exchange. Only MODP groups are implemented, so the private key is
	// a *big.Int. (If ECP groups are added later this can become an interface
	// or a dedicated type.)
	DHPrivate *big.Int // MODP private exponent
	DHPublic  []byte   // our public key bytes
	DHShared  []byte   // shared secret

	// Nonces
	NonceI []byte // initiator nonce
	NonceR []byte // responder nonce

	// IKE SA keys
	Keys *crypto.IKEKeyMaterial

	// First IKE_SA_INIT message bytes (for AUTH computation)
	InitiatorMsg1 []byte // raw IKE_SA_INIT request
	ResponderMsg1 []byte // raw IKE_SA_INIT response

	// EAP state
	EAPIdentifier uint8
	EAPMethod     uint8  // 23=AKA, 50=AKA'
	RAND          []byte // 16 bytes
	AUTN          []byte // 16 bytes
	XRES          []byte // expected RES
	CK            []byte             // cipher key
	IK            []byte             // integrity key
	EAPKeys       *eap.AKAPrimeKeys  // derived EAP-AKA' key material

	// Network addresses
	UEAddr    *net.UDPAddr // UE source address
	LocalAddr *net.UDPAddr // ePDG local address
	NATDetected bool

	// Assigned IP address (from P-GW via S2b)
	AssignedIPv4 net.IP
	AssignedIPv6 net.IP
	DNS1         net.IP
	DNS2         net.IP

	// GTP-U tunnel
	LocalTEID  uint32 // ePDG TEID
	RemoteTEID uint32 // P-GW TEID
	PGWAddr    *net.UDPAddr

	// Child SA (IPSec)
	ChildSAInboundSPI  uint32
	ChildSAOutboundSPI uint32
	ChildKeys          *crypto.ChildKeyMaterial

	// Diameter session
	DiameterSessionID string
	AuthSessionState  uint32

	// Timers
	SAExpiry    time.Time
	ChildExpiry time.Time
	DPDTimer    *time.Timer
	ReauthTimer *time.Timer
}

// NewSession creates a new ePDG session.
func NewSession(ueAddr *net.UDPAddr) *Session {
	return &Session{
		ID:        uuid.New().String(),
		State:     StateIdle,
		UEAddr:    ueAddr,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// SetState transitions the session to a new state.
func (s *Session) SetState(state State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = state
	s.UpdatedAt = time.Now()
}

// GetState returns the current session state.
func (s *Session) GetState() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.State
}

// BeginProcessing acquires the per-session processing lock. The handler must
// call this before reading or mutating session fields for an incoming message,
// and pair it with EndProcessing (typically via defer). This serialises
// concurrent receive goroutines that target the same session.
func (s *Session) BeginProcessing() {
	s.procMu.Lock()
}

// EndProcessing releases the per-session processing lock.
func (s *Session) EndProcessing() {
	s.procMu.Unlock()
}

// ---- Session Manager ----

// Manager manages all active ePDG sessions.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session // keyed by session ID
	bySPI    map[[8]byte]*Session // keyed by initiator SPI
	byIMSI   map[string]*Session // keyed by IMSI
}

// NewManager creates a new session manager.
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
		bySPI:    make(map[[8]byte]*Session),
		byIMSI:   make(map[string]*Session),
	}
}

// Add registers a new session.
func (m *Manager) Add(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID] = s
	m.bySPI[s.InitiatorSPI] = s
}

// UpdateSPI updates the SPI index after the initiator SPI is known.
func (m *Manager) UpdateSPI(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bySPI[s.InitiatorSPI] = s
}

// UpdateIMSI updates the IMSI index after EAP identity is known.
func (m *Manager) UpdateIMSI(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.IMSI != "" {
		m.byIMSI[s.IMSI] = s
	}
}

// GetByID returns a session by its internal ID.
func (m *Manager) GetByID(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// GetBySPI returns a session by the initiator SPI.
func (m *Manager) GetBySPI(spi [8]byte) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.bySPI[spi]
	return s, ok
}

// GetByIMSI returns a session by IMSI.
func (m *Manager) GetByIMSI(imsi string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.byIMSI[imsi]
	return s, ok
}

// Remove deletes a session from all indexes.
func (m *Manager) Remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return
	}
	delete(m.sessions, id)
	delete(m.bySPI, s.InitiatorSPI)
	if s.IMSI != "" {
		delete(m.byIMSI, s.IMSI)
	}
}

// All returns a snapshot of all sessions.
func (m *Manager) All() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, s)
	}
	return result
}

// Count returns the number of active sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}
