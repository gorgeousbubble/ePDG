// Package handler implements the IKEv2 message handler for ePDG.
// Based on RFC 7296 and 3GPP TS 24.302.
package handler

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"ePDG/config"
	"ePDG/diameter"
	"ePDG/eap"
	ikecrypto "ePDG/ike/crypto"
	"ePDG/ike/message"
	"ePDG/logger"
	"ePDG/session"
)

// Handler processes IKEv2 messages and drives the ePDG state machine.
type Handler struct {
	cfg        *config.Config
	sessions   *session.Manager
	diameter   *diameter.Client
	cert       tls.Certificate
	caCertPool *x509.CertPool
	localSPI   [8]byte // ePDG responder SPI prefix (random per instance)
	spiCounter uint64
	mu         sync.Mutex
}

// New creates a new IKEv2 handler.
func New(cfg *config.Config, sessions *session.Manager, diam *diameter.Client) (*Handler, error) {
	ePDGCfg := cfg.GetePDG()
	cert, err := tls.LoadX509KeyPair(ePDGCfg.CertFile, ePDGCfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("IKE handler: load cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if ePDGCfg.CAFile != "" {
		caPEM, err := os.ReadFile(ePDGCfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("IKE handler: load CA: %w", err)
		}
		caCertPool.AppendCertsFromPEM(caPEM)
	}
	h := &Handler{
		cfg:        cfg,
		sessions:   sessions,
		diameter:   diam,
		cert:       cert,
		caCertPool: caCertPool,
	}
	// generate random SPI prefix
	rand.Read(h.localSPI[:])
	return h, nil
}

// HandleMessage is the main entry point for received IKEv2 messages.
func (h *Handler) HandleMessage(raw []byte, src *net.UDPAddr, conn *net.UDPConn) {
	// strip NAT-T non-ESP marker if present
	if len(raw) > 4 && raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 {
		raw = raw[4:]
	}
	hdr, err := message.DecodeIKEHeader(raw)
	if err != nil {
		logger.Warnf("IKE: decode header from %s: %v", src, err)
		return
	}
	logger.Debugf("IKE: %s from %s msgID=%d", hdr.ExchangeType, src, hdr.MessageID)

	switch hdr.ExchangeType {
	case message.IKE_SA_INIT:
		if !hdr.IsResponse() {
			h.handleIKESAInit(raw, hdr, src, conn)
		}
	case message.IKE_AUTH:
		if !hdr.IsResponse() {
			h.handleIKEAuth(raw, hdr, src, conn)
		}
	case message.INFORMATIONAL:
		h.handleInformational(raw, hdr, src, conn)
	case message.CREATE_CHILD_SA:
		if !hdr.IsResponse() {
			h.handleCreateChildSA(raw, hdr, src, conn)
		}
	default:
		logger.Warnf("IKE: unhandled exchange type %s from %s", hdr.ExchangeType, src)
	}
}

// ---- IKE_SA_INIT ----

// handleIKESAInit processes an IKE_SA_INIT request (RFC 7296 §1.2).
func (h *Handler) handleIKESAInit(raw []byte, hdr *message.IKEHeader, src *net.UDPAddr, conn *net.UDPConn) {
	msg, err := message.DecodeIKEMessage(raw)
	if err != nil {
		logger.Warnf("IKE_SA_INIT: decode from %s: %v", src, err)
		return
	}

	// Extract KE payload
	kePayload, ok := msg.FindPayload(message.PayloadTypeKE).(*message.KEPayload)
	if !ok {
		h.sendNotify(conn, src, hdr, message.NotifyInvalidSyntax, nil)
		return
	}

	// Extract Nonce payload
	noncePayload, ok := msg.FindPayload(message.PayloadTypeNonce).(*message.NoncePayload)
	if !ok {
		h.sendNotify(conn, src, hdr, message.NotifyInvalidSyntax, nil)
		return
	}

	// Extract SA payload and select proposal
	saPayload, ok := msg.FindPayload(message.PayloadTypeSA).(*message.SAPayload)
	if !ok {
		h.sendNotify(conn, src, hdr, message.NotifyNoProposalChosen, nil)
		return
	}
	selectedProposal := h.selectIKEProposal(saPayload)
	if selectedProposal == nil {
		h.sendNotify(conn, src, hdr, message.NotifyNoProposalChosen, nil)
		return
	}

	// Perform DH key exchange (MODP-2048)
	dhGroup := ikecrypto.DHMODP2048
	peerPublicBytes := kePayload.KeyData
	peerPublic := new(big.Int).SetBytes(peerPublicBytes)
	dhPrivate, dhPublic, err := ikecrypto.GenerateDHKeyPair(dhGroup)
	if err != nil {
		logger.Errorf("IKE_SA_INIT: DH keygen: %v", err)
		return
	}
	dhShared := ikecrypto.ComputeDHSharedSecret(dhGroup, dhPrivate, peerPublic)

	// Generate responder nonce
	nonceR, err := ikecrypto.GenerateNonce(32)
	if err != nil {
		logger.Errorf("IKE_SA_INIT: nonce: %v", err)
		return
	}

	// Generate responder SPI
	var respSPI [8]byte
	rand.Read(respSPI[:])

	// Derive IKE SA keys
	keys := ikecrypto.DeriveIKEKeys(dhShared, noncePayload.NonceData, nonceR,
		hdr.InitiatorSPI, respSPI)

	// Build IKE_SA_INIT response
	respHdr := &message.IKEHeader{
		InitiatorSPI: hdr.InitiatorSPI,
		ResponderSPI: respSPI,
		MajorVersion: 2,
		ExchangeType: message.IKE_SA_INIT,
		Flags:        message.FlagResponse,
		MessageID:    hdr.MessageID,
	}

	// Build SA payload (echo selected proposal)
	respSA := &message.SAPayload{Proposals: []message.Proposal{*selectedProposal}}
	respSA.Proposals[0].Number = 1

	// Build KE payload
	dhPubBytes := dhPublic.Bytes()
	// pad to group key size
	if len(dhPubBytes) < dhGroup.KeySize {
		padded := make([]byte, dhGroup.KeySize)
		copy(padded[dhGroup.KeySize-len(dhPubBytes):], dhPubBytes)
		dhPubBytes = padded
	}
	respKE := &message.KEPayload{
		DHGroupNum: dhGroup.ID,
		KeyData:    dhPubBytes,
	}

	// Build Nonce payload
	respNonce := &message.NoncePayload{NonceData: nonceR}

	// NAT detection
	localIP := net.ParseIP(h.cfg.GetePDG().PublicIP)
	if localIP == nil {
		localIP = net.IPv4(127, 0, 0, 1)
	}
	natSrcHash := ikecrypto.NATDetectionHash(hdr.InitiatorSPI, respSPI, src.IP, uint16(src.Port))
	natDstHash := ikecrypto.NATDetectionHash(hdr.InitiatorSPI, respSPI, localIP.To4(), 500)

	natSrcNotify := &message.NotifyPayload{
		NotifyType: message.NotifyNATDetectionSourceIP,
		NotifyData: natSrcHash,
	}
	natDstNotify := &message.NotifyPayload{
		NotifyType: message.NotifyNATDetectionDestinationIP,
		NotifyData: natDstHash,
	}

	respMsg := &message.IKEMessage{
		Header: respHdr,
		Payloads: []message.IKEPayload{
			respSA, respKE, respNonce, natSrcNotify, natDstNotify,
		},
	}
	respRaw, err := respMsg.Encode()
	if err != nil {
		logger.Errorf("IKE_SA_INIT: encode response: %v", err)
		return
	}

	// Create session
	sess := session.NewSession(src)
	sess.InitiatorSPI = hdr.InitiatorSPI
	sess.ResponderSPI = respSPI
	sess.NonceI = noncePayload.NonceData
	sess.NonceR = nonceR
	sess.DHPrivate = dhPrivate
	sess.DHPublic = dhPubBytes
	sess.DHShared = dhShared
	sess.Keys = keys
	sess.InitiatorMsg1 = raw
	sess.ResponderMsg1 = respRaw
	sess.MessageIDi = 1
	sess.SetState(session.StateIKEInit)
	sess.SAExpiry = time.Now().Add(h.cfg.GetIKE().SALifetime)

	h.sessions.Add(sess)
	h.sessions.UpdateSPI(sess)

	// Send response
	h.sendRaw(conn, src, respRaw)
	logger.Infof("IKE_SA_INIT: session %s created for %s", sess.ID, src)
}

// selectIKEProposal selects the first acceptable IKE SA proposal.
func (h *Handler) selectIKEProposal(sa *message.SAPayload) *message.Proposal {
	for i := range sa.Proposals {
		p := &sa.Proposals[i]
		if p.ProtocolID == 1 { // IKE
			return p
		}
	}
	return nil
}

// ---- IKE_AUTH ----

// handleIKEAuth processes an IKE_AUTH request (RFC 7296 §2.18, 3GPP TS 24.302 §7.2).
func (h *Handler) handleIKEAuth(raw []byte, hdr *message.IKEHeader, src *net.UDPAddr, conn *net.UDPConn) {
	// Find session by initiator SPI
	sess, ok := h.sessions.GetBySPI(hdr.InitiatorSPI)
	if !ok {
		logger.Warnf("IKE_AUTH: no session for SPI %x from %s", hdr.InitiatorSPI, src)
		return
	}

	// Decrypt SK payload
	skPayload, ok2 := findSKPayload(raw)
	if !ok2 {
		logger.Warnf("IKE_AUTH: no SK payload from %s", src)
		return
	}
	decrypted, err := h.decryptSK(sess, skPayload, raw, false)
	if err != nil {
		logger.Warnf("IKE_AUTH: decrypt SK: %v", err)
		return
	}

	// Parse inner payloads
	innerMsg, err := parseInnerPayloads(decrypted, hdr.NextPayload)
	if err != nil {
		logger.Warnf("IKE_AUTH: parse inner: %v", err)
		return
	}

	// Extract IDi
	idPayload, _ := innerMsg.FindPayload(message.PayloadTypeIDi).(*message.IDPayload)
	if idPayload == nil {
		h.sendEncryptedNotify(conn, src, sess, message.NotifyInvalidSyntax, nil)
		return
	}

	// Extract EAP payload (first IKE_AUTH has EAP-Response/Identity)
	eapPayload, _ := innerMsg.FindPayload(message.PayloadTypeEAP).(*message.EAPPayload)

	// Extract CP payload (IPCP request)
	cpPayload, _ := innerMsg.FindPayload(message.PayloadTypeCP).(*message.CPPayload)

	// Extract TS payloads
	tsiPayload, _ := innerMsg.FindPayload(message.PayloadTypeTSi).(*message.TSPayload)
	tsrPayload, _ := innerMsg.FindPayload(message.PayloadTypeTSr).(*message.TSPayload)

	switch sess.GetState() {
	case session.StateIKEInit:
		// First IKE_AUTH: start EAP exchange
		h.startEAPExchange(conn, src, sess, hdr, idPayload, eapPayload)
	case session.StateEAPChallenge:
		// Subsequent IKE_AUTH: EAP-Response from UE
		h.continueEAPExchange(conn, src, sess, hdr, eapPayload, cpPayload, tsiPayload, tsrPayload)
	default:
		logger.Warnf("IKE_AUTH: unexpected state %s for session %s", sess.GetState(), sess.ID)
	}
}

// startEAPExchange initiates the EAP-AKA' exchange via Diameter SWm.
func (h *Handler) startEAPExchange(conn *net.UDPConn, src *net.UDPAddr, sess *session.Session,
	hdr *message.IKEHeader, idPayload *message.IDPayload, eapPayload *message.EAPPayload) {

	// Determine NAI/IMSI from IDi
	nai := string(idPayload.IDData)
	sess.IMSI = extractIMSI(nai)
	h.sessions.UpdateIMSI(sess)

	// Build EAP-Response/Identity to send to AAA
	var eapIdentity []byte
	if eapPayload != nil {
		eapIdentity = eapPayload.EAPMessage
	} else {
		// Build EAP-Response/Identity from IDi
		eapIdentity = buildEAPResponseIdentity(sess.EAPIdentifier, nai)
	}

	// Send DER to AAA server
	derReq := &diameter.DERRequest{
		SessionID:       sess.DiameterSessionID,
		UserName:        nai,
		EAPPayload:      eapIdentity,
		CalledStationID: sess.APN,
		ANTrusted:       false,
		VisitedNetworkID: []byte(h.cfg.GetePDG().PLMN),
	}
	if sess.DiameterSessionID == "" {
		sess.DiameterSessionID = fmt.Sprintf("%s;%d;%d", h.cfg.GetDiameter().OriginHost,
			time.Now().Unix(), sess.EAPIdentifier)
	}
	derReq.SessionID = sess.DiameterSessionID

	dea, err := h.diameter.SendDER(derReq)
	if err != nil {
		logger.Errorf("IKE_AUTH: DER failed for %s: %v", nai, err)
		h.sendEncryptedNotify(conn, src, sess, message.NotifyAuthenticationFailed, nil)
		return
	}

	if dea.ResultCode != diameter.ResultSuccess && dea.ResultCode != diameter.ResultLimitedSuccess {
		logger.Warnf("IKE_AUTH: AAA rejected %s: result=%d", nai, dea.ResultCode)
		h.sendEncryptedNotify(conn, src, sess, message.NotifyAuthenticationFailed, nil)
		return
	}

	// Forward EAP-Request (AKA-Challenge) to UE in IKE_AUTH response
	sess.SetState(session.StateEAPChallenge)
	sess.EAPIdentifier++

	h.sendIKEAuthWithEAP(conn, src, sess, hdr, dea.EAPPayload)
	logger.Infof("IKE_AUTH: EAP-AKA challenge sent to %s (IMSI=%s)", src, sess.IMSI)
}

// continueEAPExchange processes the UE's EAP-Response and completes authentication.
func (h *Handler) continueEAPExchange(conn *net.UDPConn, src *net.UDPAddr, sess *session.Session,
	hdr *message.IKEHeader, eapPayload *message.EAPPayload,
	cpPayload *message.CPPayload, tsiPayload, tsrPayload *message.TSPayload) {

	if eapPayload == nil {
		h.sendEncryptedNotify(conn, src, sess, message.NotifyAuthenticationFailed, nil)
		return
	}

	// Forward EAP-Response to AAA
	derReq := &diameter.DERRequest{
		SessionID:       sess.DiameterSessionID,
		UserName:        sess.IMSI,
		EAPPayload:      eapPayload.EAPMessage,
		CalledStationID: sess.APN,
		ANTrusted:       false,
	}
	dea, err := h.diameter.SendDER(derReq)
	if err != nil {
		logger.Errorf("IKE_AUTH: DER (challenge response) failed: %v", err)
		h.sendEncryptedNotify(conn, src, sess, message.NotifyAuthenticationFailed, nil)
		return
	}

	// Check if EAP-Success
	if dea.ResultCode == diameter.ResultSuccess && len(dea.EAPPayload) > 0 {
		eapMsg, _ := eap.Decode(dea.EAPPayload)
		if eapMsg != nil && eapMsg.Code == eap.CodeSuccess {
			// Authentication succeeded - complete IKE_AUTH
			h.completeIKEAuth(conn, src, sess, hdr, dea, cpPayload, tsiPayload, tsrPayload)
			return
		}
	}

	// Another EAP round (e.g. re-sync)
	if dea.ResultCode == diameter.ResultLimitedSuccess {
		h.sendIKEAuthWithEAP(conn, src, sess, hdr, dea.EAPPayload)
		return
	}

	// Authentication failed
	logger.Warnf("IKE_AUTH: EAP authentication failed for IMSI=%s", sess.IMSI)
	h.sendEncryptedNotify(conn, src, sess, message.NotifyAuthenticationFailed, nil)
	sess.SetState(session.StateDisconnected)
	h.sessions.Remove(sess.ID)
}

// completeIKEAuth finalises the IKE_AUTH exchange after successful EAP.
func (h *Handler) completeIKEAuth(conn *net.UDPConn, src *net.UDPAddr, sess *session.Session,
	hdr *message.IKEHeader, dea *diameter.DEAResponse,
	cpPayload *message.CPPayload, tsiPayload, tsrPayload *message.TSPayload) {

	// Assign IP address from P-GW response or AAA
	assignedIP := dea.FramedIPv4
	if assignedIP == nil {
		assignedIP = net.IPv4(10, 0, 0, 1) // fallback
	}
	sess.AssignedIPv4 = assignedIP

	// Allocate Child SA SPIs
	childSPIIn := allocateSPI()
	sess.ChildSAInboundSPI = childSPIIn

	// Derive Child SA keys
	childKeys := ikecrypto.DeriveChildKeys(sess.Keys.SK_d, sess.NonceI, sess.NonceR, 32, 16)
	sess.ChildKeys = childKeys

	// Build IKE_AUTH response payloads
	// IDr payload
	idrPayload := &message.IDPayload{}
	idrPayload = buildIDrPayload(h.cfg.GetePDG().FQDN)

	// AUTH payload (shared-key based on EAP MSK)
	authData := ikecrypto.ComputeAuthPayload(
		sess.Keys.SK_pr,
		sess.ResponderMsg1,
		sess.NonceI,
		buildIDrBody(h.cfg.GetePDG().FQDN),
	)
	authPayload := &message.AUTHPayload{
		AuthMethod: message.AuthMethodSharedKey,
		AuthData:   authData,
	}

	// EAP-Success payload
	eapSuccessMsg := buildEAPSuccess(sess.EAPIdentifier)
	eapSuccessPayload := &message.EAPPayload{EAPMessage: eapSuccessMsg}

	// CP (Configuration) reply with assigned IP
	cpReply := buildCPReply(assignedIP, sess.DNS1, sess.DNS2)

	// SA payload for Child SA
	childSA := buildChildSAPayload(childSPIIn)

	// TS payloads (accept what UE requested)
	tsiReply := tsiPayload
	tsrReply := tsrPayload
	if tsiReply == nil {
		tsiReply = buildDefaultTSi()
	}
	if tsrReply == nil {
		tsrReply = buildDefaultTSr()
	}

	innerPayloads := []message.IKEPayload{
		idrPayload, authPayload, eapSuccessPayload, cpReply, childSA, tsiReply, tsrReply,
	}

	// Encrypt and send
	if err := h.sendEncryptedIKEAuth(conn, src, sess, hdr, innerPayloads); err != nil {
		logger.Errorf("IKE_AUTH: send response: %v", err)
		return
	}

	sess.SetState(session.StateConnected)
	sess.ChildExpiry = time.Now().Add(h.cfg.GetIKE().ChildSALifetime)
	logger.Infof("IKE_AUTH: session %s connected, IMSI=%s, IP=%s", sess.ID, sess.IMSI, assignedIP)
}

// ---- INFORMATIONAL ----

func (h *Handler) handleInformational(raw []byte, hdr *message.IKEHeader, src *net.UDPAddr, conn *net.UDPConn) {
	sess, ok := h.sessions.GetBySPI(hdr.InitiatorSPI)
	if !ok {
		return
	}
	// Decrypt
	skPayload, ok2 := findSKPayload(raw)
	if !ok2 {
		return
	}
	decrypted, err := h.decryptSK(sess, skPayload, raw, false)
	if err != nil {
		return
	}
	innerMsg, err := parseInnerPayloads(decrypted, hdr.NextPayload)
	if err != nil {
		return
	}

	// Check for Delete payload
	for _, p := range innerMsg.Payloads {
		if del, ok := p.(*message.DeletePayload); ok {
			if del.ProtocolID == 1 { // IKE SA delete
				logger.Infof("INFORMATIONAL: IKE SA delete from %s (session %s)", src, sess.ID)
				h.sendEmptyInformationalResponse(conn, src, sess, hdr)
				sess.SetState(session.StateDisconnected)
				h.sessions.Remove(sess.ID)
				return
			}
		}
	}

	// DPD keepalive - send empty response
	h.sendEmptyInformationalResponse(conn, src, sess, hdr)
}

// ---- CREATE_CHILD_SA ----

func (h *Handler) handleCreateChildSA(raw []byte, hdr *message.IKEHeader, src *net.UDPAddr, conn *net.UDPConn) {
	sess, ok := h.sessions.GetBySPI(hdr.InitiatorSPI)
	if !ok {
		return
	}
	logger.Debugf("CREATE_CHILD_SA: session %s", sess.ID)
	// For now, send TEMPORARY_FAILURE to decline child SA rekey
	h.sendEncryptedNotify(conn, src, sess, message.NotifyTemporaryFailure, nil)
}

// ---- Crypto helpers ----

// decryptSK decrypts an SK payload using the session keys.
// isInitiator=true uses SK_ei/SK_ai, false uses SK_er/SK_ar.
func (h *Handler) decryptSK(sess *session.Session, skData, fullMsg []byte, isInitiator bool) ([]byte, error) {
	var encKey, integKey []byte
	if isInitiator {
		encKey = sess.Keys.SK_ei
		integKey = sess.Keys.SK_ai
	} else {
		encKey = sess.Keys.SK_er
		integKey = sess.Keys.SK_ar
	}
	// Verify integrity: ICV is last 16 bytes
	if len(skData) < 16 {
		return nil, fmt.Errorf("SK: too short for ICV")
	}
	icv := skData[len(skData)-16:]
	protected := fullMsg[:len(fullMsg)-16]
	if !ikecrypto.VerifyIntegrity(integKey, protected, icv) {
		return nil, fmt.Errorf("SK: integrity check failed")
	}
	// Decrypt
	ciphertext := skData[:len(skData)-16]
	plaintext, err := ikecrypto.DecryptAESCBC(encKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("SK: decrypt: %w", err)
	}
	// Remove padding: last byte is pad length
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("SK: empty plaintext")
	}
	padLen := int(plaintext[len(plaintext)-1])
	if padLen+1 > len(plaintext) {
		return nil, fmt.Errorf("SK: invalid padding")
	}
	return plaintext[:len(plaintext)-padLen-1], nil
}

// encryptSK encrypts inner payloads into an SK payload.
func (h *Handler) encryptSK(sess *session.Session, innerPayloads []byte, isInitiator bool) ([]byte, error) {
	var encKey, integKey []byte
	if isInitiator {
		encKey = sess.Keys.SK_ei
		integKey = sess.Keys.SK_ai
	} else {
		encKey = sess.Keys.SK_er
		integKey = sess.Keys.SK_ar
	}
	// Add padding: pad to AES block size (16), last byte = pad length
	blockSize := 16
	padLen := blockSize - ((len(innerPayloads) + 1) % blockSize)
	if padLen == blockSize {
		padLen = 0
	}
	padded := make([]byte, len(innerPayloads)+padLen+1)
	copy(padded, innerPayloads)
	padded[len(padded)-1] = byte(padLen)

	// Encrypt
	ciphertext, err := ikecrypto.EncryptAESCBC(encKey, padded)
	if err != nil {
		return nil, err
	}

	// Compute ICV over (header + SK header + ciphertext)
	// ICV placeholder is 16 zero bytes appended
	icvPlaceholder := make([]byte, 16)
	toSign := append(ciphertext, icvPlaceholder...)
	icv := ikecrypto.IntegrityHMACSHA256_128(integKey, toSign)

	return append(ciphertext, icv...), nil
}

// ---- Send helpers ----

func (h *Handler) sendRaw(conn *net.UDPConn, dst *net.UDPAddr, data []byte) {
	if _, err := conn.WriteToUDP(data, dst); err != nil {
		logger.Errorf("IKE: send to %s: %v", dst, err)
	}
}

func (h *Handler) sendNotify(conn *net.UDPConn, dst *net.UDPAddr, reqHdr *message.IKEHeader,
	notifyType message.NotifyType, data []byte) {
	respHdr := &message.IKEHeader{
		InitiatorSPI: reqHdr.InitiatorSPI,
		ResponderSPI: reqHdr.ResponderSPI,
		MajorVersion: 2,
		ExchangeType: reqHdr.ExchangeType,
		Flags:        message.FlagResponse,
		MessageID:    reqHdr.MessageID,
	}
	notify := &message.NotifyPayload{NotifyType: notifyType, NotifyData: data}
	msg := &message.IKEMessage{Header: respHdr, Payloads: []message.IKEPayload{notify}}
	raw, err := msg.Encode()
	if err != nil {
		logger.Errorf("IKE: encode notify: %v", err)
		return
	}
	h.sendRaw(conn, dst, raw)
}

func (h *Handler) sendEncryptedNotify(conn *net.UDPConn, dst *net.UDPAddr, sess *session.Session,
	notifyType message.NotifyType, data []byte) {
	notify := &message.NotifyPayload{NotifyType: notifyType, NotifyData: data}
	h.sendEncryptedResponse(conn, dst, sess, message.INFORMATIONAL, []message.IKEPayload{notify})
}

func (h *Handler) sendIKEAuthWithEAP(conn *net.UDPConn, dst *net.UDPAddr, sess *session.Session,
	reqHdr *message.IKEHeader, eapMsg []byte) {
	eapPayload := &message.EAPPayload{EAPMessage: eapMsg}
	h.sendEncryptedResponse(conn, dst, sess, message.IKE_AUTH, []message.IKEPayload{eapPayload})
}

func (h *Handler) sendEncryptedIKEAuth(conn *net.UDPConn, dst *net.UDPAddr, sess *session.Session,
	reqHdr *message.IKEHeader, payloads []message.IKEPayload) error {
	return h.sendEncryptedResponse(conn, dst, sess, message.IKE_AUTH, payloads)
}

func (h *Handler) sendEmptyInformationalResponse(conn *net.UDPConn, dst *net.UDPAddr,
	sess *session.Session, reqHdr *message.IKEHeader) {
	h.sendEncryptedResponse(conn, dst, sess, message.INFORMATIONAL, nil)
}

func (h *Handler) sendEncryptedResponse(conn *net.UDPConn, dst *net.UDPAddr, sess *session.Session,
	exchangeType message.ExchangeType, payloads []message.IKEPayload) error {

	// Encode inner payloads
	var innerBytes []byte
	nextType := message.PayloadTypeNone
	for i := len(payloads) - 1; i >= 0; i-- {
		p := payloads[i]
		body, err := p.Encode()
		if err != nil {
			return fmt.Errorf("encode payload %s: %w", p.Type(), err)
		}
		ph := &message.PayloadHeader{
			NextPayload:   nextType,
			PayloadLength: uint16(message.PayloadHeaderLen + len(body)),
		}
		chunk := append(ph.Encode(), body...)
		innerBytes = append(chunk, innerBytes...)
		nextType = p.Type()
	}

	// Encrypt
	skData, err := h.encryptSK(sess, innerBytes, false) // false = responder
	if err != nil {
		return fmt.Errorf("encrypt SK: %w", err)
	}

	// Build outer message
	respHdr := &message.IKEHeader{
		InitiatorSPI: sess.InitiatorSPI,
		ResponderSPI: sess.ResponderSPI,
		MajorVersion: 2,
		ExchangeType: exchangeType,
		Flags:        message.FlagResponse,
		MessageID:    sess.MessageIDr,
	}
	sess.MessageIDr++

	skPayload := &message.SKPayload{EncryptedData: skData}
	msg := &message.IKEMessage{Header: respHdr, Payloads: []message.IKEPayload{skPayload}}
	raw, err := msg.Encode()
	if err != nil {
		return fmt.Errorf("encode message: %w", err)
	}
	h.sendRaw(conn, dst, raw)
	return nil
}

// ---- Utility functions ----

func findSKPayload(raw []byte) ([]byte, bool) {
	if len(raw) < message.IKEHeaderLen+message.PayloadHeaderLen {
		return nil, false
	}
	nextType := message.PayloadType(raw[16])
	offset := message.IKEHeaderLen
	msgLen := int(binary.BigEndian.Uint32(raw[24:28]))
	for nextType != message.PayloadTypeNone && offset < msgLen {
		if offset+message.PayloadHeaderLen > msgLen {
			return nil, false
		}
		ph, err := message.DecodePayloadHeader(raw[offset:])
		if err != nil {
			return nil, false
		}
		end := offset + int(ph.PayloadLength)
		if nextType == message.PayloadTypeSK {
			return raw[offset+message.PayloadHeaderLen : end], true
		}
		nextType = ph.NextPayload
		offset = end
	}
	return nil, false
}

func parseInnerPayloads(decrypted []byte, firstType message.PayloadType) (*message.IKEMessage, error) {
	// Wrap in a fake IKE message for parsing
	fakeHdr := &message.IKEHeader{
		MajorVersion: 2,
		NextPayload:  firstType,
		Length:       uint32(message.IKEHeaderLen + len(decrypted)),
	}
	fake := append(fakeHdr.Encode(), decrypted...)
	return message.DecodeIKEMessage(fake)
}

func extractIMSI(nai string) string {
	// NAI format: 0<IMSI>@nai.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org
	if len(nai) > 1 && nai[0] == '0' {
		for i, c := range nai[1:] {
			if c == '@' {
				return nai[1 : i+1]
			}
		}
	}
	return nai
}

func buildEAPResponseIdentity(id uint8, identity string) []byte {
	// EAP-Response/Identity: Code=2, ID, Length, Type=1, Identity
	body := append([]byte{1}, []byte(identity)...)
	totalLen := 4 + len(body)
	b := make([]byte, 4)
	b[0] = 2 // Response
	b[1] = id
	binary.BigEndian.PutUint16(b[2:4], uint16(totalLen))
	return append(b, body...)
}

func buildEAPSuccess(id uint8) []byte {
	b := make([]byte, 4)
	b[0] = 3 // Success
	b[1] = id
	binary.BigEndian.PutUint16(b[2:4], 4)
	return b
}

func buildIDrPayload(fqdn string) *message.IDPayload {
	return &message.IDPayload{}
}

func buildIDrBody(fqdn string) []byte {
	// IDr body: IDType(1) + reserved(3) + FQDN
	b := make([]byte, 4+len(fqdn))
	b[0] = uint8(message.IDTypeFQDN)
	copy(b[4:], []byte(fqdn))
	return b
}

func buildCPReply(ip, dns1, dns2 net.IP) *message.CPPayload {
	cp := &message.CPPayload{CFGType: message.CPTypeReply}
	if ip != nil {
		cp.Attributes = append(cp.Attributes, message.CPAttribute{
			Type:  message.CPAttrInternalIPv4Address,
			Value: ip.To4(),
		})
	}
	if dns1 != nil {
		cp.Attributes = append(cp.Attributes, message.CPAttribute{
			Type:  message.CPAttrInternalIPv4DNS,
			Value: dns1.To4(),
		})
	}
	if dns2 != nil {
		cp.Attributes = append(cp.Attributes, message.CPAttribute{
			Type:  message.CPAttrInternalIPv4DNS,
			Value: dns2.To4(),
		})
	}
	return cp
}

func buildChildSAPayload(spiIn uint32) *message.SAPayload {
	spiBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(spiBytes, spiIn)
	return &message.SAPayload{
		Proposals: []message.Proposal{
			{
				Number:     1,
				ProtocolID: 3, // ESP
				SPI:        spiBytes,
				Transforms: []message.Transform{
					{Type: message.TransformTypeEncr, ID: message.EncrAESCBC256,
						Attributes: []message.TransformAttribute{message.KeyLengthAttribute(256)}},
					{Type: message.TransformTypeInteg, ID: message.IntegHMACSHA2_256_128},
					{Type: message.TransformTypeESN, ID: message.ESNNo},
				},
			},
		},
	}
}

func buildDefaultTSi() *message.TSPayload {
	return &message.TSPayload{}
}

func buildDefaultTSr() *message.TSPayload {
	return &message.TSPayload{}
}

var spiCounter uint32 = 0x10000000

func allocateSPI() uint32 {
	spiCounter++
	return spiCounter
}
