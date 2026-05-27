// Package app is the ePDG application lifecycle manager.
// Based on 3GPP TS 23.402, TS 24.302, TS 33.402.
package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ePDG/config"
	"ePDG/diameter"
	"ePDG/gtp"
	ikeserver "ePDG/ike"
	"ePDG/logger"
	"ePDG/session"
	"ePDG/store"
)

// ePDG is the main application struct.
type ePDG struct {
	cfg      *config.Config
	sessions *session.Manager
	store    *store.Store
	diameter *diameter.Client
	ikeServer *ikeserver.Server
	gtpServer *gtp.Server
	stopCh   chan struct{}
}

// New creates a new ePDG application instance.
func New(cfg *config.Config) (*ePDG, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	return &ePDG{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}, nil
}

// Init initialises all ePDG subsystems.
func (e *ePDG) Init() error {
	// 1. Logger
	logCfg := e.cfg.GetLogger()
	if err := logger.Init(logger.Config{
		Level:      logger.LogLevel(logCfg.Level),
		Filename:   logCfg.Filename,
		MaxSize:    logCfg.MaxSize,
		MaxBackups: logCfg.MaxBackups,
		MaxAge:     logCfg.MaxAge,
		Compress:   logCfg.Compress,
		Console:    logCfg.Console,
	}); err != nil {
		return fmt.Errorf("ePDG init: logger: %w", err)
	}
	logger.Info("ePDG initialising...")

	// 2. Session manager
	e.sessions = session.NewManager()

	// 3. Persistent store
	dbStore, err := store.New(e.cfg.GetDatabase())
	if err != nil {
		return fmt.Errorf("ePDG init: store: %w", err)
	}
	e.store = dbStore

	// 4. Diameter SWm client
	diamCfg := e.cfg.GetDiameter()
	e.diameter = diameter.NewClient(
		diamCfg.AAAServerAddr,
		diamCfg.OriginHost,
		diamCfg.OriginRealm,
		diamCfg.DestinationRealm,
		diamCfg.Timeout,
		diamCfg.RetryCount,
	)

	// 5. IKEv2 server (SWu interface)
	ikeServ, err := ikeserver.NewServer(e.cfg, e.sessions, e.diameter)
	if err != nil {
		return fmt.Errorf("ePDG init: IKE server: %w", err)
	}
	e.ikeServer = ikeServ

	// 6. GTP-U server (S2b interface)
	gtpCfg := e.cfg.GetGTP()
	e.gtpServer = gtp.NewServer(gtpCfg.ListenAddr, gtpCfg.BufferSize, e.handleGTPUPacket)

	logger.Info("ePDG initialised successfully")
	return nil
}

// Start starts all ePDG subsystems.
func (e *ePDG) Start() error {
	// Connect to AAA server
	if err := e.diameter.Connect(); err != nil {
		logger.Warnf("ePDG: Diameter connect failed (will retry): %v", err)
		// Non-fatal: retry in background
		go e.retryDiameterConnect()
	}

	// Start GTP-U server
	if err := e.gtpServer.Start(); err != nil {
		return fmt.Errorf("ePDG start: GTP-U: %w", err)
	}

	// Start IKEv2 server
	if err := e.ikeServer.Start(); err != nil {
		return fmt.Errorf("ePDG start: IKE: %w", err)
	}

	// Start session expiry monitor
	go e.sessionExpiryMonitor()

	logger.Infof("ePDG started (PLMN=%s, FQDN=%s)",
		e.cfg.GetePDG().PLMN, e.cfg.GetePDG().FQDN)
	return nil
}

// Stop gracefully shuts down all ePDG subsystems.
func (e *ePDG) Stop() {
	logger.Info("ePDG stopping...")
	close(e.stopCh)

	// Stop IKEv2 server
	if e.ikeServer != nil {
		e.ikeServer.Stop()
	}

	// Stop GTP-U server
	if e.gtpServer != nil {
		e.gtpServer.Stop()
	}

	// Close Diameter connection
	if e.diameter != nil {
		e.diameter.Close()
	}

	// Close store
	if e.store != nil {
		e.store.Close()
	}

	logger.Info("ePDG stopped")
}

// Status returns a summary of the ePDG status.
func (e *ePDG) Status() map[string]interface{} {
	return map[string]interface{}{
		"fqdn":          e.cfg.GetePDG().FQDN,
		"plmn":          e.cfg.GetePDG().PLMN,
		"active_sessions": e.sessions.Count(),
		"uptime":        time.Now().String(),
	}
}

// Run starts the ePDG and blocks until a signal is received.
func (e *ePDG) Run() error {
	if err := e.Init(); err != nil {
		return err
	}
	if err := e.Start(); err != nil {
		return err
	}

	// Wait for OS signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Infof("ePDG: received signal %s, shutting down", sig)
	e.Stop()
	return nil
}

// handleGTPUPacket processes a received GTP-U G-PDU from the P-GW.
// It forwards the inner IP packet to the UE via the IPSec tunnel.
func (e *ePDG) handleGTPUPacket(teid uint32, payload []byte, src interface{}) {
	// Find the session associated with this TEID
	for _, sess := range e.sessions.All() {
		if sess.LocalTEID == teid {
			// TODO: forward payload to UE via IPSec/ESP
			logger.Debugf("GTP-U: received %d bytes for TEID=0x%08x (session %s)",
				len(payload), teid, sess.ID)
			return
		}
	}
	logger.Warnf("GTP-U: no session for TEID=0x%08x", teid)
}

// sessionExpiryMonitor periodically checks for expired sessions.
func (e *ePDG) sessionExpiryMonitor() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			for _, sess := range e.sessions.All() {
				if !sess.SAExpiry.IsZero() && now.After(sess.SAExpiry) {
					logger.Infof("Session %s (IMSI=%s) expired", sess.ID, sess.IMSI)
					// Send STR to AAA
					if sess.IMSI != "" && sess.DiameterSessionID != "" {
						go e.diameter.SendSTR(sess.DiameterSessionID, sess.IMSI, 1) // 1=USER_REQUEST
					}
					sess.SetState(session.StateDisconnected)
					e.sessions.Remove(sess.ID)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					e.store.DeleteSession(ctx, sess.ID)
					cancel()
				}
			}
		}
	}
}

// retryDiameterConnect retries the Diameter connection in the background.
func (e *ePDG) retryDiameterConnect() {
	for {
		select {
		case <-e.stopCh:
			return
		case <-time.After(10 * time.Second):
			if err := e.diameter.Connect(); err != nil {
				logger.Warnf("ePDG: Diameter reconnect failed: %v", err)
			} else {
				logger.Info("ePDG: Diameter connected")
				return
			}
		}
	}
}
