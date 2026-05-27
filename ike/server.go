// Package ike implements the IKEv2 UDP server for ePDG.
// Listens on port 500 (IKE) and 4500 (NAT-T) per RFC 7296 and 3GPP TS 24.302.
package ike

import (
	"fmt"
	"net"
	"sync"

	"ePDG/config"
	"ePDG/diameter"
	"ePDG/ike/handler"
	"ePDG/logger"
	"ePDG/session"
)

// Server is the IKEv2 UDP server.
type Server struct {
	cfg      *config.Config
	handler  *handler.Handler
	conn500  *net.UDPConn // IKE port 500
	conn4500 *net.UDPConn // NAT-T port 4500
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// NewServer creates a new IKEv2 server.
func NewServer(cfg *config.Config, sessions *session.Manager, diam *diameter.Client) (*Server, error) {
	h, err := handler.New(cfg, sessions, diam)
	if err != nil {
		return nil, fmt.Errorf("IKE server: %w", err)
	}
	return &Server{
		cfg:     cfg,
		handler: h,
		stopCh:  make(chan struct{}),
	}, nil
}

// Start binds UDP sockets and starts receive loops.
func (s *Server) Start() error {
	ikeCfg := s.cfg.GetIKE()

	// Bind port 500
	addr500, err := net.ResolveUDPAddr("udp4", ikeCfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("IKE: resolve %s: %w", ikeCfg.ListenAddr, err)
	}
	conn500, err := net.ListenUDP("udp4", addr500)
	if err != nil {
		return fmt.Errorf("IKE: listen %s: %w", ikeCfg.ListenAddr, err)
	}
	s.conn500 = conn500

	// Bind port 4500 (NAT-T)
	addr4500, err := net.ResolveUDPAddr("udp4", ikeCfg.NATTListenAddr)
	if err != nil {
		conn500.Close()
		return fmt.Errorf("IKE: resolve NAT-T %s: %w", ikeCfg.NATTListenAddr, err)
	}
	conn4500, err := net.ListenUDP("udp4", addr4500)
	if err != nil {
		conn500.Close()
		return fmt.Errorf("IKE: listen NAT-T %s: %w", ikeCfg.NATTListenAddr, err)
	}
	s.conn4500 = conn4500

	logger.Infof("IKEv2 server listening on %s (IKE) and %s (NAT-T)",
		ikeCfg.ListenAddr, ikeCfg.NATTListenAddr)

	s.wg.Add(2)
	go s.receiveLoop(conn500)
	go s.receiveLoop(conn4500)
	return nil
}

// Stop shuts down the IKEv2 server.
func (s *Server) Stop() {
	close(s.stopCh)
	if s.conn500 != nil {
		s.conn500.Close()
	}
	if s.conn4500 != nil {
		s.conn4500.Close()
	}
	s.wg.Wait()
	logger.Info("IKEv2 server stopped")
}

// receiveLoop reads UDP packets and dispatches them to the handler.
func (s *Server) receiveLoop(conn *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				logger.Errorf("IKE: receive error on %s: %v", conn.LocalAddr(), err)
				continue
			}
		}
		// Handle each packet in a goroutine to avoid blocking
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handler.HandleMessage(pkt, src, conn)
	}
}
