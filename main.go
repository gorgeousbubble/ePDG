// ePDG - Evolved Packet Data Gateway
// Implements 3GPP TS 23.402, TS 24.302, TS 33.402
//
// Interfaces:
//
//	SWu  - UE to ePDG (IKEv2/IPSec, UDP 500/4500)
//	SWm  - ePDG to 3GPP AAA Server (Diameter, TCP 3868)
//	S2b  - ePDG to P-GW (GTPv2-C/GTP-U, UDP 2123/2152)
package main

import (
	"flag"
	"fmt"
	"os"

	"ePDG/app"
	"ePDG/config"
)

func main() {
	cfgPath := flag.String("config", "", "Path to JSON configuration file (optional, uses defaults if not specified)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ePDG: load config: %v\n", err)
		os.Exit(1)
	}

	epdg, err := app.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ePDG: create: %v\n", err)
		os.Exit(1)
	}

	if err := epdg.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "ePDG: run: %v\n", err)
		os.Exit(1)
	}
}
