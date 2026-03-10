package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/gosnmp/gosnmp"
)

// SNMP Trap sender tool for testing the SNMP Manager trap receiver.
// Sends various trap types: linkDown, linkUp, authFailure, coldStart, custom.

func main() {
	target := flag.String("target", "127.0.0.1", "Target IP")
	port := flag.Int("port", 1620, "Target port")
	community := flag.String("community", "public", "SNMP community string")
	trapType := flag.String("type", "all", "Trap type: linkDown, linkUp, authFail, coldStart, custom, all")
	count := flag.Int("count", 1, "Number of traps to send")
	interval := flag.Duration("interval", 500*time.Millisecond, "Interval between traps")
	flag.Parse()

	fmt.Printf("🔫 SNMP Trap Sender\n")
	fmt.Printf("   Target:    %s:%d\n", *target, *port)
	fmt.Printf("   Community: %s\n", *community)
	fmt.Printf("   Type:      %s\n", *trapType)
	fmt.Printf("   Count:     %d\n\n", *count)

	sender := &gosnmp.GoSNMP{
		Target:    *target,
		Port:      uint16(*port),
		Version:   gosnmp.Version2c,
		Community: *community,
		Timeout:   5 * time.Second,
		Retries:   1,
	}

	if err := sender.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Connect error: %v\n", err)
		os.Exit(1)
	}
	defer sender.Conn.Close()

	for i := 0; i < *count; i++ {
		switch *trapType {
		case "linkDown":
			sendLinkDown(sender, i)
		case "linkUp":
			sendLinkUp(sender, i)
		case "authFail":
			sendAuthFailure(sender, i)
		case "coldStart":
			sendColdStart(sender, i)
		case "custom":
			sendCustom(sender, i)
		case "all":
			sendColdStart(sender, i)
			time.Sleep(*interval)
			sendLinkDown(sender, i)
			time.Sleep(*interval)
			sendLinkUp(sender, i)
			time.Sleep(*interval)
			sendAuthFailure(sender, i)
			time.Sleep(*interval)
			sendCustom(sender, i)
		default:
			fmt.Fprintf(os.Stderr, "Unknown trap type: %s\n", *trapType)
			os.Exit(1)
		}

		if i < *count-1 {
			time.Sleep(*interval)
		}
	}

	fmt.Println("\n✅ All traps sent!")
}

// sendLinkDown sends a linkDown trap (interface going down).
func sendLinkDown(s *gosnmp.GoSNMP, seq int) {
	trap := gosnmp.SnmpTrap{
		Variables: []gosnmp.SnmpPDU{
			// sysUpTime.0
			{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(time.Now().Unix())},
			// snmpTrapOID.0 → linkDown
			{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"},
			// ifIndex.1
			{Name: ".1.3.6.1.2.1.2.2.1.1.1", Type: gosnmp.Integer, Value: 1},
			// ifDescr.1
			{Name: ".1.3.6.1.2.1.2.2.1.2.1", Type: gosnmp.OctetString, Value: "GigabitEthernet0/1"},
			// ifOperStatus.1 = down(2)
			{Name: ".1.3.6.1.2.1.2.2.1.8.1", Type: gosnmp.Integer, Value: 2},
		},
	}

	_, err := s.SendTrap(trap)
	if err != nil {
		fmt.Printf("   ❌ linkDown trap #%d: %v\n", seq, err)
	} else {
		fmt.Printf("   📡 [%d] linkDown — GigabitEthernet0/1 is DOWN\n", seq)
	}
}

// sendLinkUp sends a linkUp trap (interface coming back up).
func sendLinkUp(s *gosnmp.GoSNMP, seq int) {
	trap := gosnmp.SnmpTrap{
		Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(time.Now().Unix())},
			// snmpTrapOID.0 → linkUp
			{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.4"},
			{Name: ".1.3.6.1.2.1.2.2.1.1.2", Type: gosnmp.Integer, Value: 2},
			{Name: ".1.3.6.1.2.1.2.2.1.2.2", Type: gosnmp.OctetString, Value: "GigabitEthernet0/2"},
			// ifOperStatus.2 = up(1)
			{Name: ".1.3.6.1.2.1.2.2.1.8.2", Type: gosnmp.Integer, Value: 1},
		},
	}

	_, err := s.SendTrap(trap)
	if err != nil {
		fmt.Printf("   ❌ linkUp trap #%d: %v\n", seq, err)
	} else {
		fmt.Printf("   📡 [%d] linkUp — GigabitEthernet0/2 is UP\n", seq)
	}
}

// sendAuthFailure sends an authenticationFailure trap.
func sendAuthFailure(s *gosnmp.GoSNMP, seq int) {
	trap := gosnmp.SnmpTrap{
		Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(time.Now().Unix())},
			// snmpTrapOID.0 → authenticationFailure
			{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.5"},
			// Source IP that attempted authentication
			{Name: ".1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: "unauthorized-host"},
		},
	}

	_, err := s.SendTrap(trap)
	if err != nil {
		fmt.Printf("   ❌ authFailure trap #%d: %v\n", seq, err)
	} else {
		fmt.Printf("   🔒 [%d] authenticationFailure — unauthorized access attempt!\n", seq)
	}
}

// sendColdStart sends a coldStart trap (device reboot).
func sendColdStart(s *gosnmp.GoSNMP, seq int) {
	trap := gosnmp.SnmpTrap{
		Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(0)}, // just rebooted
			// snmpTrapOID.0 → coldStart
			{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.1"},
			// sysDescr
			{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: "Cisco IOS XE Software, Version 17.06.05, RELEASE"},
			// sysName
			{Name: ".1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: "core-router-01"},
		},
	}

	_, err := s.SendTrap(trap)
	if err != nil {
		fmt.Printf("   ❌ coldStart trap #%d: %v\n", seq, err)
	} else {
		fmt.Printf("   🔄 [%d] coldStart — device rebooted!\n", seq)
	}
}

// sendCustom sends a custom enterprise trap with CPU utilization alert.
func sendCustom(s *gosnmp.GoSNMP, seq int) {
	trap := gosnmp.SnmpTrap{
		Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(time.Now().Unix())},
			// snmpTrapOID.0 → custom enterprise trap
			{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.9.9.109.1.1.1.0"},
			// CPU 5 min utilization = 95%
			{Name: ".1.3.6.1.4.1.9.9.109.1.1.1.1.8.1", Type: gosnmp.Gauge32, Value: uint(95)},
			// Memory used
			{Name: ".1.3.6.1.4.1.9.9.48.1.1.1.5.1", Type: gosnmp.Gauge32, Value: uint(850000)},
			// Description
			{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: "CPU utilization exceeded 90% threshold"},
		},
	}

	_, err := s.SendTrap(trap)
	if err != nil {
		fmt.Printf("   ❌ custom trap #%d: %v\n", seq, err)
	} else {
		fmt.Printf("   ⚠️  [%d] custom enterprise trap — CPU 95%%, memory alert!\n", seq)
	}
}
