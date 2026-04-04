//go:build ignore

// fetch-zabbix-templates downloads official Zabbix 7.0 YAML templates,
// converts them to the SNMP-Manager built-in format, and writes to
// configs/templates/builtin_templates.json.
//
// Usage:
//   go run scripts/fetch_zabbix_templates.go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	snmptemplate "github.com/me262/snmp-manager/internal/template"
)

var zabbixTemplateURLs = []string{
	// ── Network devices (verified working in release/7.0) ──────────────────
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/generic_snmp/template_net_generic_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/alcatel_timetra_snmp/template_net_alcatel_timetra_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/arista_snmp/template_net_arista_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/brocade_fc_sw_snmp/template_net_brocade_fc_sw_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/brocade_foundry_sw_snmp/template_net_brocade_foundry_sw_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/ciena/template_net_ciena_3906_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/dell_force_s_series_snmp/template_net_dell_force_s_series_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/dlink_des7200_snmp/template_net_dlink_des7200_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/dlink_des_snmp/template_net_dlink_des_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/extreme_snmp/template_net_extreme_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/f5_bigip_snmp/template_net_f5_bigip_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/generic_snmp_snmp/template_module_generic_snmp_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/hp_hh3c_snmp/template_net_hp_hh3c_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/hp_hpn_snmp/template_net_hp_hpn_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/huawei_snmp/template_net_huawei_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/icmp_ping/template_module_icmp_ping.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/juniper_mx_snmp/template_net_juniper_mx_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/juniper_snmp/template_net_juniper_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/netgear_snmp/template_net_netgear_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/tplink_snmp/template_net_tplink_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/net/ubiquiti_airos_snmp/template_net_ubiquiti_airos_snmp.yaml",

	// ── OS / Servers ───────────────────────────────────────────────────────
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/os/linux_snmp_snmp/template_os_linux_snmp_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/os/windows_snmp/template_os_windows_snmp.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/os/freebsd/template_os_freebsd.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/os/linux/template_os_linux.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/os/aix/template_os_aix.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/os/solaris/template_os_solaris.yaml",
	"https://raw.githubusercontent.com/zabbix/zabbix/release/7.0/templates/os/macos/template_os_macos.yaml",
}

func main() {
	client := &http.Client{Timeout: 30 * time.Second}

	// Load existing builtin templates
	outPath := filepath.Join("configs", "templates", "builtin_templates.json")
	existingJSON, err := os.ReadFile(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: could not read %s: %v\n", outPath, err)
	}

	var existing []snmptemplate.Template
	_ = json.Unmarshal(existingJSON, &existing)

	// Index by ID to avoid duplicates
	byID := make(map[string]*snmptemplate.Template)
	for i := range existing {
		t := &existing[i]
		t.Builtin = true
		byID[t.ID] = t
	}

	fetched := 0
	failed := 0

	for _, url := range zabbixTemplateURLs {
		fmt.Printf("Fetching %s ... ", url)

		resp, err := client.Get(url)
		if err != nil {
			fmt.Printf("FAIL (request): %v\n", err)
			failed++
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			fmt.Printf("FAIL (%d)\n", resp.StatusCode)
			failed++
			continue
		}

		templates, err := snmptemplate.ParseZabbixYAML(body)
		if err != nil {
			fmt.Printf("FAIL (parse): %v\n", err)
			failed++
			continue
		}

		for _, t := range templates {
			t.Builtin = true
			if _, exists := byID[t.ID]; !exists {
			byID[t.ID] = t
			fmt.Printf("OK  →  %s (%s, %d items)\n", t.Name, t.ID, len(t.Items))
			fetched++
		} else {
			// Always overwrite to pick up improved categories/fields
			byID[t.ID] = t
			fmt.Printf("UPD →  %s (%s)\n", t.Name, t.ID)
			fetched++
		}
		}
	}

	// Collect and sort
	all := make([]snmptemplate.Template, 0, len(byID))
	for _, t := range byID {
		all = append(all, *t)
	}

	// Write output
	data, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal error: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✓ Done: %d fetched, %d failed, %d total in %s\n",
		fetched, failed, len(all), outPath)
}
