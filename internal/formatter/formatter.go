package formatter

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/me262/snmp-manager/internal/pipeline"
)

// CEFFormatter formats events in ArcSight Common Event Format.
// Format: CEF:Version|Device Vendor|Device Product|Device Version|Event ID|Name|Severity|Extensions
type CEFFormatter struct {
	Vendor  string
	Product string
	Version string
}

// NewCEFFormatter creates a new CEF formatter.
func NewCEFFormatter() *CEFFormatter {
	return &CEFFormatter{
		Vendor:  "SNMPManager",
		Product: "SNMP-Manager",
		Version: "1.0",
	}
}

// Format converts an SNMPEvent to CEF format.
func (f *CEFFormatter) Format(event *pipeline.SNMPEvent) (string, error) {
	// Map severity to CEF severity (0-10)
	cefSeverity := int(event.Severity)

	// Build event name
	eventName := event.OIDName
	if eventName == "" {
		eventName = event.OID
	}

	// Event class ID
	classID := mapOIDToClassID(event.OID)

	// Build extensions
	extensions := []string{
		fmt.Sprintf("src=%s", event.DeviceIP),
		fmt.Sprintf("rt=%s", event.Timestamp.Format(time.RFC3339)),
		fmt.Sprintf("cat=%s", event.Category),
	}

	if event.DeviceHostname != "" {
		extensions = append(extensions, fmt.Sprintf("shost=%s", event.DeviceHostname))
	}
	if event.DeviceType != "" {
		extensions = append(extensions, fmt.Sprintf("cs1Label=DeviceType cs1=%s", event.DeviceType))
	}
	if event.DeviceVendor != "" {
		extensions = append(extensions, fmt.Sprintf("cs2Label=Vendor cs2=%s", event.DeviceVendor))
	}

	extensions = append(extensions, fmt.Sprintf("cs3Label=OID cs3=%s", event.OID))
	extensions = append(extensions, fmt.Sprintf("cs4Label=SNMPVersion cs4=%s", event.Version))

	if event.ValueStr != "" {
		extensions = append(extensions, fmt.Sprintf("msg=%s", escCEF(event.ValueStr)))
	}

	if event.DeviceLocation != "" {
		extensions = append(extensions, fmt.Sprintf("cs5Label=Location cs5=%s", event.DeviceLocation))
	}

	// Add variable bindings
	for i, v := range event.Variables {
		if i >= 5 {
			break
		}
		label := v.OIDName
		if label == "" {
			label = v.OID
		}
		extensions = append(extensions, fmt.Sprintf("cn%dLabel=%s cn%d=%v", i+1, label, i+1, v.Value))
	}

	cef := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s",
		escCEFHeader(f.Vendor),
		escCEFHeader(f.Product),
		escCEFHeader(f.Version),
		classID,
		escCEFHeader(eventName),
		cefSeverity,
		strings.Join(extensions, " "),
	)

	return cef, nil
}

// JSONFormatter formats events as JSON.
type JSONFormatter struct {
	Pretty bool
}

// NewJSONFormatter creates a new JSON formatter.
func NewJSONFormatter(pretty bool) *JSONFormatter {
	return &JSONFormatter{Pretty: pretty}
}

// Format converts an SNMPEvent to JSON format.
func (f *JSONFormatter) Format(event *pipeline.SNMPEvent) (string, error) {
	var data []byte
	var err error

	if f.Pretty {
		data, err = json.MarshalIndent(event, "", "  ")
	} else {
		data, err = json.Marshal(event)
	}

	if err != nil {
		return "", fmt.Errorf("json marshal: %w", err)
	}
	return string(data), nil
}

// SyslogFormatter formats events as RFC 5424 syslog messages.
type SyslogFormatter struct {
	AppName string
}

// NewSyslogFormatter creates a new syslog formatter.
func NewSyslogFormatter() *SyslogFormatter {
	return &SyslogFormatter{
		AppName: "snmpmanager",
	}
}

// Format converts an SNMPEvent to RFC 5424 syslog format.
func (f *SyslogFormatter) Format(event *pipeline.SNMPEvent) (string, error) {
	// Map severity to syslog severity (0-7, lower is more severe)
	syslogSeverity := mapToSyslogSeverity(event.Severity)

	// Facility: local0 (16)
	facility := 16
	priority := facility*8 + syslogSeverity

	hostname := event.DeviceHostname
	if hostname == "" {
		hostname = event.DeviceIP
	}

	// Structured data
	sd := fmt.Sprintf("[snmp oid=\"%s\" name=\"%s\" value=\"%s\" version=\"%s\" type=\"%s\"]",
		event.OID,
		event.OIDName,
		escSD(event.ValueStr),
		event.Version,
		string(event.EventType),
	)

	// Message
	msg := fmt.Sprintf("%s=%s on %s", event.OIDName, event.ValueStr, hostname)

	syslog := fmt.Sprintf("<%d>1 %s %s %s %s %s %s %s",
		priority,
		event.Timestamp.Format(time.RFC3339),
		hostname,
		f.AppName,
		event.ID[:8],
		mapEventTypeToMsgID(event.EventType),
		sd,
		msg,
	)

	return syslog, nil
}

// LEEFFormatter formats events in IBM QRadar LEEF format.
type LEEFFormatter struct {
	Vendor  string
	Product string
	Version string
}

// NewLEEFFormatter creates a new LEEF formatter.
func NewLEEFFormatter() *LEEFFormatter {
	return &LEEFFormatter{
		Vendor:  "SNMPManager",
		Product: "SNMP-Manager",
		Version: "1.0",
	}
}

// Format converts an SNMPEvent to LEEF format.
func (f *LEEFFormatter) Format(event *pipeline.SNMPEvent) (string, error) {
	// LEEF:Version|Vendor|Product|Version|EventID|
	eventID := event.OIDName
	if eventID == "" {
		eventID = event.OID
	}

	attrs := []string{
		fmt.Sprintf("src=%s", event.DeviceIP),
		fmt.Sprintf("sev=%d", int(event.Severity)),
		fmt.Sprintf("cat=%s", event.Category),
		fmt.Sprintf("devTime=%s", event.Timestamp.Format(time.RFC3339)),
	}

	if event.DeviceHostname != "" {
		attrs = append(attrs, fmt.Sprintf("srcName=%s", event.DeviceHostname))
	}

	attrs = append(attrs, fmt.Sprintf("oid=%s", event.OID))
	attrs = append(attrs, fmt.Sprintf("oidName=%s", event.OIDName))

	if event.ValueStr != "" {
		attrs = append(attrs, fmt.Sprintf("value=%s", event.ValueStr))
	}

	leef := fmt.Sprintf("LEEF:2.0|%s|%s|%s|%s|%s",
		f.Vendor, f.Product, f.Version, eventID,
		strings.Join(attrs, "\t"),
	)

	return leef, nil
}

// Helper functions

func mapOIDToClassID(oid string) string {
	// Map well-known trap OIDs to class IDs
	switch {
	case strings.HasPrefix(oid, "1.3.6.1.6.3.1.1.5.1"):
		return "SNMP-COLD-START"
	case strings.HasPrefix(oid, "1.3.6.1.6.3.1.1.5.2"):
		return "SNMP-WARM-START"
	case strings.HasPrefix(oid, "1.3.6.1.6.3.1.1.5.3"):
		return "SNMP-LINK-DOWN"
	case strings.HasPrefix(oid, "1.3.6.1.6.3.1.1.5.4"):
		return "SNMP-LINK-UP"
	case strings.HasPrefix(oid, "1.3.6.1.6.3.1.1.5.5"):
		return "SNMP-AUTH-FAIL"
	default:
		return "SNMP-EVENT"
	}
}

func mapToSyslogSeverity(s pipeline.Severity) int {
	switch {
	case s >= 9:
		return 2 // Critical
	case s >= 7:
		return 3 // Error
	case s >= 5:
		return 4 // Warning
	case s >= 3:
		return 5 // Notice
	default:
		return 6 // Informational
	}
}

func mapEventTypeToMsgID(t pipeline.EventType) string {
	switch t {
	case pipeline.EventTypeTrap:
		return "SNMP_TRAP"
	case pipeline.EventTypePoll:
		return "SNMP_POLL"
	case pipeline.EventTypeInform:
		return "SNMP_INFORM"
	default:
		return "SNMP_EVENT"
	}
}

// escCEFHeader escapes characters for CEF header fields.
func escCEFHeader(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

// escCEF escapes characters for CEF extension values.
func escCEF(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

// escSD escapes characters for syslog structured data.
func escSD(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "]", "\\]")
	return s
}
