package normalizer

// CVEItem represents a single identified CVE entry with CVSS and description
type CVEItem struct {
	ID   string  `json:"id"`
	CVSS float64 `json:"cvss"`
	Type string  `json:"type"` // e.g. "Remote Code Execution", "Privilege Escalation", "DoS", etc.
}

// ServiceItem represents an open port and detected service
type ServiceItem struct {
	Port         int       `json:"port"`
	Protocol     string    `json:"protocol"`
	Service      string    `json:"service"`
	Product      string    `json:"product"`
	Version      string    `json:"version"`
	ReportedCVEs []CVEItem `json:"reported_cves"`
}

// TargetMetadata contains host-level audit info
type TargetMetadata struct {
	IP         string `json:"ip"`
	Hostnames  string `json:"hostnames,omitempty"`
	OSDetected string `json:"os_detected"`
	ScanType   string `json:"scan_type"`
}

// IncidentManifest is the strict, noise-free context object sent to LLM
// Formatted exactly as defined in system design PDF (Page 2 & 3).
type IncidentManifest struct {
	TargetMetadata TargetMetadata `json:"target_metadata"`
	OpenServices   []ServiceItem  `json:"open_services"`
}
