package normalizer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseNmapXML(t *testing.T) {
	xmlPath := filepath.Join("..", "..", "testdata", "sample_vuln_host.xml")
	data, err := os.ReadFile(xmlPath)
	if err != nil {
		t.Fatalf("Failed to read test xml: %v", err)
	}

	manifest, err := ParseNmapXML(data, "Aggressive Audit")
	if err != nil {
		t.Fatalf("ParseNmapXML returned error: %v", err)
	}

	if manifest.TargetMetadata.IP != "192.168.10.15" {
		t.Errorf("Expected IP 192.168.10.15, got %s", manifest.TargetMetadata.IP)
	}

	if len(manifest.OpenServices) != 3 {
		t.Fatalf("Expected 3 open services, got %d", len(manifest.OpenServices))
	}

	// Verify Port 22 SSH
	p22 := manifest.OpenServices[0]
	if p22.Port != 22 || p22.Service != "ssh" || p22.Product != "OpenSSH" {
		t.Errorf("Unexpected port 22 details: %+v", p22)
	}

	// Verify Port 80 HTTP / WordPress CVE
	p80 := manifest.OpenServices[1]
	if p80.Port != 80 || len(p80.ReportedCVEs) == 0 {
		t.Fatalf("Port 80 should have CVEs, got: %+v", p80)
	}
	foundWordPressRCE := false
	for _, c := range p80.ReportedCVEs {
		if c.ID == "CVE-2019-8942" && c.CVSS == 8.8 {
			foundWordPressRCE = true
		}
	}
	if !foundWordPressRCE {
		t.Errorf("Expected to find CVE-2019-8942 with CVSS 8.8 on port 80")
	}

	// Verify Port 445 Samba CVE
	p445 := manifest.OpenServices[2]
	if p445.Port != 445 || len(p445.ReportedCVEs) == 0 {
		t.Fatalf("Port 445 should have CVEs, got: %+v", p445)
	}
	foundSambaRCE := false
	for _, c := range p445.ReportedCVEs {
		if c.ID == "CVE-2017-7494" && c.CVSS == 9.8 {
			foundSambaRCE = true
		}
	}
	if !foundSambaRCE {
		t.Errorf("Expected to find CVE-2017-7494 with CVSS 9.8 on port 445")
	}
}
