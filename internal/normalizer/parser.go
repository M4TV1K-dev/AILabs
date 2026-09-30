package normalizer

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	// Regular expression to catch CVE occurrences in NSE script text output
	cveRegex = regexp.MustCompile(`(CVE-\d{4}-\d{4,8})\s+([0-9]+\.[0-9]+)?\s*([^\n\r]*)`)
	simpleCVERegex = regexp.MustCompile(`CVE-\d{4}-\d{4,8}`)
)

// ParseNmapXML parses raw Nmap XML output and produces a normalized IncidentManifest.
func ParseNmapXML(rawXML []byte, scanType string) (*IncidentManifest, error) {
	if len(rawXML) == 0 {
		return nil, fmt.Errorf("вывод Nmap XML пуст")
	}

	var run NmapRun
	if err := xml.Unmarshal(rawXML, &run); err != nil {
		return nil, fmt.Errorf("ошибка парсинга Nmap XML: %w", err)
	}

	manifest := &IncidentManifest{
		TargetMetadata: TargetMetadata{
			ScanType: scanType,
		},
		OpenServices: []ServiceItem{},
	}

	if len(run.Hosts) == 0 {
		manifest.TargetMetadata.IP = "Unknown"
		manifest.TargetMetadata.OSDetected = "Не определена (хост не ответил)"
		return manifest, nil
	}

	host := run.Hosts[0]

	// 1. Extract IP address
	for _, addr := range host.Addresses {
		if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
			manifest.TargetMetadata.IP = addr.Addr
			break
		}
	}
	if manifest.TargetMetadata.IP == "" && len(host.Addresses) > 0 {
		manifest.TargetMetadata.IP = host.Addresses[0].Addr
	}

	// 2. Extract Hostnames
	var hostnames []string
	for _, h := range host.Hostnames.Hostnames {
		if h.Name != "" {
			hostnames = append(hostnames, h.Name)
		}
	}
	if len(hostnames) > 0 {
		manifest.TargetMetadata.Hostnames = strings.Join(hostnames, ", ")
	}

	// 3. Extract OS
	if len(host.OS.OSMatches) > 0 {
		bestMatch := host.OS.OSMatches[0]
		manifest.TargetMetadata.OSDetected = fmt.Sprintf("%s (точность %s%%)", bestMatch.Name, bestMatch.Accuracy)
	} else {
		manifest.TargetMetadata.OSDetected = "Не определена (требуются права root/admin или открытые порты)"
	}

	// 4. Extract Open Services and CVEs
	for _, p := range host.Ports.Ports {
		if p.State.State != "open" {
			continue // Filter out closed/filtered ports
		}

		serviceName := p.Service.Name
		if serviceName == "" {
			serviceName = "unknown"
		}

		product := p.Service.Product
		if product == "" {
			product = serviceName
		}

		version := p.Service.Version
		if p.Service.ExtraInfo != "" {
			if version != "" {
				version = fmt.Sprintf("%s (%s)", version, p.Service.ExtraInfo)
			} else {
				version = p.Service.ExtraInfo
			}
		}

		// Extract CVEs from scripts
		cves := extractCVEsFromScripts(p.Scripts)

		manifest.OpenServices = append(manifest.OpenServices, ServiceItem{
			Port:         p.PortID,
			Protocol:     p.Protocol,
			Service:      serviceName,
			Product:      product,
			Version:      version,
			ReportedCVEs: cves,
		})
	}

	return manifest, nil
}

// extractCVEsFromScripts walks both structured tables and text output of scripts
func extractCVEsFromScripts(scripts []NmapScript) []CVEItem {
	cveMap := make(map[string]CVEItem)

	for _, s := range scripts {
		// Method 1: Walk structured XML tables (standard vulners NSE format)
		walkTables(s.Tables, cveMap)

		// Method 2: Regex scanning over text output as robust fallback
		if s.Output != "" {
			matches := cveRegex.FindAllStringSubmatch(s.Output, -1)
			for _, m := range matches {
				cveID := m[1]
				var cvss float64
				if len(m) > 2 && m[2] != "" {
					cvss, _ = strconv.ParseFloat(m[2], 64)
				}
				typ := "Vulnerability"
				if len(m) > 3 {
					desc := strings.TrimSpace(m[3])
					if strings.Contains(strings.ToLower(desc), "*exploit*") {
						typ = "Known Exploit Available"
					} else if len(desc) > 30 {
						typ = desc[:30] + "..."
					} else if desc != "" {
						typ = desc
					}
				}

				if existing, exists := cveMap[cveID]; !exists || (cvss > existing.CVSS) {
					cveMap[cveID] = CVEItem{
						ID:   cveID,
						CVSS: cvss,
						Type: typ,
					}
				}
			}

			// Fallback: simple regex search if formatted line wasn't matched
			simpleMatches := simpleCVERegex.FindAllString(s.Output, -1)
			for _, cveID := range simpleMatches {
				if _, exists := cveMap[cveID]; !exists {
					cveMap[cveID] = CVEItem{
						ID:   cveID,
						CVSS: 7.0, // Default moderate-high if CVSS unparsed
						Type: "Security Vulnerability",
					}
				}
			}
		}
	}

	// Convert map to slice
	var results []CVEItem
	for _, item := range cveMap {
		results = append(results, item)
	}

	// Sort descending by CVSS score so most critical CVEs come first
	sort.Slice(results, func(i, j int) bool {
		return results[i].CVSS > results[j].CVSS
	})

	// Cap at top 8 CVEs per port to prevent exceeding LLM context budget
	if len(results) > 8 {
		results = results[:8]
	}

	return results
}

// walkTables recursively parses vulners nested tables
func walkTables(tables []NmapTable, cveMap map[string]CVEItem) {
	for _, t := range tables {
		var id string
		var cvss float64
		var typ string

		for _, elem := range t.Elems {
			switch elem.Key {
			case "id":
				id = elem.Value
			case "cvss":
				cvss, _ = strconv.ParseFloat(elem.Value, 64)
			case "type":
				typ = elem.Value
			}
		}

		if strings.HasPrefix(id, "CVE-") {
			if typ == "" {
				typ = "Reported CVE"
			}
			cveMap[id] = CVEItem{
				ID:   id,
				CVSS: cvss,
				Type: typ,
			}
		}

		// Recurse into child tables
		if len(t.Tables) > 0 {
			walkTables(t.Tables, cveMap)
		}
	}
}
