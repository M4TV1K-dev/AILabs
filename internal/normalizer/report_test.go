package normalizer

import (
	"strings"
	"testing"
)

func TestCleanAIOutput(t *testing.T) {
	raw := `Thinking Process:

1.  Analyze the Request:
    *   Role: SOC Lead Analyst.
    *   Task: Create a concise conclusion.
2.  Drafting the Sections:
    *   Threat Assessment: Critical.

Let's assemble the text.

**Оценка угрозы для бизнеса:**
На хосте 192.168.10.15 обнаружены критические уязвимости.

**Сценарий атаки:**
Злоумышленник может получить удаленный доступ.

**Ключевой вывод:**
Требуется немедленная изоляция.`

	cleaned := CleanAIOutput(raw)

	if strings.Contains(cleaned, "Thinking Process:") {
		t.Errorf("CleanAIOutput failed to strip 'Thinking Process:'\nResult: %s", cleaned)
	}

	if strings.Contains(cleaned, "Role: SOC Lead Analyst") {
		t.Errorf("CleanAIOutput failed to strip English planning\nResult: %s", cleaned)
	}

	if !strings.Contains(cleaned, "**Оценка угрозы для бизнеса:**") {
		t.Errorf("CleanAIOutput missing Russian section header\nResult: %s", cleaned)
	}

	if !strings.Contains(cleaned, "На хосте 192.168.10.15") {
		t.Errorf("CleanAIOutput missing Russian content body\nResult: %s", cleaned)
	}
}

func TestBuildExecutiveReport(t *testing.T) {
	manifest := &IncidentManifest{
		TargetMetadata: TargetMetadata{
			IP:         "192.168.10.15",
			Hostnames:  "vuln-test.local",
			OSDetected: "Ubuntu 5.4",
			ScanType:   "Aggressive",
		},
		OpenServices: []ServiceItem{
			{
				Port:     80,
				Protocol: "tcp",
				Service:  "http",
				Product:  "WordPress",
				Version:  "5.0.3",
				ReportedCVEs: []CVEItem{
					{ID: "CVE-2019-8942", CVSS: 8.8, Type: "RCE"},
				},
			},
			{
				Port:     22,
				Protocol: "tcp",
				Service:  "ssh",
				Product:  "OpenSSH",
				Version:  "8.2",
			},
		},
	}

	report := BuildExecutiveReport(manifest, "**Оценка угрозы для бизнеса:**\nКритический риск.", "Thinking Process: dummy reasoning")

	if !strings.Contains(report, "🛡️ Отчет по результатам аудита") {
		t.Errorf("Report missing title")
	}

	if !strings.Contains(report, "🔴 КРАСНЫЙ УРОВЕНЬ") {
		t.Errorf("Report missing RED level")
	}

	if !strings.Contains(report, "🟡 ЖЕЛТЫЙ УРОВЕНЬ") {
		t.Errorf("Report missing YELLOW level")
	}

	if !strings.Contains(report, "CVE-2019-8942") {
		t.Errorf("Report missing CVE")
	}

	if !strings.Contains(report, "Критический риск.") {
		t.Errorf("Report missing clean AI summary")
	}
}

func TestExtractBestAIAnalysis(t *testing.T) {
	// Scenario: mainContent cut off mid-sentence, reasoning contains full draft
	mainContent := `**Оценка угрозы для бизнеса:**
На сервере найдены уязвимости.
**Сценарий атаки:**
Атакующий подключается к порту 80, где CVE-2`

	reasoning := `Thinking Process:
1. Analyze request...
    *Revised Draft:*
    **Оценка угрозы для бизнеса:**
    На сервере найдены уязвимости.

    **Сценарий атаки:**
    Атакующий подключается к порту 80 и загружает эксплойт.

    **Ключевой вывод:**
    Требуется немедленное исправление.

    *Final check on constraints:*
    - Russian only? Yes.`

	result := ExtractBestAIAnalysis(mainContent, reasoning, "length")

	if strings.Contains(result, "где CVE-2") {
		t.Errorf("Expected truncated content to be replaced by full draft, got: %s", result)
	}

	if !strings.Contains(result, "Ключевой вывод:") {
		t.Errorf("Expected full draft with 'Ключевой вывод:', got: %s", result)
	}

	if strings.Contains(result, "Thinking Process:") || strings.Contains(result, "Final check") {
		t.Errorf("Expected reasoning scaffolding stripped, got: %s", result)
	}
}
