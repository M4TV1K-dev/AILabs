package normalizer

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	// Regex to strip thinking process artifacts if they leak
	thinkingBlockRegex = regexp.MustCompile(`(?s)Thinking Process:.*?(?:Let's assemble the text\.?|Ready to generate\.?|\n\n###|\n\n\*\*)`)
)

// CleanAIOutput extracts clean Russian text and strips reasoning boilerplate
func CleanAIOutput(raw string) string {
	cleaned := strings.TrimSpace(raw)
	if cleaned == "" {
		return ""
	}

	// 1. If contains Thinking Process or internal monologue, extract Russian draft
	if strings.Contains(cleaned, "Thinking Process:") || strings.Contains(cleaned, "Thinking Process") {
		// Prefer the final revised draft if present
		draftMarkers := []string{"*Revised Draft:*", "Revised Draft:", "*Draft:*", "Draft:"}
		for _, dm := range draftMarkers {
			if pos := strings.LastIndex(cleaned, dm); pos != -1 {
				cleaned = strings.TrimSpace(cleaned[pos+len(dm):])
				break
			}
		}

		// Otherwise look for Russian section headers
		russianMarkers := []string{
			"**Оценка угрозы",
			"Оценка угрозы",
			"### 💼",
			"### Бизнес",
			"### Экспертное",
			"**Executive Summary",
			"Executive Summary",
			"Общий уровень риска",
			"Отчет по результатам",
			"На хосте",
			"В ходе аудита",
			"**Сценарий атаки",
		}

		firstIdx := -1
		for _, m := range russianMarkers {
			if pos := strings.Index(cleaned, m); pos != -1 {
				if firstIdx == -1 || pos < firstIdx {
					firstIdx = pos
				}
			}
		}

		if firstIdx != -1 {
			cleaned = strings.TrimSpace(cleaned[firstIdx:])
		} else {
			// Find first line that is predominantly Cyrillic
			lines := strings.Split(cleaned, "\n")
			for i, line := range lines {
				trimmedLine := strings.TrimSpace(line)
				if containsCyrillic(trimmedLine) && !strings.Contains(trimmedLine, "Drafting") && !strings.Contains(trimmedLine, "Constraint") && !strings.Contains(trimmedLine, "Language:") {
					cleaned = strings.TrimSpace(strings.Join(lines[i:], "\n"))
					break
				}
			}
		}

		// Cut off any trailing English checks or internal checklist
		endMarkers := []string{
			"*Final check",
			"Final check",
			"Ready to output",
			"Ready to generate",
			"```",
		}
		for _, em := range endMarkers {
			if pos := strings.Index(cleaned, em); pos != -1 {
				cleaned = strings.TrimSpace(cleaned[:pos])
			}
		}
	}

	// 2. Unindent lines that were nested in bullet points (e.g. 4 spaces)
	lines := strings.Split(cleaned, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimLeft(l, " \t")
	}
	cleaned = strings.Join(lines, "\n")
	cleaned = strings.TrimPrefix(cleaned, "Let's assemble the text.")

	return strings.TrimSpace(cleaned)
}

// ExtractBestAIAnalysis selects the most complete and high-quality Russian analysis.
func ExtractBestAIAnalysis(mainContent, reasoning string, finishReason string) string {
	cleanedMain := CleanAIOutput(mainContent)
	cleanedReasoning := CleanAIOutput(reasoning)

	isTruncated := finishReason == "length" || isAbruptlyCut(cleanedMain)

	// If main content has complete sections and isn't truncated, use it
	if cleanedMain != "" && !isTruncated && strings.Contains(cleanedMain, "Ключевой вывод") {
		return trimAbruptEnding(cleanedMain)
	}

	// If reasoning contains a full draft with key conclusion, prefer it!
	if strings.Contains(cleanedReasoning, "Ключевой вывод") {
		return trimAbruptEnding(cleanedReasoning)
	}

	// If main content has substance and isn't empty, use it cleanly trimmed
	if cleanedMain != "" {
		return trimAbruptEnding(cleanedMain)
	}

	if cleanedReasoning != "" {
		return trimAbruptEnding(cleanedReasoning)
	}

	return ""
}

func isAbruptlyCut(s string) bool {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return false
	}
	lastChar := trimmed[len(trimmed)-1]
	// If it doesn't end with standard punctuation, it's likely cut off
	if lastChar != '.' && lastChar != '!' && lastChar != '?' && lastChar != ':' && lastChar != ')' && lastChar != '»' && lastChar != '`' {
		return true
	}
	return false
}

func trimAbruptEnding(s string) string {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || !isAbruptlyCut(trimmed) {
		return trimmed
	}
	// Find last valid sentence terminator (. ! ?)
	lastDot := strings.LastIndexAny(trimmed, ".!?")
	if lastDot != -1 && lastDot > len(trimmed)/3 {
		return strings.TrimSpace(trimmed[:lastDot+1])
	}
	return trimmed
}

func containsCyrillic(s string) bool {
	for _, r := range s {
		if (r >= 'а' && r <= 'я') || (r >= 'А' && r <= 'Я') || r == 'ё' || r == 'Ё' {
			return true
		}
	}
	return false
}

// BuildExecutiveReport creates a stunning, client-ready presentation report.
// It combines deterministic facts from Nmap/Go with AI executive insights.
func BuildExecutiveReport(m *IncidentManifest, aiAnalysis string, reasoningLog string) string {
	var sb strings.Builder
	now := time.Now().Format("02.01.2006 15:04")

	// Calculate overall risk and stats
	maxCVSS := 0.0
	cveCount := 0
	hasRemoteAccess := false
	var vulnerableServices []string
	var remoteAccessServices []string

	for _, s := range m.OpenServices {
		if len(s.ReportedCVEs) > 0 {
			vulnerableServices = append(vulnerableServices, fmt.Sprintf("%s (порт %d)", s.Product, s.Port))
			for _, c := range s.ReportedCVEs {
				cveCount++
				if c.CVSS > maxCVSS {
					maxCVSS = c.CVSS
				}
			}
		}
		if s.Port == 22 || s.Port == 3389 || s.Port == 445 || s.Port == 21 || s.Port == 23 {
			hasRemoteAccess = true
			remoteAccessServices = append(remoteAccessServices, fmt.Sprintf("%s (порт %d)", s.Product, s.Port))
		}
	}

	riskBadge := "🟢 **НИЗКИЙ (Штатное состояние)**"
	if maxCVSS >= 7.0 {
		riskBadge = fmt.Sprintf("🔴 **КРИТИЧЕСКИЙ (CVSS %.1f / Высокая угроза взлома)**", maxCVSS)
	} else if maxCVSS > 0.0 || hasRemoteAccess {
		riskBadge = "🟡 **СРЕДНИЙ / ПОВЫШЕННЫЙ (Требует внимания ИТ-службы)**"
	}

	// --- 1. HEADER ---
	sb.WriteString("# 🛡️ Отчет по результатам аудита информационной безопасности\n\n")
	sb.WriteString(fmt.Sprintf("> **Объект аудита:** `%s` | **Дата:** `%s` | **Профиль:** `%s` | **Статус:** `Завершен`\n\n",
		m.TargetMetadata.IP, now, m.TargetMetadata.ScanType))

	// --- 2. PASSPORT TABLE ---
	sb.WriteString("### 📊 Паспорт проверяемого сетевого узла\n\n")
	sb.WriteString("| Параметр аудита | Значение |\n")
	sb.WriteString("| :--- | :--- |\n")
	sb.WriteString(fmt.Sprintf("| **Целевой адрес / Домен** | `%s` |\n", m.TargetMetadata.IP))
	if m.TargetMetadata.Hostnames != "" {
		sb.WriteString(fmt.Sprintf("| **Сетевое имя (Hostname)** | `%s` |\n", m.TargetMetadata.Hostnames))
	}
	sb.WriteString(fmt.Sprintf("| **Операционная система** | `%s` |\n", m.TargetMetadata.OSDetected))
	sb.WriteString(fmt.Sprintf("| **Открытых сетевых портов** | `%d` |\n", len(m.OpenServices)))
	sb.WriteString(fmt.Sprintf("| **Обнаружено уязвимостей (CVE)** | `%d` |\n", cveCount))
	sb.WriteString(fmt.Sprintf("| **Итоговый уровень риска для бизнеса** | %s |\n\n", riskBadge))

	// --- 3. AI EXECUTIVE SUMMARY ---
	sb.WriteString("### 💼 Экспертное заключение для руководства компании\n\n")
	cleanedAI := CleanAIOutput(aiAnalysis)
	if cleanedAI != "" {
		sb.WriteString("> 🤖 **Аналитическая оценка инцидента (AI SOC Analyst):**\n>\n")
		// Indent lines for blockquote
		lines := strings.Split(cleanedAI, "\n")
		for _, l := range lines {
			sb.WriteString("> " + l + "\n")
		}
		sb.WriteString("\n")
	} else {
		// High quality deterministic executive summary if LLM was brief
		if maxCVSS >= 7.0 {
			sb.WriteString("> ⚠️ **Внимание руководства:** На целевом узле обнаружены критические уязвимости наивысшего приоритета. Имеющиеся дефекты безопасности позволяют удаленному злоумышленнику обойти механизмы авторизации и получить полный контроль над сервером без ввода учетных данных. Рекомендуется безотлагательное принятие защитных мер.\n\n")
		} else if hasRemoteAccess {
			sb.WriteString("> ℹ️ **Сводка:** Критических уязвимостей с готовыми эксплойтами не зафиксировано, однако открыты сервисы удаленного доступа. Требуется проверка политик аутентификации и ограничение доступа по белому списку IP.\n\n")
		} else {
			sb.WriteString("> ✅ **Сводка:** Сетевой узел находится в штатном состоянии, известных уязвимостей не выявлено.\n\n")
		}
	}

	// --- 4. RED TIER ---
	var redItems, yellowItems, greenItems []string
	for _, s := range m.OpenServices {
		if len(s.ReportedCVEs) > 0 {
			serviceMaxCVSS := 0.0
			for _, c := range s.ReportedCVEs {
				if c.CVSS > serviceMaxCVSS {
					serviceMaxCVSS = c.CVSS
				}
			}

			var cveLines []string
			for _, c := range s.ReportedCVEs {
				cveLines = append(cveLines, fmt.Sprintf("    - 🚨 **%s** (Рейтинг CVSS: `%.1f`) — *%s*", c.ID, c.CVSS, c.Type))
			}

			if serviceMaxCVSS >= 7.0 {
				redItems = append(redItems, fmt.Sprintf(
					"#### ⛔ Порт %d/%s — Служба `%s` (Версия: %s %s)\n"+
						"  - **Обнаруженные CVE:**\n%s\n"+
						"  - **Бизнес-риск:** Позволяет удаленному атакующему выполнить произвольный код (RCE) и перехватить управление сервером.\n"+
						"  - 👉 **Действие:** Срочно изолировать порт правилом в файрволе и обновить ПО до актуальной безопасной версии.",
					s.Port, s.Protocol, s.Service, s.Product, s.Version, strings.Join(cveLines, "\n"),
				))
			} else {
				yellowItems = append(yellowItems, fmt.Sprintf(
					"#### ⚠️ Порт %d/%s — Служба `%s` (Версия: %s %s)\n"+
						"  - **Уязвимости умеренного риска:**\n%s\n"+
						"  - 👉 **Действие:** Запланировать обновление компонента в ближайшее техническое окно.",
					s.Port, s.Protocol, s.Service, s.Product, s.Version, strings.Join(cveLines, "\n"),
				))
			}
		} else if s.Port == 22 || s.Port == 3389 || s.Port == 445 || s.Port == 21 || s.Port == 23 {
			yellowItems = append(yellowItems, fmt.Sprintf(
				"#### ⚠️ Порт %d/%s — Служба удаленного управления `%s` (%s %s)\n"+
					"  - **Фактор риска:** Прямой доступ к панели/консоли управления, потенциальная мишень для перебора паролей (брутфорса).\n"+
					"  - 👉 **Действие:** Запретить прямой вход по паролю, настроить вход исключительно по ключам/сертификатам или скрыть за VPN.",
				s.Port, s.Protocol, s.Service, s.Product, s.Version,
			))
		} else {
			greenItems = append(greenItems, fmt.Sprintf(
				"- **Порт %d/%s (`%s` %s %s)**: Штатная служба без зафиксированных проблем безопасности.",
				s.Port, s.Protocol, s.Service, s.Product, s.Version,
			))
		}
	}

	sb.WriteString("### 🔴 КРАСНЫЙ УРОВЕНЬ: Критические угрозы (Немедленная реакция)\n\n")
	if len(redItems) > 0 {
		for _, item := range redItems {
			sb.WriteString(item + "\n\n")
		}
	} else {
		sb.WriteString("✅ *Критических уязвимостей с высоким рейтингом опасности не выявлено.*\n\n")
	}

	sb.WriteString("### 🟡 ЖЕЛТЫЙ УРОВЕНЬ: Предупреждения и точки удаленного входа\n\n")
	if len(yellowItems) > 0 {
		for _, item := range yellowItems {
			sb.WriteString(item + "\n\n")
		}
	} else {
		sb.WriteString("✅ *Потенциально опасных точек входа без защиты не обнаружено.*\n\n")
	}

	sb.WriteString("### 🟢 ЗЕЛЕНЫЙ УРОВЕНЬ: Штатные сервисы без замечаний\n\n")
	if len(greenItems) > 0 {
		for _, item := range greenItems {
			sb.WriteString(item + "\n\n")
		}
	} else {
		sb.WriteString("*Штатных вспомогательных служб не зафиксировано.*\n\n")
	}

	// --- 5. TOP-3 PRIORITY ACTION PLAN ---
	sb.WriteString("### 🎯 ТОП-3 первоочередных шага для ИТ-отдела на сегодня:\n\n")
	if len(redItems) > 0 {
		sb.WriteString("1. **Сетевая изоляция периметра:** Настроить правила межсетевого экрана (файрвола), закрыв публичный доступ к критическим портам.\n")
		sb.WriteString("2. **Установка патчей безопасности:** Произвести внеплановое обновление скомпрометированных пакетов программного обеспечения до стабильных версий.\n")
		sb.WriteString("3. **Аудит журналов доступа (SIEM/Logs):** Проверить системные логи на предмет следов возможной эксплуатации обнаруженных уязвимостей в прошлом.\n\n")
	} else {
		sb.WriteString("1. **Контроль учетных записей:** Включить обязательную двухфакторную аутентификацию (2FA) для всех административных интерфейсов.\n")
		sb.WriteString("2. **Регламент обновлений:** Настроить регулярную установку обновлений операционной системы по расписанию.\n")
		sb.WriteString("3. **Периодический аудит:** Проводить повторное сканирование сетевого периметра не реже одного раза в месяц.\n\n")
	}

	// --- 6. OPTIONAL EXPANDABLE REASONING SPOILER ---
	if reasoningLog != "" && strings.TrimSpace(reasoningLog) != "" {
		sb.WriteString("\n---\n")
		sb.WriteString("<details>\n")
		sb.WriteString("<summary>🧠 Технический лог рассуждений модели (Для специалистов ИБ)</summary>\n\n")
		sb.WriteString("```\n")
		sb.WriteString(strings.TrimSpace(reasoningLog) + "\n")
		sb.WriteString("```\n")
		sb.WriteString("</details>\n")
	}

	return sb.String()
}
