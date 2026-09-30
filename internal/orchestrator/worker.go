package orchestrator

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"host-security-auditor/internal/config"
	"host-security-auditor/internal/llm"
	"host-security-auditor/internal/normalizer"
	"host-security-auditor/internal/scanner"
)

// Orchestrator coordinates the pipeline from scanning to LLM synthesis
type Orchestrator struct {
	Store       *TaskStore
	Cfg         *config.Config
	LLMClient   *llm.Client
	NmapRunner  scanner.Runner
	MockRunner  scanner.Runner
}

// NewOrchestrator creates a new Orchestrator instance
func NewOrchestrator(cfg *config.Config, llmClient *llm.Client) *Orchestrator {
	return &Orchestrator{
		Store:      NewTaskStore(),
		Cfg:        cfg,
		LLMClient:  llmClient,
		NmapRunner: scanner.NewNmapRunner(cfg.GetNmapPath()),
		MockRunner: scanner.NewMockRunner(),
	}
}

// SubmitTask validates parameters and launches the audit pipeline asynchronously
func (o *Orchestrator) SubmitTask(targetInput string, profileID ScanProfileID, isDemo bool, noLLM bool) (*AuditTask, error) {
	// 1. Validate Target
	targetInfo, err := ValidateTarget(targetInput)
	if err != nil {
		return nil, fmt.Errorf("ошибка валидации цели: %w", err)
	}

	// 2. Resolve Profile
	profile, ok := GetProfile(profileID)
	if !ok {
		profile, _ = GetProfile(ProfileStandard)
	}

	// 3. Generate Task ID
	now := time.Now()
	taskID := fmt.Sprintf("audit-%s-%04d", now.Format("20060102-150405"), rand.Intn(10000))

	task := &AuditTask{
		ID:         taskID,
		Target:     targetInfo.Clean,
		TargetInfo: *targetInfo,
		Profile:    profile,
		Status:     StatusQueued,
		Progress:   0,
		Logs:       []string{fmt.Sprintf("[%s] Задача создана для цели %s (%s)", now.Format("15:04:05"), targetInfo.Clean, targetInfo.Type)},
		IsDemo:     isDemo,
		NoLLM:      noLLM,
		CreatedAt:  now,
	}

	o.Store.Add(task)

	// Launch in background
	go o.runPipeline(task)

	return task, nil
}

// runPipeline executes: Nmap -> XML Normalizer -> Strict JSON Manifest -> Local LLM
func (o *Orchestrator) runPipeline(task *AuditTask) {
	startTime := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	log := func(msg string) {
		ts := time.Now().Format("15:04:05")
		line := fmt.Sprintf("[%s] %s", ts, msg)
		o.Store.AppendLog(task.ID, line)
	}

	// --- STAGE 1: SCANNING ---
	o.Store.UpdateStatus(task.ID, StatusScanning, 15)
	log(fmt.Sprintf("==> ЭТАП 1/3: Запуск сканирования Nmap [Профиль: %s]...", task.Profile.Name))

	var runner scanner.Runner
	if task.IsDemo {
		log("[STAND] Запущен режим стендовой симуляции (согласно сценарию из PDF)")
		runner = o.MockRunner
	} else {
		// Use configured nmap path
		runner = scanner.NewNmapRunner(o.Cfg.GetNmapPath())
	}

	xmlBytes, err := runner.RunScan(ctx, task.Target, task.Profile, log)
	if err != nil {
		task.Status = StatusFailed
		task.Error = err.Error()
		log(fmt.Sprintf("[ОШИБКА СКАНИРОВАНИЯ] %v", err))
		o.Store.Add(task)
		return
	}

	task.RawXML = string(xmlBytes)
	o.Store.UpdateStatus(task.ID, StatusNormalizing, 50)

	// --- STAGE 2: NORMALIZATION & DATA AGGREGATION ---
	log("==> ЭТАП 2/3: Нормализация Nmap XML и сборка контекстного JSON-манифеста...")
	manifest, err := normalizer.ParseNmapXML(xmlBytes, task.Profile.Name)
	if err != nil {
		task.Status = StatusFailed
		task.Error = fmt.Sprintf("Ошибка парсинга XML: %v", err)
		log(fmt.Sprintf("[ОШИБКА НОРМАЛИЗАЦИИ] %v", err))
		o.Store.Add(task)
		return
	}

	// Ensure target metadata matches validated target
	if manifest.TargetMetadata.IP == "" || manifest.TargetMetadata.IP == "Unknown" {
		manifest.TargetMetadata.IP = task.Target
	}

	task.Manifest = manifest
	totalCVEs := 0
	for _, s := range manifest.OpenServices {
		totalCVEs += len(s.ReportedCVEs)
	}
	log(fmt.Sprintf("[НОРМАЛИЗАТОР] Успешно сформирован манифест: %d открытых сервисов, %d подтвержденных CVE", len(manifest.OpenServices), totalCVEs))
	o.Store.UpdateStatus(task.ID, StatusAnalyzingLLM, 70)

	// --- STAGE 3: SYNTHESIS & REPORTING ---
	var aiSummary, reasoning string
	if task.NoLLM {
		log("==> ЭТАП 3/3: Экспресс-генерация SOC-отчета (детерминированный режим без LLM)...")
	} else {
		o.Store.UpdateStatus(task.ID, StatusAnalyzingLLM, 70)
		log(fmt.Sprintf("==> ЭТАП 3/3: Передача данных в локальную LLM (%s via %s)...", o.Cfg.LLM.Model, o.Cfg.LLM.Provider))
		log("[LLM] Применение строгого системного промпта SOC аналитика (защита от галлюцинаций)...")

		// Update LLM config before call in case user edited settings
		o.LLMClient.UpdateConfig(o.Cfg.GetLLM())

		aiResult, err := o.LLMClient.GenerateAnalysis(ctx, manifest)
		if err != nil {
			log(fmt.Sprintf("[ВНИМАНИЕ] LLM вернул сообщение: %v. Формируем эталонный отчет...", err))
		} else {
			aiSummary = aiResult.Analysis
			reasoning = aiResult.Reasoning
			log("[LLM] Экспертное заключение от локальной нейросети успешно синтезировано!")
		}
	}

	report := normalizer.BuildExecutiveReport(manifest, aiSummary, reasoning)

	// --- COMPLETION ---
	completedAt := time.Now()
	duration := completedAt.Sub(startTime).Round(time.Second).String()

	task.LLMReport = report
	task.Status = StatusCompleted
	task.Progress = 100
	task.CompletedAt = &completedAt
	task.Duration = duration
	o.Store.Add(task)

	log(fmt.Sprintf("==> Аудит успешно завершен за %s!", duration))
}

// generateDeterministicFallbackReport builds an offline report if TextGen/LLM server is temporarily offline
func generateDeterministicFallbackReport(m *normalizer.IncidentManifest, llmErr error) string {
	var sb strings.Builder

	sb.WriteString("# 🛡️ Отчет аудита защищенности хоста (Автоматическая сводка)\n\n")
	sb.WriteString(fmt.Sprintf("> ⚠️ **Примечание:** Локальный сервер LLM вернул сообщение: `%v`.\n", llmErr))
	sb.WriteString("> Ниже представлена первичная структурная раскладка по правилам безопасности из спецификации:\n\n")

	sb.WriteString(fmt.Sprintf("**Цель:** `%s` | **ОС:** `%s` | **Профиль:** `%s`\n\n",
		m.TargetMetadata.IP, m.TargetMetadata.OSDetected, m.TargetMetadata.ScanType))

	var redList, yellowList, greenList []string

	for _, s := range m.OpenServices {
		if len(s.ReportedCVEs) > 0 {
			maxCVSS := 0.0
			for _, c := range s.ReportedCVEs {
				if c.CVSS > maxCVSS {
					maxCVSS = c.CVSS
				}
			}
			cveDetails := ""
			for _, c := range s.ReportedCVEs {
				cveDetails += fmt.Sprintf("  - **%s** (CVSS %.1f, %s)\n", c.ID, c.CVSS, c.Type)
			}

			if maxCVSS >= 7.0 {
				redList = append(redList, fmt.Sprintf("- **Порт %d/%s (%s %s)**\n%s  👉 **Действие:** Срочно изолировать порт на межсетевом экране, обновить сервис до актуальной версии!",
					s.Port, s.Protocol, s.Product, s.Version, cveDetails))
			} else {
				yellowList = append(yellowList, fmt.Sprintf("- **Порт %d/%s (%s %s)**\n%s  👉 **Действие:** Запланировать обновление компонента.",
					s.Port, s.Protocol, s.Product, s.Version, cveDetails))
			}
		} else if s.Port == 22 || s.Port == 3389 || s.Port == 445 || s.Port == 21 {
			yellowList = append(yellowList, fmt.Sprintf("- **Порт %d/%s (%s %s)**: Сервис удаленного доступа без явных CVE.\n  👉 **Действие:** Ограничить доступ через белый список IP / VPN, включить двухфакторную аутентификацию (2FA).",
				s.Port, s.Protocol, s.Product, s.Version))
		} else {
			greenList = append(greenList, fmt.Sprintf("- **Порт %d/%s (%s %s)**: Штатная служба без зафиксированных уязвимостей.\n  👉 **Действие:** Регулярный мониторинг журнала событий.",
				s.Port, s.Protocol, s.Product, s.Version))
		}
	}

	sb.WriteString("## 🔴 КРАСНЫЙ УРОВЕНЬ (Критично)\n")
	if len(redList) > 0 {
		for _, item := range redList {
			sb.WriteString(item + "\n\n")
		}
	} else {
		sb.WriteString("Критических уязвимостей с высоким CVSS не обнаружено.\n\n")
	}

	sb.WriteString("## 🟡 ЖЕЛТЫЙ УРОВЕНЬ (Предупреждение)\n")
	if len(yellowList) > 0 {
		for _, item := range yellowList {
			sb.WriteString(item + "\n\n")
		}
	} else {
		sb.WriteString("Потенциально опасных служб удаленного доступа не обнаружено.\n\n")
	}

	sb.WriteString("## 🟢 ЗЕЛЕНЫЙ УРОВЕНЬ (Безопасно)\n")
	if len(greenList) > 0 {
		for _, item := range greenList {
			sb.WriteString(item + "\n\n")
		}
	} else {
		sb.WriteString("Штатных служб без замечаний не обнаружено.\n\n")
	}

	sb.WriteString("## 📋 Рекомендации для руководства\n")
	sb.WriteString("1. Немедленно ограничить сетевой периметр правилами файрвола.\n")
	sb.WriteString("2. Обновить уязвимые компоненты программного обеспечения.\n")
	sb.WriteString("3. Подключите клиент TextGen или Ollama в настройках веб-панели для генерации развернутого бизнес-отчета от языковой модели.\n")

	return sb.String()
}
