package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"host-security-auditor/internal/config"
	"host-security-auditor/internal/llm"
	"host-security-auditor/internal/orchestrator"
	"host-security-auditor/internal/web"
)

const version = "2.0.0"

func main() {
	var (
		portFlag       string
		configFlag     string
		noBrowserFlag  bool
		cliTargetFlag  string
		cliProfileFlag string
		cliDemoFlag    bool
		cliNoLLMFlag   bool
	)

	flag.StringVar(&portFlag, "port", "", "Server HTTP port (e.g. :8080)")
	flag.StringVar(&configFlag, "config", "config.json", "Path to config.json file")
	flag.BoolVar(&noBrowserFlag, "no-browser", false, "Do not open web browser automatically")
	flag.StringVar(&cliTargetFlag, "target", "", "Run in CLI mode for specific target")
	flag.StringVar(&cliProfileFlag, "profile", "aggressive", "Scan profile for CLI mode: fast, standard, aggressive")
	flag.BoolVar(&cliDemoFlag, "demo", false, "Use mock/stand mode for CLI test")
	flag.BoolVar(&cliNoLLMFlag, "no-llm", false, "Run express deterministic audit without LLM")
	flag.Parse()

	printBanner()

	// Load configuration
	cfg, err := config.Load(configFlag)
	if err != nil {
		log.Fatalf("[FATAL] Ошибка загрузки конфигурации: %v", err)
	}

	if portFlag != "" {
		if portFlag[0] != ':' {
			portFlag = ":" + portFlag
		}
		cfg.ServerPort = portFlag
	}

	// Initialize LLM Client
	llmClient := llm.NewClient(cfg.GetLLM())

	// Initialize Orchestrator
	orch := orchestrator.NewOrchestrator(cfg, llmClient)

	// If CLI target specified, run in terminal mode
	if cliTargetFlag != "" {
		runCLIMode(orch, cliTargetFlag, cliProfileFlag, cliDemoFlag, cliNoLLMFlag)
		return
	}

	// Start Web Server
	srv := web.NewServer(cfg, orch, llmClient, configFlag)

	addr := cfg.ServerPort
	serverURL := fmt.Sprintf("http://localhost%s", addr)

	fmt.Println("----------------------------------------------------------------------")
	fmt.Printf("🚀 Веб-интерфейс SOC Аналитика запущен: %s\n", serverURL)
	fmt.Printf("🔧 LLM Бэкенд: %s (%s) @ %s\n", cfg.LLM.Provider, cfg.LLM.Model, cfg.LLM.Endpoint)
	fmt.Printf("📡 Путь к Nmap: %s\n", cfg.GetNmapPath())
	fmt.Println("💡 Нажмите Ctrl+C для остановки сервера")
	fmt.Println("----------------------------------------------------------------------")

	// Open browser automatically
	if !noBrowserFlag {
		go func() {
			time.Sleep(600 * time.Millisecond)
			openBrowser(serverURL)
		}()
	}

	if err := http.ListenAndServe(addr, srv); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[FATAL] Ошибка запуска HTTP сервера: %v", err)
	}
}

func printBanner() {
	fmt.Println(`
╔══════════════════════════════════════════════════════════════════════╗
║           🛡️  HOST SECURITY AUDITOR (GO + LOCAL LLM)                ║
║           Модульная система аудита защищенности хостов               ║
║           Pipeline: Nmap -> Normalizer -> Strict JSON -> LLM         ║
╚══════════════════════════════════════════════════════════════════════╝`)
}

func runCLIMode(orch *orchestrator.Orchestrator, target, profile string, demo bool, noLLM bool) {
	fmt.Printf("[CLI] Запуск аудита для цели: %s (профиль: %s, демо: %v, без LLM: %v)\n", target, profile, demo, noLLM)
	task, err := orch.SubmitTask(target, orchestrator.ScanProfileID(profile), demo, noLLM)
	if err != nil {
		fmt.Printf("[CLI ОШИБКА] %v\n", err)
		os.Exit(1)
	}

	lastLogIdx := 0
	for {
		t, ok := orch.Store.Get(task.ID)
		if !ok {
			break
		}

		for lastLogIdx < len(t.Logs) {
			fmt.Println(t.Logs[lastLogIdx])
			lastLogIdx++
		}

		if t.Status == orchestrator.StatusCompleted {
			fmt.Println("\n================ ФИНАЛЬНЫЙ ОТЧЕТ ИБ ================")
			fmt.Println(t.LLMReport)
			fmt.Println("====================================================")
			break
		} else if t.Status == orchestrator.StatusFailed {
			fmt.Printf("\n[ОШИБКА АУДИТА] %s\n", t.Error)
			os.Exit(1)
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func openBrowser(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
		args = []string{url}
	}
	_ = exec.Command(cmd, args...).Start()
}
