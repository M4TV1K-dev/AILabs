package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"host-security-auditor/internal/config"
	"host-security-auditor/internal/llm"
	"host-security-auditor/internal/normalizer"
	"host-security-auditor/internal/orchestrator"
)

//go:embed static/*
var staticFS embed.FS

// Server handles HTTP API requests and serves embedded web UI
type Server struct {
	cfg          *config.Config
	orchestrator *orchestrator.Orchestrator
	llmClient    *llm.Client
	configPath   string
	mux          *http.ServeMux
}

// NewServer initializes the HTTP server
func NewServer(cfg *config.Config, orch *orchestrator.Orchestrator, llmClient *llm.Client, configPath string) *Server {
	s := &Server{
		cfg:          cfg,
		orchestrator: orch,
		llmClient:    llmClient,
		configPath:   configPath,
		mux:          http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	// Serve embedded static files
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(staticSub))
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", fileServer))
	s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		indexBytes, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "Failed to load index.html", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexBytes)
	})

	// API Endpoints
	s.mux.HandleFunc("GET /api/profiles", s.handleGetProfiles)
	s.mux.HandleFunc("GET /api/tasks", s.handleGetTasks)
	s.mux.HandleFunc("POST /api/tasks", s.handleCreateTask)
	s.mux.HandleFunc("GET /api/tasks/{id}", s.handleGetTaskByID)
	s.mux.HandleFunc("POST /api/tasks/{id}/reanalyze", s.handleReanalyzeTask)
	s.mux.HandleFunc("GET /api/tasks/{id}/download", s.handleDownloadReport)
	s.mux.HandleFunc("GET /api/config", s.handleGetConfig)
	s.mux.HandleFunc("POST /api/config", s.handleUpdateConfig)
	s.mux.HandleFunc("POST /api/llm/test", s.handleTestLLM)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Simple CORS & JSON default headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleGetProfiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, orchestrator.AvailableProfiles())
}

func (s *Server) handleGetTasks(w http.ResponseWriter, r *http.Request) {
	tasks := s.orchestrator.Store.List()
	writeJSON(w, http.StatusOK, tasks)
}

type createTaskRequest struct {
	Target    string                     `json:"target"`
	ProfileID orchestrator.ScanProfileID `json:"profile_id"`
	IsDemo    bool                       `json:"is_demo"`
	NoLLM     bool                       `json:"no_llm"`
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	var req createTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Некорректный JSON запроса")
		return
	}

	task, err := s.orchestrator.SubmitTask(req.Target, req.ProfileID, req.IsDemo, req.NoLLM)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, task)
}

func (s *Server) handleGetTaskByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	task, ok := s.orchestrator.Store.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "Задача не найдена")
		return
	}
	writeJSON(w, http.StatusOK, task)
}

func (s *Server) handleReanalyzeTask(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	task, ok := s.orchestrator.Store.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "Задача не найдена")
		return
	}
	if task.Manifest == nil {
		writeError(w, http.StatusBadRequest, "Для задачи отсутствует нормализованный манифест сканирования")
		return
	}

	go func() {
		s.orchestrator.Store.UpdateStatus(task.ID, orchestrator.StatusAnalyzingLLM, 80)
		s.orchestrator.Store.AppendLog(task.ID, "[LLM] Повторный запуск синтеза отчета через нейросеть...")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		s.llmClient.UpdateConfig(s.cfg.GetLLM())
		res, err := s.llmClient.GenerateAnalysis(ctx, task.Manifest)
		var aiSummary, reasoning string
		if err != nil {
			s.orchestrator.Store.AppendLog(task.ID, fmt.Sprintf("[ОШИБКА LLM] %v", err))
		} else {
			aiSummary = res.Analysis
			reasoning = res.Reasoning
			s.orchestrator.Store.AppendLog(task.ID, "[LLM] Отчет успешно обновлен моделью!")
		}
		task.LLMReport = normalizer.BuildExecutiveReport(task.Manifest, aiSummary, reasoning)
		s.orchestrator.Store.UpdateStatus(task.ID, orchestrator.StatusCompleted, 100)
		s.orchestrator.Store.Add(task)
	}()

	writeJSON(w, http.StatusOK, map[string]string{"message": "Анализ LLM запущен"})
}

func (s *Server) handleDownloadReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	task, ok := s.orchestrator.Store.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "Задача не найдена")
		return
	}

	filename := fmt.Sprintf("audit-report-%s.md", sanitizeFilename(task.Target))
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))

	content := task.LLMReport
	if content == "" {
		content = fmt.Sprintf("# Отчет по аудиту %s\n\nОтчет еще не сформирован. Текущий статус: %s", task.Target, task.Status)
	}
	w.Write([]byte(content))
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfgCopy := *s.cfg
	// Mask API key if set
	if cfgCopy.LLM.APIKey != "" {
		cfgCopy.LLM.APIKey = "******"
	}
	writeJSON(w, http.StatusOK, cfgCopy)
}

func (s *Server) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var newCfg config.Config
	if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
		writeError(w, http.StatusBadRequest, "Некорректный JSON конфигурации")
		return
	}

	// Keep existing API key if masked string was sent
	if newCfg.LLM.APIKey == "******" {
		newCfg.LLM.APIKey = s.cfg.LLM.APIKey
	}

	s.cfg.Update(newCfg)
	if err := s.cfg.Save(s.configPath); err != nil {
		writeError(w, http.StatusInternalServerError, "Ошибка сохранения config.json: "+err.Error())
		return
	}
	s.llmClient.UpdateConfig(newCfg.LLM)

	writeJSON(w, http.StatusOK, map[string]string{"message": "Конфигурация успешно сохранена"})
}

func (s *Server) handleTestLLM(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()

	s.llmClient.UpdateConfig(s.cfg.GetLLM())
	if err := s.llmClient.TestConnection(ctx); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("Ошибка связи с сервером LLM: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "Подключение к LLM успешно!"})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func sanitizeFilename(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, ":", "_")
	return filepath.Clean(s)
}
