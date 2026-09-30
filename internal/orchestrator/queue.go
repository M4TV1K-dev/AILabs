package orchestrator

import (
	"sync"
	"time"

	"host-security-auditor/internal/normalizer"
)

// TaskStatus defines current step of execution
type TaskStatus string

const (
	StatusQueued       TaskStatus = "queued"
	StatusScanning     TaskStatus = "scanning"
	StatusNormalizing  TaskStatus = "normalizing"
	StatusAnalyzingLLM TaskStatus = "analyzing_llm"
	StatusCompleted    TaskStatus = "completed"
	StatusFailed       TaskStatus = "failed"
)

// AuditTask represents a complete audit task from scan to executive report
type AuditTask struct {
	ID          string                       `json:"id"`
	Target      string                       `json:"target"`
	TargetInfo  TargetInfo                   `json:"target_info"`
	Profile     ScanProfile                  `json:"profile"`
	Status      TaskStatus                   `json:"status"`
	Progress    int                          `json:"progress"`
	Logs        []string                     `json:"logs"`
	RawXML      string                       `json:"raw_xml,omitempty"`
	Manifest    *normalizer.IncidentManifest `json:"manifest,omitempty"`
	LLMReport   string                       `json:"llm_report,omitempty"`
	Error       string                       `json:"error,omitempty"`
	IsDemo      bool                         `json:"is_demo"`
	NoLLM       bool                         `json:"no_llm"`
	CreatedAt   time.Time                    `json:"created_at"`
	CompletedAt *time.Time                   `json:"completed_at,omitempty"`
	Duration    string                       `json:"duration,omitempty"`
}

// TaskStore manages concurrent access to audit tasks
type TaskStore struct {
	mu    sync.RWMutex
	tasks map[string]*AuditTask
	order []string
}

// NewTaskStore creates a thread-safe task repository
func NewTaskStore() *TaskStore {
	return &TaskStore{
		tasks: make(map[string]*AuditTask),
		order: []string{},
	}
}

// Add inserts or updates a task
func (s *TaskStore) Add(task *AuditTask) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tasks[task.ID]; !exists {
		s.order = append([]string{task.ID}, s.order...)
	}
	s.tasks[task.ID] = task
}

// Get retrieves a task by ID
func (s *TaskStore) Get(id string) (*AuditTask, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tasks[id]
	return t, ok
}

// List returns all tasks in reverse chronological order
func (s *TaskStore) List() []*AuditTask {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*AuditTask, 0, len(s.order))
	for _, id := range s.order {
		if t, ok := s.tasks[id]; ok {
			result = append(result, t)
		}
	}
	return result
}

// AppendLog adds a log line to a task
func (s *TaskStore) AppendLog(id, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if t, ok := s.tasks[id]; ok {
		t.Logs = append(t.Logs, line)
	}
}

// UpdateStatus changes status and progress
func (s *TaskStore) UpdateStatus(id string, status TaskStatus, progress int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if t, ok := s.tasks[id]; ok {
		t.Status = status
		t.Progress = progress
	}
}
