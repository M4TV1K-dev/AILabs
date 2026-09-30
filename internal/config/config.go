package config

import (
	"encoding/json"
	"os"
	"sync"
)

// LLMConfig holds parameters for the local LLM inference engine.
type LLMConfig struct {
	Provider    string  `json:"provider"`    // "openai" (TextGen/LM-Studio/vLLM) or "ollama"
	Endpoint    string  `json:"endpoint"`    // e.g. "http://127.0.0.1:5000/v1" or "http://127.0.0.1:11434/api/chat"
	Model       string  `json:"model"`       // e.g. "qwen2.5:7b", "mistral-7b-instruct", etc.
	APIKey      string  `json:"api_key"`     // Optional, for providers requiring Bearer token
	Temperature float64 `json:"temperature"` // 0.1 - 0.3 recommended for factual SOC analysis
	MaxTokens   int     `json:"max_tokens"`  // Max generation tokens (e.g. 2048)
}

// Config represents the application configuration.
type Config struct {
	mu         sync.RWMutex
	ServerPort string    `json:"server_port"` // e.g. ":8080"
	NmapPath   string    `json:"nmap_path"`   // Custom path to nmap.exe or "nmap" from PATH
	LLM        LLMConfig `json:"llm"`
}

// DefaultConfig returns a preconfigured configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		ServerPort: ":8080",
		NmapPath:   "nmap",
		LLM: LLMConfig{
			Provider:    "openai", // TextGen WebUI standard /v1 API
			Endpoint:    "http://127.0.0.1:5000/v1",
			Model:       "qwen2.5",
			APIKey:      "",
			Temperature: 0.2,
			MaxTokens:   4096,
		},
	}
}

// Load loads configuration from a JSON file, or creates one if it doesn't exist.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			_ = cfg.Save(path)
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save writes current configuration to disk.
func (c *Config) Save(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Update updates the configuration in a thread-safe manner.
func (c *Config) Update(newCfg Config) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.ServerPort = newCfg.ServerPort
	c.NmapPath = newCfg.NmapPath
	c.LLM = newCfg.LLM
}

// GetLLM returns a copy of LLMConfig.
func (c *Config) GetLLM() LLMConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.LLM
}

// GetNmapPath returns current nmap executable path.
func (c *Config) GetNmapPath() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.NmapPath
}
