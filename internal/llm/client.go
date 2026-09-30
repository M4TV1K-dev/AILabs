package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"host-security-auditor/internal/config"
	"host-security-auditor/internal/normalizer"
)

// AIResult holds both the final extracted analysis and any reasoning thoughts
type AIResult struct {
	Analysis  string
	Reasoning string
}

// Client handles interaction with local LLM APIs
type Client struct {
	cfg        config.LLMConfig
	httpClient *http.Client
}

// NewClient creates an LLM Client instance
func NewClient(cfg config.LLMConfig) *Client {
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 600 * time.Second, // 10 minutes: local inference on CPU/GPU
		},
	}
}

// UpdateConfig updates the client's configuration
func (c *Client) UpdateConfig(cfg config.LLMConfig) {
	c.cfg = cfg
}

// GenerateAnalysis queries the LLM and returns both clean analysis text and reasoning
func (c *Client) GenerateAnalysis(ctx context.Context, manifest *normalizer.IncidentManifest) (*AIResult, error) {
	userPrompt, err := BuildUserPrompt(manifest)
	if err != nil {
		return nil, err
	}

	provider := strings.ToLower(strings.TrimSpace(c.cfg.Provider))
	if provider == "ollama" && !strings.Contains(c.cfg.Endpoint, "/v1") {
		text, err := c.callOllamaNative(ctx, userPrompt)
		if err != nil {
			return nil, err
		}
		return &AIResult{Analysis: text}, nil
	}

	return c.callOpenAICompatible(ctx, userPrompt)
}

// GenerateReport satisfies legacy interface
func (c *Client) GenerateReport(ctx context.Context, manifest *normalizer.IncidentManifest) (string, error) {
	res, err := c.GenerateAnalysis(ctx, manifest)
	if err != nil {
		return "", err
	}
	if res.Analysis != "" {
		return res.Analysis, nil
	}
	return res.Reasoning, nil
}

func (c *Client) callOpenAICompatible(ctx context.Context, userPrompt string) (*AIResult, error) {
	baseEndpoint := strings.TrimRight(c.cfg.Endpoint, "/")
	endpoint := baseEndpoint
	if !strings.HasSuffix(endpoint, "/chat/completions") {
		endpoint += "/chat/completions"
	}

	modelName := c.resolveModelName(baseEndpoint)

	maxTokens := c.cfg.MaxTokens
	if maxTokens < 2000 {
		maxTokens = 2500
	}

	payload := map[string]interface{}{
		"model": modelName,
		"messages": []map[string]string{
			{"role": "system", "content": SystemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"temperature": c.cfg.Temperature,
		"max_tokens":  maxTokens,
		"stream":      false,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("ошибка кодирования запроса: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("ошибка создания запроса: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ошибка соединения с TextGen/LLM сервером (%s): %w", endpoint, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения ответа: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("LLM сервер вернул код %d: %s", resp.StatusCode, string(respBytes))
	}

	var chatResp struct {
		Choices []struct {
			Index   int `json:"index"`
			Message struct {
				Role             string `json:"role"`
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(respBytes, &chatResp); err != nil {
		return nil, fmt.Errorf("ошибка разбора JSON ответа TextGen: %w", err)
	}

	if chatResp.Error != nil && chatResp.Error.Message != "" {
		return nil, fmt.Errorf("ошибка TextGen API: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("модель вернула 0 вариантов ответа")
	}

	choice := chatResp.Choices[0]
	mainContent := strings.TrimSpace(choice.Message.Content)
	reasoning := strings.TrimSpace(choice.Message.ReasoningContent)

	// Extract the most complete and polished Russian analysis
	analysis := normalizer.ExtractBestAIAnalysis(mainContent, reasoning, choice.FinishReason)

	return &AIResult{
		Analysis:  analysis,
		Reasoning: reasoning,
	}, nil
}

func (c *Client) resolveModelName(baseEndpoint string) string {
	if c.cfg.Model != "" && c.cfg.Model != "qwen2.5" && c.cfg.Model != "default" {
		return c.cfg.Model
	}

	modelsURL := baseEndpoint
	if strings.HasSuffix(modelsURL, "/chat/completions") {
		modelsURL = strings.TrimSuffix(modelsURL, "/chat/completions")
	}
	modelsURL = strings.TrimRight(modelsURL, "/") + "/models"

	req, err := http.NewRequest("GET", modelsURL, nil)
	if err != nil {
		return c.cfg.Model
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return c.cfg.Model
	}
	defer resp.Body.Close()

	var modelsResp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&modelsResp); err == nil && len(modelsResp.Data) > 0 {
		return modelsResp.Data[0].ID
	}

	return c.cfg.Model
}

func (c *Client) callOllamaNative(ctx context.Context, userPrompt string) (string, error) {
	endpoint := strings.TrimRight(c.cfg.Endpoint, "/")
	if !strings.HasSuffix(endpoint, "/api/chat") {
		if strings.HasSuffix(endpoint, "/api") {
			endpoint += "/chat"
		} else {
			endpoint += "/api/chat"
		}
	}

	payload := map[string]interface{}{
		"model": c.cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": SystemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"stream": false,
		"options": map[string]interface{}{
			"temperature": c.cfg.Temperature,
			"num_predict": c.cfg.MaxTokens,
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ошибка подключения к Ollama (%s): %w", endpoint, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Ollama вернула код %d: %s", resp.StatusCode, string(respBytes))
	}

	var ollamaResp struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
	}

	if err := json.Unmarshal(respBytes, &ollamaResp); err != nil {
		return "", fmt.Errorf("ошибка парсинга ответа Ollama: %w", err)
	}

	return strings.TrimSpace(ollamaResp.Message.Content), nil
}

func (c *Client) TestConnection(ctx context.Context) error {
	endpoint := strings.TrimRight(c.cfg.Endpoint, "/")
	modelsURL := endpoint
	if !strings.HasSuffix(modelsURL, "/models") {
		modelsURL += "/models"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", modelsURL, nil)
	if err != nil {
		return err
	}
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	testClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := testClient.Do(req)
	if err != nil {
		req2, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		resp2, err2 := testClient.Do(req2)
		if err2 != nil {
			return fmt.Errorf("нет связи с сервером %s: %w", endpoint, err)
		}
		defer resp2.Body.Close()
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return fmt.Errorf("сервер вернул статус ошибки: %d", resp.StatusCode)
	}

	return nil
}
