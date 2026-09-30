package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// Runner abstracts running a security scan
type Runner interface {
	RunScan(ctx context.Context, target string, profile ScanProfile, onLog func(string)) ([]byte, error)
}

// NmapRunner executes Nmap CLI as a subprocess
type NmapRunner struct {
	NmapPath string
}

// NewNmapRunner creates an NmapRunner with configured binary path
func NewNmapRunner(nmapPath string) *NmapRunner {
	if nmapPath == "" {
		nmapPath = "nmap"
	}
	return &NmapRunner{NmapPath: nmapPath}
}

// RunScan runs nmap with the specified profile flags and returns raw XML bytes
func (r *NmapRunner) RunScan(ctx context.Context, target string, profile ScanProfile, onLog func(string)) ([]byte, error) {
	args := []string{}
	args = append(args, profile.DefaultArgs...)

	// Ensure XML stdout is enabled
	hasOX := false
	for _, a := range args {
		if a == "-oX" {
			hasOX = true
			break
		}
	}
	if !hasOX {
		args = append(args, "-oX", "-")
	}

	// Append target as last argument
	args = append(args, target)

	onLog(fmt.Sprintf("[SCANNER] Запуск процесса: %s %s", r.NmapPath, strings.Join(args, " ")))
	startTime := time.Now()

	cmd := exec.CommandContext(ctx, r.NmapPath, args...)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	cmd.Stdout = &stdoutBuf
	cmd.Stderr = io.MultiWriter(&stderrBuf, &logWriter{onLog: onLog})

	err := cmd.Run()
	duration := time.Since(startTime).Round(time.Millisecond)

	if err != nil {
		stderrStr := strings.TrimSpace(stderrBuf.String())
		onLog(fmt.Sprintf("[ERROR] Nmap завершился с ошибкой за %s: %v. Stderr: %s", duration, err, stderrStr))

		// Check for permission errors on Windows/Linux (e.g. -sS or -O requires root/administrator)
		if strings.Contains(strings.ToLower(stderrStr), "requires root") ||
			strings.Contains(strings.ToLower(stderrStr), "requires administrator") ||
			strings.Contains(strings.ToLower(stderrStr), "winpcap") ||
			strings.Contains(strings.ToLower(stderrStr), "npcap") {
			onLog("[WARN] Обнаружено ограничение прав для SYN-сканирования (-sS). Пробуем fallback на TCP Connect (-sT)...")
			fallbackArgs := make([]string, 0, len(args))
			for _, a := range args {
				if a == "-sS" {
					fallbackArgs = append(fallbackArgs, "-sT")
				} else if a == "-O" {
					continue
				} else {
					fallbackArgs = append(fallbackArgs, a)
				}
			}
			fallbackCmd := exec.CommandContext(ctx, r.NmapPath, fallbackArgs...)
			stdoutBuf.Reset()
			stderrBuf.Reset()
			fallbackCmd.Stdout = &stdoutBuf
			fallbackCmd.Stderr = &stderrBuf
			if fbErr := fallbackCmd.Run(); fbErr == nil {
				onLog(fmt.Sprintf("[SCANNER] Сканирование завершено успешно в режиме TCP Connect (-sT) за %s", time.Since(startTime).Round(time.Millisecond)))
				return stdoutBuf.Bytes(), nil
			}
		}

		if strings.Contains(err.Error(), "executable file not found") {
			return nil, fmt.Errorf("утилита nmap не найдена по пути '%s'. Установите Nmap или укажите путь в настройках", r.NmapPath)
		}
		return nil, fmt.Errorf("ошибка выполнения Nmap: %v (%s)", err, stderrStr)
	}

	onLog(fmt.Sprintf("[SCANNER] Сканирование успешно завершено за %s. Получено %d байт XML.", duration, stdoutBuf.Len()))
	return stdoutBuf.Bytes(), nil
}

type logWriter struct {
	onLog func(string)
}

func (w *logWriter) Write(p []byte) (n int, err error) {
	lines := strings.Split(string(p), "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" {
			w.onLog("[NMAP STDERR] " + trimmed)
		}
	}
	return len(p), nil
}
