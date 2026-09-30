package llm

import (
	"encoding/json"
	"fmt"
	"strings"

	"host-security-auditor/internal/normalizer"
)

// SystemPrompt guides the model to produce a concise, professional executive analysis strictly in Russian
const SystemPrompt = `Ты — ведущий аналитик центра мониторинга кибербезопасности (SOC).
Перед тобой результаты сканирования сетевого хоста.
Твоя задача — составить краткое, убедительное АНАЛИТИЧЕСКОЕ ЗАКЛЮЧЕНИЕ ДЛЯ ГЕНЕРАЛЬНОГО ДИРЕКТОРА компании на РУССКОМ ЯЗЫКЕ.

СТРОГИЕ ПРАВИЛА:
1. ЯЗЫК ОТВЕТА: ИСКЛЮЧИТЕЛЬНО РУССКИЙ ЯЗЫК. Не используй английский язык (кроме общепринятых аббревиатур: CVE, RCE, IP, TCP, HTTP, SSH, SMB).
2. Рассуждай предельно кратко (не более 100 слов в блоке мыслей). Не дублируй несколько черновиков. Сразу выводи законченный итоговый ответ.
3. Оперируй ТОЛЬКО фактами и CVE из предоставленного JSON. Запрещено выдумывать уязвимости, которых нет в списке.
4. Структура ответа (3 четких блока):
   - **Оценка угрозы для бизнеса:** объясни директору простыми словами, чем грозят найденные уязвимости (простой бизнеса, финансовые потери, утечка конфиденциальных данных клиентов, шифрование серверов).
   - **Сценарий атаки:** как злоумышленник снаружи может воспользоваться этими портами.
   - **Ключевой вывод:** почему действовать нужно безотлагательно.
5. Итоговый ответ должен быть полным, цельным и логически завершенным (без обрыва предложений).`

// BuildUserPrompt wraps the incident manifest into the prompt for LLM
func BuildUserPrompt(manifest *normalizer.IncidentManifest) (string, error) {
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("ошибка сериализации JSON-манифеста: %w", err)
	}

	var sb strings.Builder
	sb.WriteString("Входной JSON-манифест инцидента безопасности хоста:\n```json\n")
	sb.WriteString(string(manifestJSON))
	sb.WriteString("\n```\n\n")
	sb.WriteString("Составь аналитическое заключение для руководства компании строго на русском языке согласно инструкции.")

	return sb.String(), nil
}
