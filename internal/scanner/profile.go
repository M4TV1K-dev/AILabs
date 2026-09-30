package scanner

// ScanProfileID represents profile identifier
type ScanProfileID string

const (
	ProfileFast       ScanProfileID = "fast"
	ProfileStandard   ScanProfileID = "standard"
	ProfileAggressive ScanProfileID = "aggressive"
	ProfileCustom     ScanProfileID = "custom"
)

// ScanProfile defines configuration and flags for an Nmap audit run
type ScanProfile struct {
	ID          ScanProfileID `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	DefaultArgs []string      `json:"default_args"`
	Goal        string        `json:"goal"`
}

// AvailableProfiles returns the profiles specified in the system design document
func AvailableProfiles() []ScanProfile {
	return []ScanProfile{
		{
			ID:          ProfileFast,
			Name:        "Экспресс-сканирование (Fast / Discovery)",
			Description: "Быстрая инвентаризация активных портов без углубления в детали",
			Goal:        "Массовый обзор хоста/подсети, минимальное время сканирования",
			DefaultArgs: []string{"-sS", "-T4", "--top-ports", "100", "-n"},
		},
		{
			ID:          ProfileStandard,
			Name:        "Базовый аудит сервисов (Standard)",
			Description: "Определение операционной системы и базовых версий сетевых служб",
			Goal:        "Инвентаризация сервисов и ОС без запуска тяжелых скриптов",
			DefaultArgs: []string{"-sV", "--version-light", "-O", "-T3"},
		},
		{
			ID:          ProfileAggressive,
			Name:        "Глубокий аудит уязвимостей (Aggressive / Audit)",
			Description: "Распознавание служб, сопоставление с базами CVE (NSE vulners) и детекция ОС",
			Goal:        "Полноценный аудит ИБ с извлечением известных уязвимостей (WordPress, SMB, SSH, Apache)",
			DefaultArgs: []string{"-sV", "--version-all", "-sC", "--script=vulners", "-O", "-T3", "--top-ports", "1000"},
		},
	}
}

// GetProfile retrieves a profile by its ID
func GetProfile(id ScanProfileID) (ScanProfile, bool) {
	for _, p := range AvailableProfiles() {
		if p.ID == id {
			return p, true
		}
	}
	return ScanProfile{}, false
}
