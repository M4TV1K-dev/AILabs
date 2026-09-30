package orchestrator

import "host-security-auditor/internal/scanner"

// Re-export profile types from scanner to maintain clean architecture
type ScanProfileID = scanner.ScanProfileID
type ScanProfile = scanner.ScanProfile

const (
	ProfileFast       = scanner.ProfileFast
	ProfileStandard   = scanner.ProfileStandard
	ProfileAggressive = scanner.ProfileAggressive
	ProfileCustom     = scanner.ProfileCustom
)

// AvailableProfiles returns the profiles
func AvailableProfiles() []ScanProfile {
	return scanner.AvailableProfiles()
}

// GetProfile retrieves a profile by its ID
func GetProfile(id ScanProfileID) (ScanProfile, bool) {
	return scanner.GetProfile(id)
}
