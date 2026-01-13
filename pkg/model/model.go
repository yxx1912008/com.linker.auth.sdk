package auth_model

import "time"

// LicenseStatus 表示授权状态的结构体
type LicenseStatus struct {
	Valid        bool      `json:"valid"`
	ExpireDate   time.Time `json:"expireDate"`
	LicenseType  string    `json:"licenseType"`
	ErrorCount   int       `json:"errorCount"`
	ErrorMessage string    `json:"errorMessage"`
}

