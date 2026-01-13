package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"net/http"
	"sync"
	"time"

	"com.linker.auth.sdk/internal/model"
	tools "com.linker.auth.sdk/internal/utils"
	auth_model "com.linker.auth.sdk/pkg/model"
)

// AuthSDK 授权SDK的主结构体
type AuthSDK struct {
	config       *AuthConfigs
	status       auth_model.LicenseStatus
	mu           sync.RWMutex
	ticker       *time.Ticker
	httpClient   *http.Client
	shutdownChan chan struct{}
}

// 授权配置
type AuthConfigs struct {
	CheckInterval time.Duration `json:"checkInterval"` // 检查间隔
	AuthEndpoint  string        `json:"authEndpoint"`  //授权地址
	ProductCode   string        `json:"productCode"`   //产品码
	Enable        bool          `json:"enable"`        //是否开启sdk
	HttpTimeout   time.Duration `json:"httpTimeout"`   //http请求超时时间
	MaxRetryTimes int           `json:"maxRetryTimes"` //授权校验失败最大重试次数

}

func NewAuthConfigs() *AuthConfigs {
	return &AuthConfigs{
		CheckInterval: 1 * time.Hour,
		AuthEndpoint:  "",
		ProductCode:   "20",
		Enable:        false,
		HttpTimeout:   10 * time.Second,
		MaxRetryTimes: 3,
	}
}

// NewAuthSDK 创建一个新的授权SDK实例
func NewAuthSDK(config *AuthConfigs) (*AuthSDK, error) {

	if !config.Enable  {
		return nil, fmt.Errorf("auth is not enabled")
	}

	if config.AuthEndpoint == "" {
		return nil, fmt.Errorf("authEndpoint is required")
	}
	if config.CheckInterval <= 0 {
		config.CheckInterval = 1 * time.Hour // 默认每小时检查一次
	}

	sdk := &AuthSDK{
		config:       config,
		httpClient:   &http.Client{Timeout: config.HttpTimeout},
		shutdownChan: make(chan struct{}),
	}

	// 初始检查
	if err := sdk.checkLicense(); err != nil {
		return nil, fmt.Errorf("initial license check failed: %w", err)
	}

	// 启动定时检查
	sdk.startTicker()

	return sdk, nil
}

// GetLicenseStatus 获取当前授权状态
func (s *AuthSDK) GetLicenseStatus() auth_model.LicenseStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// Shutdown 优雅关闭SDK，停止定时检查
func (s *AuthSDK) Shutdown() {
	s.ticker.Stop()
	close(s.shutdownChan)
}

// 启动定时检查
func (s *AuthSDK) startTicker() {
	s.ticker = time.NewTicker(s.config.CheckInterval)
	go func() {
		for {
			select {
			case <-s.ticker.C:
				s.checkLicense()
			case <-s.shutdownChan:
				return
			}
		}
	}()
}

// 检查授权状态
func (s *AuthSDK) checkLicense() error {

	reqBody := &model.AuthorizationReq{
		ProductCode: s.config.ProductCode,
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request body failed: %w", err)
	}
	//转成string
	jsonBodyStr := string(jsonBody)
	//sm4加密
	finalStr, err := tools.EncryptDataCBC(jsonBodyStr)
	if err != nil {
		return fmt.Errorf("sm4加密失败: %w", err)
	}

	req, err := http.NewRequest("POST", s.config.AuthEndpoint, bytes.NewBuffer([]byte(finalStr)))
	if err != nil {
		return fmt.Errorf("create request failed: %w", err)
	}

	req.Header.Set("Content-Type", "text/plain")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.updateStatus(false, time.Time{}, "授权服务连接失败", err.Error())
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.updateStatus(false, time.Time{}, "读取响应失败", err.Error())
		return fmt.Errorf("read response body failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		s.updateStatus(false, time.Time{},
			fmt.Sprintf("授权服务返回错误状态码: %d", resp.StatusCode), string(body))
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var status model.AuthRestResponse
	if err := json.Unmarshal(body, &status); err != nil {
		s.updateStatus(false, time.Time{}, "解析授权响应失败", err.Error())
		return fmt.Errorf("unmarshal response failed: %w", err)
	}

	if status.Code != "0" && !status.Success {
		s.updateStatus(false, time.Time{}, status.Message, string(body))
		return fmt.Errorf("unexpected status code: %s", status.Code)
	}

	if status.Data == "" {
		s.updateStatus(false, time.Time{}, "授权服务返回空数据", string(body))
		return fmt.Errorf("unexpected status code: %s", status.Code)
	}

	var license model.AuthorizationResp

	//sm4解密
	licenseStr, err := tools.DecryptDataCBC(status.Data)
	if err != nil {
		s.updateStatus(false, time.Time{}, "sm4解密失败", err.Error())
		return fmt.Errorf("sm4解密失败: %w", err)
	}

	if err := json.Unmarshal([]byte(licenseStr), &license); err != nil {
		s.updateStatus(false, time.Time{}, "解析授权响应失败", err.Error())
		return fmt.Errorf("unmarshal response failed: %w", err)
	}

	s.updateStatus(license.IsAuthInfo, license.EffectiveDate.GetTime(), "操作成功", "")
	return nil
}

// 更新授权状态
func (s *AuthSDK) updateStatus(valid bool, expireDate time.Time, errorMsg, debugMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	//如果errcount<配置的次数，只计数，不更新状态
	if !valid && s.status.ErrorCount < s.config.MaxRetryTimes {
		s.status.ErrorCount++
		s.status.ErrorMessage = errorMsg
		return
	}

	if valid {
		s.status.ErrorCount = 0
	}

	s.status = auth_model.LicenseStatus{
		Valid:        valid,
		ExpireDate:   expireDate,
		ErrorMessage: errorMsg,
	}

	if debugMsg != "" {
		fmt.Printf("授权状态更新: %v, 调试信息: %s\n", s.status, debugMsg)
	} else {
		fmt.Printf("授权状态更新: %v\n", s.status)
	}
}
