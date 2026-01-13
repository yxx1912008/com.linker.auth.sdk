package model

import (
	"time"
)


// http请求响应体
type AuthRestResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
	Success bool   `json:"success"`
}

// 授权服务请求的结构体
type AuthorizationReq struct {
	ProductCode string `json:"productCode"` // 设备码
}

// 自定义时间类型
type CustomTime time.Time

// 定义时间格式
const CustomTimeFormat = "2006-01-02T15:04:05"

// 实现 UnmarshalJSON 接口
func (ct *CustomTime) UnmarshalJSON(data []byte) error {
	// 去掉引号
	str := string(data)
	str = str[1 : len(str)-1]
	// 使用自定义格式解析时间
	parsedTime, err := time.Parse(CustomTimeFormat, str)
	if err != nil {
		return err
	}
	// 转换为 CustomTime 类型
	*ct = CustomTime(parsedTime)
	return nil
}

// 获取time.Time类型
func (ct *CustomTime) GetTime() time.Time {
	return time.Time(*ct)
}

// 授权服务返回的结构体
type AuthorizationResp struct {
	DeviceIdentification []string   `json:"deviceIdentification"` // 设备码（多个以逗号分隔）
	EffectiveDate        CustomTime `json:"effectiveDate"`        // 授权到期时间
	StartTime            CustomTime `json:"startTime"`            // 授权开始时间
	PerpetualLicense     int        `json:"perpetualLicense"`     //是否永久授权，0:否，1:是
	LicenseType          int        `json:"licenseType"`          //授权方式，0:离线，1:在线
	ContractNumber       string     `json:"contractNumber"`       //合同编号
	EmpowerId            int64      `json:"empowerId"`            //授权id（需存储，心跳和上报时候会用到）
	ProductCode          int        `json:"productCode"`          //产品唯一code
	GoodsCode            []string   `json:"goodsCode"`            //需要上报的商品code（多个以逗号分隔）
	IntervalTime         int        `json:"intervalTime"`         //心跳频率，单位：小时
	ExpandParam          string     `json:"expandParam"`          //拓展参数
	IsAuthInfo           bool       `json:"isAuthInfo"`           //
}
