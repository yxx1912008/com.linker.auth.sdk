package tools

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// SM4 类相关常量
const (
	SM4_ENCRYPT       = 1
	SM4_DECRYPT       = 0
	DEFAULT_SECRETKEY = "AD42F6697B035B75"
	DEFAULT_IV        = "80E4FEF93BE20BAD"
)

// SboxTable 常量
// SboxTable 常量
var SboxTable = []byte{
	256 - 42, 256 - 112, 256 - 23, 256 - 2, 256 - 52, 256 - 31, 61, 256 - 73, 22, 256 - 74, 20, 256 - 62, 40, 256 - 5, 44, 5,
	43, 103, 256 - 102, 118, 42, 256 - 66, 4, 256 - 61, 256 - 86, 68, 19, 38, 73, 256 - 122, 6, 256 - 103,
	256 - 100, 66, 80, 256 - 12, 256 - 111, 256 - 17, 256 - 104, 122, 51, 84, 11, 67, 256 - 19, 256 - 49, 256 - 84,
	98, 256 - 28, 256 - 77, 28, 256 - 87, 256 - 55, 8, 256 - 24, 256 - 107, 256 - 128, 256 - 33, 256 - 108, 256 - 6, 117, 256 - 113,
	63, 256 - 90, 71, 7, 256 - 89, 256 - 4, 256 - 13, 115, 23, 256 - 70, 256 - 125, 89, 60, 25, 256 - 26, 256 - 123,
	79, 256 - 88, 104, 107, 256 - 127, 256 - 78, 113, 100, 256 - 38, 256 - 117, 256 - 8, 256 - 21, 15, 75, 112,
	86, 256 - 99, 53, 30, 36, 14, 94, 99, 88, 256 - 47, 256 - 94, 37, 34, 124, 59, 1, 33,
	120, 256 - 121, 256 - 44, 0, 70, 87, 256 - 97, 256 - 45, 39, 82, 76, 54, 2, 256 - 25, 256 - 96, 256 - 60,
	256 - 56, 256 - 98, 256 - 22, 256 - 65, 256 - 118, 256 - 46, 64, 256 - 57, 56, 256 - 75, 256 - 93, 256 - 9, 256 - 14, 256 - 50, 256 - 7,
	97, 21, 256 - 95, 256 - 32, 256 - 82, 93, 256 - 92, 256 - 101, 52, 26, 85, 256 - 83, 256 - 109, 50, 48, 256 - 11,
	256 - 116, 256 - 79, 256 - 29, 29, 256 - 10, 256 - 30, 46, 256 - 126, 102, 256 - 54, 96, 256 - 64, 41, 35, 256 - 85,
	13, 83, 78, 111, 256 - 43, 256 - 37, 55, 69, 256 - 34, 256 - 3, 256 - 114, 47, 3, 256 - 1, 106, 114,
	109, 108, 91, 81, 256 - 115, 27, 256 - 81, 256 - 110, 256 - 69, 256 - 35, 256 - 68, 127, 17, 256 - 39, 92,
	65, 31, 16, 90, 256 - 40, 10, 256 - 63, 49, 256 - 120, 256 - 91, 256 - 51, 123, 256 - 67, 45, 116, 256 - 48,
	18, 256 - 72, 256 - 27, 256 - 76, 256 - 80, 256 - 119, 105, 256 - 105, 74, 12, 256 - 106, 119, 126, 101, 256 - 71,
	256 - 15, 9, 256 - 59, 110, 256 - 58, 256 - 124, 24, 256 - 16, 125, 256 - 20, 58, 256 - 36, 77, 32, 121, 256 - 18,
	95, 62, 256 - 41, 256 - 53, 57, 72,
}

// FK 常量
var FK = []int32{
	-1548633402, 1453994832, 1736282519, -1301273892,
}

// CK 常量
var CK = []int32{
	462357, 472066609, 943670861, 1415275113, 1886879365, -1936483679,
	-1464879427, -993275175, -521670923, -66909679, 404694573, 876298825,
	1347903077, 1819507329, -2003855715, -1532251463, -1060647211, -589042959,
	-117504499, 337322537, 808926789, 1280531041, 1752135293, -2071227751,
	-1599623499, -1128019247, -656414995, -184876535, 269950501, 741554753,
	1213159005, 1684763257,
}

// 辅助函数：获取大端序的长整型
func GET_ULONG_BE(b []byte, i int) uint32 {
	return uint32(b[i]&0xff)<<24 | uint32(b[i+1]&0xff)<<16 | uint32(b[i+2]&0xff)<<8 | uint32(b[i+3]&0xff)
}

// 辅助函数：将长整型按大端序放入字节数组
func PUT_ULONG_BE(n uint32, b []byte, i int) {
	b[i] = byte(n >> 24)
	b[i+1] = byte(n >> 16)
	b[i+2] = byte(n >> 8)
	b[i+3] = byte(n)
}

// 辅助函数：左移
func SHL(x uint32, n int) uint32 {
	return x << n
}

// 辅助函数：循环左移
func ROTL(x uint32, n int) uint32 {
	return SHL(x, n) | (x >> (32 - n))
}

// 辅助函数：交换
func SWAP(sk []uint32, i int) {
	t := sk[i]
	sk[i] = sk[31-i]
	sk[31-i] = t
}

// sm4Sbox 函数
func sm4Sbox(inch byte) byte {
	i := int(inch & 0xff)
	return SboxTable[i]
}

// sm4Lt 函数
func sm4Lt(ka uint32) uint32 {
	var a [4]byte
	var b [4]byte
	PUT_ULONG_BE(ka, a[:], 0)
	b[0] = sm4Sbox(a[0])
	b[1] = sm4Sbox(a[1])
	b[2] = sm4Sbox(a[2])
	b[3] = sm4Sbox(a[3])
	bb := GET_ULONG_BE(b[:], 0)
	return bb ^ ROTL(bb, 2) ^ ROTL(bb, 10) ^ ROTL(bb, 18) ^ ROTL(bb, 24)
}

// sm4F 函数
func sm4F(x0, x1, x2, x3, rk uint32) uint32 {
	return x0 ^ sm4Lt(x1^x2^x3^rk)
}

// sm4CalciRK 函数
func sm4CalciRK(ka uint32) uint32 {
	var a [4]byte
	var b [4]byte
	PUT_ULONG_BE(ka, a[:], 0)
	b[0] = sm4Sbox(a[0])
	b[1] = sm4Sbox(a[1])
	b[2] = sm4Sbox(a[2])
	b[3] = sm4Sbox(a[3])
	bb := GET_ULONG_BE(b[:], 0)
	return bb ^ ROTL(bb, 13) ^ ROTL(bb, 23)
}

// sm4_setkey 函数
func sm4_setkey(SK []uint32, key []byte) {
	MK := make([]uint32, 4)
	k := make([]uint32, 36)
	MK[0] = GET_ULONG_BE(key, 0)
	MK[1] = GET_ULONG_BE(key, 4)
	MK[2] = GET_ULONG_BE(key, 8)
	MK[3] = GET_ULONG_BE(key, 12)
	k[0] = MK[0] ^ uint32(FK[0])
	k[1] = MK[1] ^ uint32(FK[1])
	k[2] = MK[2] ^ uint32(FK[2])
	k[3] = MK[3] ^ uint32(FK[3])
	for i := 0; i < 32; i++ {
		k[i+4] = k[i] ^ sm4CalciRK(k[i+1]^k[i+2]^k[i+3]^uint32(CK[i]))
		SK[i] = k[i+4]
	}
}

// sm4_one_round 函数
func sm4_one_round(sk []uint32, input []byte, output []byte) {
	ulbuf := make([]uint32, 36)
	ulbuf[0] = GET_ULONG_BE(input, 0)
	ulbuf[1] = GET_ULONG_BE(input, 4)
	ulbuf[2] = GET_ULONG_BE(input, 8)
	ulbuf[3] = GET_ULONG_BE(input, 12)
	for i := 0; i < 32; i++ {
		ulbuf[i+4] = sm4F(ulbuf[i], ulbuf[i+1], ulbuf[i+2], ulbuf[i+3], sk[i])
	}
	PUT_ULONG_BE(ulbuf[35], output, 0)
	PUT_ULONG_BE(ulbuf[34], output, 4)
	PUT_ULONG_BE(ulbuf[33], output, 8)
	PUT_ULONG_BE(ulbuf[32], output, 12)
}

// padding 函数
func padding(input []byte, mode int) []byte {
	if input == nil {
		return nil
	}
	if mode == 1 {
		p := 16 - len(input)%16
		ret := make([]byte, len(input)+p)
		copy(ret, input)
		for i := 0; i < p; i++ {
			ret[len(input)+i] = byte(p)
		}
		return ret
	} else {
		p := int(input[len(input)-1])
		return input[:len(input)-p]
	}
}

// sm4_setkey_enc 函数
func sm4_setkey_enc(sk []uint32, key []byte) {
	sm4_setkey(sk, key)
}

// sm4SetkeyDec 函数
func sm4SetkeyDec(sk []uint32, key []byte) {
	sm4_setkey(sk, key)
	for i := 0; i < 16; i++ {
		SWAP(sk, i)
	}
}

// sm4CryptCbc 函数
func sm4CryptCbc(sk []uint32, iv []byte, input []byte, mode int) ([]byte, error) {
	if len(iv) != 16 {
		return nil, fmt.Errorf("iv error")
	}
	if mode == SM4_ENCRYPT {
		input = padding(input, 1)
	}
	output := make([]byte, 0)
	temp := make([]byte, 16)
	for len(input) > 0 {
		in := input[:16]
		out := make([]byte, 16)
		out1 := make([]byte, 16)
		if mode == SM4_ENCRYPT {
			for i := 0; i < 16; i++ {
				out[i] = in[i] ^ iv[i]
			}
			sm4_one_round(sk, out, out1)
			copy(iv, out1)
		} else {
			copy(temp, in)
			sm4_one_round(sk, in, out)
			for i := 0; i < 16; i++ {
				out1[i] = out[i] ^ iv[i]
			}
			copy(iv, temp)
		}
		output = append(output, out1...)
		input = input[16:]
	}
	if mode == SM4_DECRYPT {
		output = padding(output, 0)
	}
	return output, nil
}

func Utf8ToGbk(str string) (string, error) {
	// 使用 GBK 编码器将 UTF-8 转换为 GBK
	encoder := simplifiedchinese.GBK.NewEncoder()
	gbkBytes, _, err := transform.String(encoder, str)
	if err != nil {
		return "", err
	}
	return string(gbkBytes), nil
}

func GbkToUtf8(str []byte) string {
	// 使用 GBK 编码器将 GBK 转换为 UTF-8
	decoder := simplifiedchinese.GBK.NewDecoder()
	utf8Bytes, _, err := transform.String(decoder, string(str))
	if err != nil {
		fmt.Println("转换失败:%s", str)
		return ""
	}
	return string(utf8Bytes)
}

// EncryptDataCBC 函数
func EncryptDataCBC(data string) (string, error) {
	data, err := Utf8ToGbk(data)
	if err != nil {
		fmt.Println("转换失败:%s", data)
		return "", err
	}

	sk := make([]uint32, 32)
	sm4_setkey_enc(sk, []byte(DEFAULT_SECRETKEY))
	encrypted, err := sm4CryptCbc(sk, []byte(DEFAULT_IV), []byte(data), SM4_ENCRYPT)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptDataCBC 函数
func DecryptDataCBC(cipherText string) (string, error) {

	decoded, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	sk := make([]uint32, 32)
	sm4SetkeyDec(sk, []byte(DEFAULT_SECRETKEY))
	decrypted, err := sm4CryptCbc(sk, []byte(DEFAULT_IV), decoded, SM4_DECRYPT)
	if err != nil {
		return "", err
	}
	return GbkToUtf8(decrypted), nil
}

// func main() {
// 	text := "你好"
// 	key := "AD42F6697B035B72"
// 	iv := "BD42F6697B035B72"

// 	encrypted, err := EncryptDataCBC(text, key, iv)
// 	if err != nil {
// 		fmt.Println("加密出错:", err)
// 		return
// 	}
// 	fmt.Println("原文: " + text)
// 	fmt.Println("加密: " + encrypted)

// 	decrypted, err := DecryptDataCBC(encrypted, key, iv)
// 	if err != nil {
// 		fmt.Println("解密出错:", err)
// 		return
// 	}
// 	fmt.Println("解密: " + decrypted)
// }
