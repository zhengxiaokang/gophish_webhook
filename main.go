package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	serverPath = kingpin.Flag("path", "Webhook server path").Default("/webhook").Short('u').String()
	serverPort = kingpin.Flag("port", "Webhook server port").Default("9999").Short('p').String()
	serverIP   = kingpin.Flag("server", "Server address").Default("127.0.0.1").Short('h').IP()
	secret     = kingpin.Flag("secret", "Webhook secret").Short('s').String()

	errNoSignature      = errors.New("No X-Gophish-Signature header provided")
	errInvalidSignature = errors.New("Invalid signature provided")
)

func getOpenAccessToken() (string, int64) {
	// 定义接口调用ID和密钥
	const appId = "xxx"
	const appSecret = "xxxx"

	// 构建请求参数
	payload := map[string]string{
		"appId":     appId,
		"appSecret": appSecret,
	}

	// 将参数转换为JSON格式
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Errorf("Failed to marshal JSON payload: %v", err)
		return "", 0
	}

	// 创建HTTP POST请求
	req, err1 := http.NewRequest("POST", "https://open.popo.netease.com/open-apis/token", bytes.NewBuffer(jsonPayload))
	if err1 != nil {
		log.Errorf("Failed to create HTTP request: %v", err1)
		return "", 0
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	client := &http.Client{}
	var flag = true
	var resp *http.Response
	for flag {
		res, err2 := client.Do(req)
		resp = res
		if err2 != nil {
			log.Errorf("Failed to send HTTP request: %v", err2)
			time.Sleep(3 * time.Second)
		} else {
			flag = false
		}
	}

	// 读取响应内容
	body, err3 := io.ReadAll(resp.Body)
	if err3 != nil {
		log.Errorf("Failed to read response body: %v", err3)
		return "", 0
	}
	if resp != nil {
		defer resp.Body.Close()
	}

	// 定义结构体来存储解析后的 JSON 数据
	type ResponseData struct {
		Data struct {
			OpenAccessToken string `json:"openAccessToken"`
			AccessExpiredAt int64  `json:"accessExpiredAt"`
		} `json:"data"`
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
		TraceId string `json:"traceid"`
	}

	var responseData ResponseData
	err4 := json.Unmarshal(body, &responseData)
	if err4 != nil {
		log.Errorf("Failed to unmarshal JSON response: %v", err4)
		return "", 0
	}

	// 检查 errcode 是否为 0
	if responseData.ErrCode != 0 {
		log.Errorf("Request failed with error code: %d, error message: %s", responseData.ErrCode, responseData.ErrMsg)
		return "", 0
	}

	// 获取 openAccessToken
	openAccessToken := responseData.Data.OpenAccessToken
	accessExpiredAt := responseData.Data.AccessExpiredAt
	return openAccessToken, accessExpiredAt
}

func sendPOPO(openAccessToken *string, accessExpiredAt *int64, receiver string) {
	// 将 accessExpiredAt 从毫秒转换为秒
	expirationTime := time.Unix(*accessExpiredAt/1000, 0)
	// 获取当前时间
	now := time.Now()
	// 计算时间间隔
	duration := expirationTime.Sub(now)

	// 检查时间间隔是否小于等于 5 分钟
	if duration <= 5*time.Minute {
		*openAccessToken, *accessExpiredAt = getOpenAccessToken()
	}

	// 构建请求参数
	payload := map[string]string{
		"sender":   "grp.nis@corp.netease.com",
		"receiver": receiver,
		"message": `【安全提醒】钓鱼邮件中招提醒
		
您好，由于您在本次钓鱼邮件演练中，打开邮件中的钓鱼网站并提交了账号密码，遂触发此提醒。请放心，本次演练不会记录您的密码，不过在真实钓鱼攻击中，您的账号密码已经泄露。
为了提高您的安全意识，请点击：https://salon.netease.com/app/course-detail?id=3005914&type=media 观看线上安全意识培训视频，并完成试题。

如有任何疑问，请联系安全中心 POPO服务号：网易安全`,
	}

	// 将参数转换为JSON格式
	jsonPayload, err := json.Marshal(payload)
	// 后续代码中避免重复声明 err
	if err != nil {
		log.Errorf("Failed to marshal JSON payload: %v", err)
		return
	}

	// 创建HTTP POST请求
	req, err1 := http.NewRequest("POST", "https://open.popo.netease.com/open-apis/robot/v1/p2p", bytes.NewBuffer(jsonPayload))
	if err1 != nil {
		log.Errorf("Failed to create HTTP request: %v", err1)
		return
	}

	// 添加自定义请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Open-Access-Token", *openAccessToken)

	// 发送请求
	client := &http.Client{}
	var flag = true
	var resp *http.Response
	for flag {
		res, err2 := client.Do(req)
		resp = res
		if err2 != nil {
			log.Errorf("Failed to send HTTP request: %v", err2)
			time.Sleep(3 * time.Second)
		} else {
			flag = false
		}
	}
	if resp != nil {
		defer resp.Body.Close()
	}
}

func webhookHandler(w http.ResponseWriter, r *http.Request, openAccessToken *string, accessExpiredAt *int64) {
	if r.URL.Path != *serverPath {
		http.NotFound(w, r)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the provided signature
	defer r.Body.Close()

	// Get the provided signature
	signatureHeader := r.Header.Get("X-Gophish-Signature")
	if signatureHeader == "" {
		log.Errorf("no signature provided in ruest from %s", r.RemoteAddr)
		http.Error(w, errNoSignature.Error(), http.StatusBadRequest)
		return
	}

	signatureParts := strings.SplitN(signatureHeader, "=", 2)
	if len(signatureParts) != 2 {
		log.Errorf("invalid signature: %s", signatureHeader)
		http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
		return
	}
	signature := signatureParts[1]

	gotHash, err := hex.DecodeString(signature)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	// Copy out the ruest body so we can validate the signature
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Validate the signature
	expectedMAC := hmac.New(sha256.New, []byte(*secret))
	expectedMAC.Write(body)
	expectedHash := expectedMAC.Sum(nil)

	if !hmac.Equal(gotHash, expectedHash) {
		log.Errorf("invalid signature provided. expected %s got %s", hex.EncodeToString(expectedHash), signature)
		http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
		return
	}

	// Print the request header information(taken from net/http/httputil.DumpRequest)
	buf := &bytes.Buffer{}
	rURI := r.RequestURI
	if rURI == "" {
		rURI = r.URL.RequestURI()
	}

	fmt.Fprintf(buf, "%s %s HTTP/%d.%d\r\n", r.Method,
		rURI, r.ProtoMajor, r.ProtoMinor)

	absRequestURI := strings.HasPrefix(r.RequestURI, "http://") || strings.HasPrefix(r.RequestURI, "https://")
	if !absRequestURI {
		host := r.Host
		if host == "" && r.URL != nil {
			host = r.URL.Host
		}
		if host != "" {
			fmt.Fprintf(buf, "Host: %s\r\n", host)
		}
	}

	// Print out the payload
	r.Header.Write(buf)
	err = json.Indent(buf, body, "", "    ")
	if err != nil {
		log.Error("error indenting json body: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	buf.WriteTo(os.Stdout)
	fmt.Print("\n")

	w.WriteHeader(http.StatusNoContent)

	// 定义一个结构体来存储解析后的JSON数据
	type RequestData struct {
		Email   string `json:"email"`
		Time    string `json:"time"`
		Message string `json:"message"`
		Details string `json:"details"`
	}

	var requestData RequestData
	// 解析JSON数据
	err = json.Unmarshal(body, &requestData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 获取email字段的值
	email := requestData.Email
	message := requestData.Message

	if message == "Submitted Data" {
		sendPOPO(openAccessToken, accessExpiredAt, email)
	}
}

func main() {
	kingpin.Parse()
	addr := net.JoinHostPort(serverIP.String(), *serverPort)
	log.Infof("Webhook server started at %s%s", addr, *serverPath)
	openAccessToken, accessExpiredAt := getOpenAccessToken()
	//http.ListenAndServe(addr, http.HandlerFunc(webhookHandler))
	// 使用闭包将 openAccessToken 和 accessExpiredAt 传入 webhookHandler
	http.HandleFunc(*serverPath, func(w http.ResponseWriter, r *http.Request) {
		webhookHandler(w, r, &openAccessToken, &accessExpiredAt)
	})

	log.Fatal(http.ListenAndServe(addr, nil))
}
