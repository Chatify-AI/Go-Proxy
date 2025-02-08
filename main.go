package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 常量定义
const (
	DefaultTimeout = 300 * time.Second
	UserAgent      = "IPS/1.0"
	DefaultPort    = "2888"
)

// 全局变量
var (
	imageRecords    = make(map[string]time.Time)
	imageRecordsMux sync.Mutex
	localAPIURL     = "http://host.docker.internal:3000" // 默认使用 host.docker.internal
	imageCounter    uint64                               // 添加计数器

	// 图片记录优化
	imageTimeList = make([]*ImageRecord, 0, 1000) // 预分配容量
	imageListMux  sync.Mutex
)

// ImageRecord 图片记录结构
type ImageRecord struct {
	FileName   string
	CreateTime time.Time
}

func init() {
	// 如果环境变量中设置了 LOCAL_API_URL，则使用环境变量的值
	if url := os.Getenv("LOCAL_API_URL"); url != "" {
		localAPIURL = url
	}
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	TargetURL string
	RealKey   string
}

// AzureErrorResponse Azure 的错误响应结构
type AzureErrorResponse struct {
	Error struct {
		Code    string      `json:"code"`
		Message string      `json:"message"`
		Param   interface{} `json:"param,omitempty"`
		Type    interface{} `json:"type,omitempty"`
	} `json:"error"`
}

// ClaudeErrorResponse Claude 的错误响应结构
type ClaudeErrorResponse struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSONError(w http.ResponseWriter, statusCode int, errType string) {
	w.Header().Set("Content-Type", "application/json")

	switch errType {
	case "azure_auth":
		w.WriteHeader(401)
		resp := AzureErrorResponse{}
		resp.Error.Code = "401"
		resp.Error.Message = "Access denied due to invalid subscription key or wrong API endpoint. Make sure to provide a valid key for an active subscription and use a correct regional API endpoint for your resource."
		_ = json.NewEncoder(w).Encode(resp)

	case "azure_image":
		w.WriteHeader(400)
		resp := AzureErrorResponse{}
		resp.Error.Code = "BadRequest"
		resp.Error.Message = "Invalid image data."
		_ = json.NewEncoder(w).Encode(resp)

	case "claude_auth":
		w.WriteHeader(401)
		resp := ClaudeErrorResponse{
			Type: "error",
			Error: struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			}{
				Type:    "authentication_error",
				Message: "invalid x-api-key",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)

	case "claude_image":
		w.WriteHeader(400)
		resp := ClaudeErrorResponse{
			Type: "error",
			Error: struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			}{
				Type:    "bad_request",
				Message: "Invalid image format or content",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)

	case "claude_rate_limit":
		w.WriteHeader(429)
		resp := ClaudeErrorResponse{
			Type: "error",
			Error: struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			}{
				Type:    "rate_limit_error",
				Message: "Number of request tokens has exceeded your per-minute rate limit in cline when it has not been used for days.",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)

	default:
		w.WriteHeader(429)
		waitTime := rand.Intn(9) + 1
		resp := AzureErrorResponse{}
		resp.Error.Code = "429"
		resp.Error.Message = fmt.Sprintf("Requests to the ChatCompletions_Create Operation under Azure OpenAI API version 2024-12-01-preview have exceeded call rate limit of your current OpenAI S0 pricing tier. Please retry after %d seconds. Please go here: https://aka.ms/oai/quotaincrease if you would like to further increase the default rate limit.", waitTime)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func parseAuthHeader(authVal string) (config ProxyConfig, ok bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authVal, prefix) {
		return ProxyConfig{}, false
	}

	token := strings.TrimPrefix(authVal, prefix)
	return parseProxyToken(token)
}

func parseXAPIKey(keyVal string) (config ProxyConfig, ok bool) {
	return parseProxyToken(keyVal)
}

func parseProxyToken(token string) (config ProxyConfig, ok bool) {
	// 如果是标准的 sk- 格式，直接使用本地地址
	if strings.HasPrefix(token, "sk-") {
		return ProxyConfig{
			TargetURL: localAPIURL,
			RealKey:   token,
		}, true
	}

	// 否则尝试解析 URL-sk 格式
	if idx := strings.Index(token, "-sk"); idx != -1 {
		target := strings.TrimRight(token[:idx], "/")
		key := token[idx+1:]

		if !strings.HasPrefix(key, "sk-") {
			key = "sk-" + key
		}

		log.Printf("[INFO] Forward to: %s", target)
		return ProxyConfig{
			TargetURL: target,
			RealKey:   key,
		}, true
	}

	return ProxyConfig{}, false
}

func processImageFields(r io.Reader) ([]byte, error) {
	var reqData map[string]interface{}
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&reqData); err != nil {
		log.Printf("[ERROR] Failed to parse request body: %v", err)
		return nil, err
	}

	messages, ok := reqData["messages"].([]interface{})
	if !ok {
		return json.Marshal(reqData)
	}

	for _, m := range messages {
		msgMap, ok := m.(map[string]interface{})
		if !ok {
			continue
		}

		content, ok := msgMap["content"].([]interface{})
		if !ok {
			if _, ok := msgMap["content"].(string); ok {
				continue
			}
			continue
		}

		for _, c := range content {
			cMap, ok := c.(map[string]interface{})
			if !ok {
				continue
			}

			if t, _ := cMap["type"].(string); t == "image_url" {
				imageURLObj, ok := cMap["image_url"].(map[string]interface{})
				if !ok {
					continue
				}

				urlStr, ok := imageURLObj["url"].(string)
				if !ok {
					continue
				}

				// 如果已经是我们的图片服务 URL，不需要再处理
				if strings.Contains(urlStr, "/images/") {
					continue
				}

				var imgBytes []byte
				var err error

				if strings.HasPrefix(urlStr, "http") {
					log.Printf("[INFO] Processing image from URL")
					imgBytes, err = downloadImage(urlStr)
				} else if strings.HasPrefix(urlStr, "data:image") {
					log.Printf("[INFO] Processing base64 image")
					imgBytes, err = decodeBase64Image(urlStr)
				}

				if err != nil {
					log.Printf("[ERROR] Image processing failed: %v", err)
					continue
				}

				if newURL, err := saveImageLocally(imgBytes); err == nil {
					imageURLObj["url"] = newURL
				} else {
					log.Printf("[ERROR] Failed to save image: %v", err)
				}
			}
		}
	}

	// 确保请求体包含必要的字段
	if _, ok := reqData["model"]; !ok {
		reqData["model"] = "gpt-4-vision-preview"
	}
	if _, ok := reqData["max_tokens"]; !ok {
		reqData["max_tokens"] = 4096
	}

	return json.Marshal(reqData)
}

// 下载 HTTP 图片
func downloadImage(urlStr string) ([]byte, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download image: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("image download failed with status: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// 解码 base64 图片
func decodeBase64Image(dataURL string) ([]byte, error) {
	parts := strings.SplitN(dataURL, ",", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("格式错误")
	}

	return base64.StdEncoding.DecodeString(parts[1])
}

// 保存图片到本地
func saveImageLocally(data []byte) (string, error) {
	imagePath := os.Getenv("IMAGE_STORAGE_PATH")
	counter := atomic.AddUint64(&imageCounter, 1)
	fileName := fmt.Sprintf("img_%d_%d.jpg", time.Now().UnixNano(), counter)
	filePath := filepath.Join(imagePath, fileName)

	if err := os.WriteFile(filePath, data, 0666); err != nil {
		return "", fmt.Errorf("failed to write image file: %v", err)
	}

	now := time.Now()
	imageRecordsMux.Lock()
	imageRecords[fileName] = now
	imageRecordsMux.Unlock()

	imageListMux.Lock()
	imageTimeList = append(imageTimeList, &ImageRecord{
		FileName:   fileName,
		CreateTime: now,
	})
	imageListMux.Unlock()

	// 使用公网 IP 和端口生成 URL
	publicIP := os.Getenv("PUBLIC_IP")
	if publicIP == "" {
		log.Printf("[ERROR] PUBLIC_IP environment variable is not set")
		return "", fmt.Errorf("PUBLIC_IP environment variable is not set")
	}

	newURL := fmt.Sprintf("http://%s:%s/images/%s",
		publicIP,
		os.Getenv("SERVER_PORT"),
		fileName)

	log.Printf("[INFO] Image saved: %s", fileName)
	return newURL, nil
}

// 转发响应到客户端
func forwardResponse(w http.ResponseWriter, resp *http.Response) error {
	// 尝试获取 flusher，判断是否支持流式响应
	flusher, canFlush := w.(http.Flusher)

	// 复制响应头
	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	// 如果不支持流式响应，使用普通响应
	if !canFlush {
		w.WriteHeader(resp.StatusCode)
		_, err := io.Copy(w, resp.Body)
		return err
	}

	// 流式响应处理
	w.Header().Del("Content-Length") // 流式响应不需要 Content-Length
	w.WriteHeader(resp.StatusCode)
	flusher.Flush()

	reader := bufio.NewReader(resp.Body)
	buf := make([]byte, 4096)

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return fmt.Errorf("写入响应失败: %v", werr)
			}
			flusher.Flush()
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("读取响应失败: %v", err)
		}
	}
}

func handleAzureOpenAI(w http.ResponseWriter, r *http.Request) {
	handleProxyRequest(w, r, parseAuthHeader)
}

func handleClaude(w http.ResponseWriter, r *http.Request) {
	// 将 X-API-Key 转换为 Authorization Bearer 格式
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		r.Header.Set("Authorization", "Bearer "+apiKey)
	}
	handleProxyRequest(w, r, parseAuthHeader)
}

func handleProxyRequest(w http.ResponseWriter, r *http.Request, parseAuth func(string) (ProxyConfig, bool)) {
	log.Printf("[INFO] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	// 读取和处理请求体
	bodyData, err := readAndProcessRequestBody(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "azure_image")
		return
	}

	// 解析认证信息
	authValue := r.Header.Get("Authorization")
	if authValue == "" {
		authValue = r.Header.Get("X-API-Key")
	}

	config, ok := parseAuth(authValue)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "azure_auth")
		return
	}

	// 转发请求
	if err := forwardRequest(w, r, config, bodyData); err != nil {
		log.Printf("[ERROR] 转发请求失败: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "azure_image")
	}
}

func readAndProcessRequestBody(r *http.Request) ([]byte, error) {
	return processImageFields(r.Body)
}

func forwardRequest(w http.ResponseWriter, r *http.Request, config ProxyConfig, bodyData []byte) error {
	// 构建目标 URL
	finalURL := fmt.Sprintf("%s/v1/chat/completions", config.TargetURL)

	log.Printf("[INFO] Forwarding request to upstream")

	// 创建转发请求
	forwardReq, err := http.NewRequest(r.Method, finalURL, bytes.NewReader(bodyData))
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	forwardReq.Header = http.Header{}
	forwardReq.Header.Set("Authorization", "Bearer "+config.RealKey)
	forwardReq.Header.Set("Content-Type", "application/json")
	forwardReq.Header.Set("User-Agent", UserAgent)
	forwardReq.Header.Set("X-Proxy-Request", "true")

	// 发送请求
	client := &http.Client{Timeout: DefaultTimeout}
	resp, err := client.Do(forwardReq)
	if err != nil {
		return fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 处理非 200 状态码
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			writeJSONError(w, resp.StatusCode, "azure_auth")
		case http.StatusTooManyRequests:
			writeJSONError(w, resp.StatusCode, "") // 使用默认的 429 错误
		default:
			writeJSONError(w, resp.StatusCode, "azure_image")
		}
		return nil
	}

	return forwardResponse(w, resp)
}

func cleanupImages() {
	for {
		time.Sleep(1 * time.Minute)
		now := time.Now()
		threshold := now.Add(-5 * time.Minute)

		imageListMux.Lock()
		// 找到第一个不需要删除的索引
		cutIndex := 0
		for i, record := range imageTimeList {
			if record.CreateTime.After(threshold) {
				cutIndex = i
				break
			}

			// 删除文件
			imagePath := os.Getenv("IMAGE_STORAGE_PATH")
			if imagePath == "" {
				imagePath = filepath.Join("/data", "images")
			}
			path := filepath.Join(imagePath, record.FileName)

			imageRecordsMux.Lock()
			delete(imageRecords, record.FileName)
			imageRecordsMux.Unlock()

			if err := os.Remove(path); err == nil {
				log.Printf("[INFO] Cleaned: %s", record.FileName)
			}
		}

		// 移除已处理的记录
		if cutIndex > 0 {
			imageTimeList = imageTimeList[cutIndex:]
		}
		imageListMux.Unlock()
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", handleAzureOpenAI)
	mux.HandleFunc("/v1/messages", handleClaude)

	// 设置静态文件服务
	imagePath := os.Getenv("IMAGE_STORAGE_PATH")
	fs := http.FileServer(http.Dir(imagePath))
	mux.Handle("/images/", http.StripPrefix("/images/", fs))

	// 启动清理任务
	go cleanupImages()

	// 启动服务器
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = DefaultPort
	}
	addr := ":" + port
	log.Printf("[INFO] Server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[FATAL] Server failed: %v", err)
	}
}
