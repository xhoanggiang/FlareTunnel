package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/olekukonko/tablewriter"
)

// ====================================================================
// CONSTANTS & TYPES
// ====================================================================

const (
	Version           = "1.0.0"
	CloudflareBaseURL = "https://api.cloudflare.com/client/v4"
	WorkerScript      = `/**
 * FlareTunnel - Cloudflare Worker URL Redirection Script (ES Modules)
 */
export default {
  async fetch(request) {
    try {
      const url = new URL(request.url)
      const targetUrl = getTargetUrl(url, request.headers)

      if (!targetUrl) {
        return createErrorResponse('No target URL specified', {
          usage: {
            query_param: '?url=https://example.com',
            header: 'X-Target-URL: https://example.com',
            path: '/https://example.com'
          }
        }, 400)
      }

      let targetURL
      try {
        targetURL = new URL(targetUrl)
      } catch (e) {
        return createErrorResponse('Invalid target URL', { provided: targetUrl }, 400)
      }

      // Build target URL with filtered query parameters
      const targetParams = new URLSearchParams()
      for (const [key, value] of url.searchParams) {
        if (!['url', '_cb', '_t'].includes(key)) {
          targetParams.append(key, value)
        }
      }
      if (targetParams.toString()) {
        targetURL.search = targetParams.toString()
      }

      // Create proxied request
      const { req: proxyRequest, droppedHeaders } = createProxyRequest(request, targetURL)
      const response = await fetch(proxyRequest)

      // Process and return response
      return createProxyResponse(response, request.method, droppedHeaders)

    } catch (error) {
      return createErrorResponse('Proxy request failed', {
        message: error.message,
        timestamp: new Date().toISOString()
      }, 500)
    }
  }
}

function getTargetUrl(url, headers) {
  // Priority: query param > header > path
  let targetUrl = url.searchParams.get('url')

  if (!targetUrl) {
    targetUrl = headers.get('X-Target-URL')
  }

  if (!targetUrl && url.pathname !== '/') {
    const pathUrl = url.pathname.slice(1)
    if (pathUrl.startsWith('http')) {
      targetUrl = pathUrl
    }
  }

  return targetUrl
}

function createProxyRequest(request, targetURL) {
  const proxyHeaders = new Headers()
  const allowedHeaders = [
    'accept', 'accept-language', 'accept-encoding', 'authorization',
    'cache-control', 'content-type', 'content-length', 'cookie',
    'origin', 'referer', 'user-agent', 'if-none-match', 'if-modified-since',
    'range', 'pragma', 'x-requested-with', 'chatgpt-account-id'
  ]
  const ignoredHeaders = [
    'host', 'connection', 'cf-connecting-ip', 'cf-ipcountry', 'cf-ray',
    'cf-visitor', 'cf-worker', 'x-forwarded-proto', 'x-forwarded-for',
    'x-real-ip', 'true-client-ip', 'cdn-loop', 'x-my-x-forwarded-for'
  ]

  const droppedHeaders = []

  for (const [key, value] of request.headers) {
    const k = key.toLowerCase()
    if (allowedHeaders.includes(k)) {
      proxyHeaders.set(key, value)
    } else if (!ignoredHeaders.includes(k)) {
      droppedHeaders.push(k)
    }
  }

  proxyHeaders.set('Host', targetURL.hostname)

  // Set X-Forwarded-For header
  const customXForwardedFor = request.headers.get('X-My-X-Forwarded-For')
  if (customXForwardedFor) {
    proxyHeaders.set('X-Forwarded-For', customXForwardedFor)
  } else {
    proxyHeaders.set('X-Forwarded-For', generateRandomIP())
  }

  return {
    req: new Request(targetURL.toString(), {
      method: request.method,
      headers: proxyHeaders,
      body: ['GET', 'HEAD'].includes(request.method) ? null : request.body
    }),
    droppedHeaders
  }
}

function createProxyResponse(response, requestMethod, droppedHeaders) {
  const responseHeaders = new Headers()

  // Copy ALL response headers (let browser handle encoding)
  for (const [key, value] of response.headers) {
    responseHeaders.set(key, value)
  }

  // Report dropped headers back to the local proxy
  if (droppedHeaders && droppedHeaders.length > 0) {
    responseHeaders.set('X-Dropped-Headers', droppedHeaders.join(', '))
  }

  // Add/Override CORS headers
  responseHeaders.set('Access-Control-Allow-Origin', '*')
  responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD')
  responseHeaders.set('Access-Control-Allow-Headers', '*')

  if (requestMethod === 'OPTIONS') {
    return new Response(null, { status: 204, headers: responseHeaders })
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders
  })
}

function createErrorResponse(error, details, status) {
  return new Response(JSON.stringify({ error, ...details }), {
    status,
    headers: { 'Content-Type': 'application/json' }
  })
}

function generateRandomIP() {
  return [1, 2, 3, 4].map(() => Math.floor(Math.random() * 255) + 1).join('.')
}`
)

// Account represents a Cloudflare account configuration
type Account struct {
	Name      string `json:"name"`
	APIToken  string `json:"api_token"`
	AccountID string `json:"account_id"`
	ZoneID    string `json:"zone_id,omitempty"`
	Subdomain string `json:"subdomain,omitempty"`
}

// Config represents the FlareTunnel configuration
type Config struct {
	Accounts []Account `json:"accounts"`
}

// Worker represents a Cloudflare Worker deployment
type Worker struct {
	Name              string `json:"name"`
	URL               string `json:"url"`
	CreatedAt         string `json:"created_at"`
	ID                string `json:"id"`
	AccountID         string `json:"account_id"`
	ConfigAccountName string `json:"config_account_name,omitempty"`
}

// Analytics represents worker analytics data
type Analytics struct {
	Success       bool           `json:"success"`
	TotalRequests int            `json:"total_requests"`
	PerWorker     map[string]int `json:"per_worker"`
	Limit         int            `json:"limit"`
	Error         string         `json:"error,omitempty"`
}

// ====================================================================
// CLOUDFLARE API CLIENT
// ====================================================================

type CloudflareClient struct {
	APIToken  string
	AccountID string
	BaseURL   string
	Headers   map[string]string
	subdomain string
}

func NewCloudflareClient(apiToken, accountID, subdomain string) *CloudflareClient {
	return &CloudflareClient{
		APIToken:  apiToken,
		AccountID: accountID,
		BaseURL:   CloudflareBaseURL,
		Headers: map[string]string{
			"Authorization": "Bearer " + apiToken,
			"Content-Type":  "application/json",
		},
		subdomain: subdomain,
	}
}

func (c *CloudflareClient) GetSubdomain() (string, error) {
	if c.subdomain != "" {
		return c.subdomain, nil
	}

	subdomain, err := c.FetchSubdomain()
	if err != nil {
		fmt.Printf("⚠️  [GetSubdomain] Warning: Failed to retrieve subdomain from API: %v\n", err)
		fmt.Println("👉 To fix this, either give your API Token 'Account - Cloudflare Workers: Read' permission, or manually add '\"subdomain\": \"your-subdomain\"' for this account in flaretunnel.json")
		c.subdomain = strings.ToLower(c.AccountID)
		return c.subdomain, nil
	}

	c.subdomain = subdomain
	return c.subdomain, nil
}

func (c *CloudflareClient) FetchSubdomain() (string, error) {
	url := fmt.Sprintf("%s/accounts/%s/workers/subdomain", c.BaseURL, c.AccountID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result struct {
		Result struct {
			Subdomain string `json:"subdomain"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Result.Subdomain == "" {
		return "", fmt.Errorf("empty subdomain in API response")
	}
	return result.Result.Subdomain, nil
}

func (c *CloudflareClient) CreateWorker(name string) (*Worker, error) {
	if name == "" {
		name = generateWorkerName()
	}

	url := fmt.Sprintf("%s/accounts/%s/workers/scripts/%s", c.BaseURL, c.AccountID, name)

	var b bytes.Buffer
	writer := multipartWriter(&b)
	
	metadata := map[string]string{
		"body_part":   "script",
		"main_module": "worker.js",
	}
	metadataJSON, _ := json.Marshal(metadata)
	
	writer.WriteField("metadata", string(metadataJSON))
	writer.WriteField("script", WorkerScript)
	contentType := writer.FormDataContentType()
	writer.Close()

	req, err := http.NewRequest("PUT", url, &b)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Content-Type", contentType)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create worker: %s", string(body))
	}

	// Enable subdomain
	subdomain, _ := c.GetSubdomain()
	subdomainURL := fmt.Sprintf("%s/accounts/%s/workers/scripts/%s/subdomain", c.BaseURL, c.AccountID, name)
	subdomainBody := bytes.NewBufferString(`{"enabled":true}`)
	subdomainReq, _ := http.NewRequest("POST", subdomainURL, subdomainBody)
	for k, v := range c.Headers {
		subdomainReq.Header.Set(k, v)
	}
	client.Do(subdomainReq)

	workerURL := fmt.Sprintf("https://%s.%s.workers.dev", name, subdomain)

	return &Worker{
		Name:      name,
		URL:       workerURL,
		CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
		ID:        name,
		AccountID: c.AccountID,
	}, nil
}

func (c *CloudflareClient) ListWorkers() ([]*Worker, error) {
	url := fmt.Sprintf("%s/accounts/%s/workers/scripts", c.BaseURL, c.AccountID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Result []struct {
			ID        string `json:"id"`
			CreatedOn string `json:"created_on"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	subdomain, _ := c.GetSubdomain()
	workers := []*Worker{}

	for _, script := range result.Result {
		if strings.HasPrefix(script.ID, "flaretunnel-") {
			workers = append(workers, &Worker{
				Name:      script.ID,
				URL:       fmt.Sprintf("https://%s.%s.workers.dev", script.ID, subdomain),
				CreatedAt: script.CreatedOn,
				AccountID: c.AccountID,
			})
		}
	}

	return workers, nil
}

func (c *CloudflareClient) DeleteWorker(name string) error {
	url := fmt.Sprintf("%s/accounts/%s/workers/scripts/%s", c.BaseURL, c.AccountID, name)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}

	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 404 {
		return fmt.Errorf("failed to delete worker: status %d", resp.StatusCode)
	}

	return nil
}

func (c *CloudflareClient) GetAnalytics() (*Analytics, error) {
	graphqlURL := "https://api.cloudflare.com/client/v4/graphql"

	now := time.Now()
	dateStart := now.Add(-24 * time.Hour).Format("2006-01-02T15:04:05Z")
	dateEnd := now.Format("2006-01-02T15:04:05Z")

	query := `
		query WorkersAnalytics($accountTag: string!, $datetimeStart: string!, $datetimeEnd: string!) {
			viewer {
				accounts(filter: {accountTag: $accountTag}) {
					workersInvocationsAdaptive(
						limit: 10000
						filter: {
							datetime_geq: $datetimeStart
							datetime_leq: $datetimeEnd
						}
						orderBy: [sum_requests_DESC]
					) {
						dimensions {
							scriptName
						}
						sum {
							requests
							errors
							subrequests
						}
					}
				}
			}
		}
	`

	variables := map[string]interface{}{
		"accountTag":     c.AccountID,
		"datetimeStart":  dateStart,
		"datetimeEnd":    dateEnd,
	}

	payload := map[string]interface{}{
		"query":     query,
		"variables": variables,
	}

	payloadBytes, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", graphqlURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return &Analytics{Success: false, Limit: 100000, PerWorker: make(map[string]int)}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return &Analytics{Success: false, Limit: 100000, PerWorker: make(map[string]int)}, nil
	}

	var result struct {
		Data struct {
			Viewer struct {
				Accounts []struct {
					WorkersInvocationsAdaptive []struct {
						Dimensions struct {
							ScriptName string `json:"scriptName"`
						} `json:"dimensions"`
						Sum struct {
							Requests int `json:"requests"`
						} `json:"sum"`
					} `json:"workersInvocationsAdaptive"`
				} `json:"accounts"`
			} `json:"viewer"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return &Analytics{Success: false, Limit: 100000, PerWorker: make(map[string]int)}, nil
	}

	analytics := &Analytics{
		Success:   true,
		Limit:     100000,
		PerWorker: make(map[string]int),
	}

	if len(result.Data.Viewer.Accounts) > 0 {
		for _, inv := range result.Data.Viewer.Accounts[0].WorkersInvocationsAdaptive {
			scriptName := inv.Dimensions.ScriptName
			requests := inv.Sum.Requests
			analytics.PerWorker[scriptName] = requests
			analytics.TotalRequests += requests
		}
	}

	return analytics, nil
}

// ====================================================================
// SSL CERTIFICATE GENERATION
// ====================================================================

func generateCACert(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return nil
		}
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(3650 * 24 * time.Hour)

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Local"},
			Organization: []string{"FlareTunnel"},
			CommonName:   "FlareTunnel CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	fmt.Printf("✓ Generated CA certificate: %s\n", certPath)
	return nil
}

func generateHostCert(hostname, caCertPath, caKeyPath string) (*tls.Certificate, error) {
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Local"},
			Organization: []string{"FlareTunnel"},
			CommonName:   hostname,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname, "*." + hostname},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

// ====================================================================
// FLARETUNNEL MANAGER
// ====================================================================

type FlareTunnel struct {
	Config          *Config
	Clients         map[string]*CloudflareClient
	EndpointsFile   string
	ConfigFile      string
	workers         []*Worker
	workersMutex    sync.RWMutex
}

func NewFlareTunnel(configFile string) (*FlareTunnel, error) {
	if configFile == "" {
		configFile = "flaretunnel.json"
	}

	config, err := loadConfig(configFile)
	if err != nil {
		return nil, err
	}

	ft := &FlareTunnel{
		Config:        config,
		Clients:       make(map[string]*CloudflareClient),
		EndpointsFile: "flaretunnel_endpoints.json",
		ConfigFile:    configFile,
	}

	for _, account := range config.Accounts {
		ft.Clients[account.Name] = NewCloudflareClient(account.APIToken, account.AccountID, account.Subdomain)
	}

	return ft, nil
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Remove BOM if present (UTF-8-sig compatibility)
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func (ft *FlareTunnel) SaveEndpoints(workers []*Worker) error {
	data, err := json.MarshalIndent(workers, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ft.EndpointsFile, data, 0644)
}

func (ft *FlareTunnel) LoadEndpoints() ([]*Worker, error) {
	data, err := os.ReadFile(ft.EndpointsFile)
	if err != nil {
		return nil, err
	}

	// Remove BOM if present
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}

	var workers []*Worker
	if err := json.Unmarshal(data, &workers); err != nil {
		return nil, err
	}

	return workers, nil
}

func (ft *FlareTunnel) SyncEndpoints() ([]*Worker, error) {
	allWorkers := []*Worker{}

	for accountName, client := range ft.Clients {
		workers, err := client.ListWorkers()
		if err != nil {
			continue
		}

		for _, w := range workers {
			w.ConfigAccountName = accountName
			allWorkers = append(allWorkers, w)
		}
	}

	if len(allWorkers) > 0 {
		ft.SaveEndpoints(allWorkers)
	}

	return allWorkers, nil
}

func (ft *FlareTunnel) CreateWorkers(count int, accountName string, distribute bool) error {
	fmt.Printf("\nCreating %d FlareTunnel endpoint(s)...\n", count)

	created := []*Worker{}

	if accountName != "" {
		// Single account
		client, ok := ft.Clients[accountName]
		if !ok {
			return fmt.Errorf("account '%s' not found", accountName)
		}

		fmt.Printf("   Using account: %s\n", accountName)

		for i := 0; i < count; i++ {
			worker, err := client.CreateWorker("")
			if err != nil {
				fmt.Printf("  [%d/%d] Failed: %v\n", i+1, count, err)
				continue
			}
			worker.ConfigAccountName = accountName
			created = append(created, worker)
			fmt.Printf("  [%d/%d] %s -> %s\n", i+1, count, worker.Name, worker.URL)
		}
	} else if distribute && len(ft.Clients) > 1 {
		// Distribute across accounts
		fmt.Printf("   Distribution mode: Checking quotas across %d account(s)...\n", len(ft.Clients))

		accountQuotas := make(map[string]int)
		for name, client := range ft.Clients {
			analytics, _ := client.GetAnalytics()
			remaining := 100000 - analytics.TotalRequests
			accountQuotas[name] = remaining
			fmt.Printf("      %s: %d requests remaining\n", name, remaining)
		}

		totalQuota := 0
		for _, quota := range accountQuotas {
			totalQuota += quota
		}

		if totalQuota == 0 {
			totalQuota = len(ft.Clients)
			for name := range accountQuotas {
				accountQuotas[name] = 1
			}
		}

		workersPerAccount := make(map[string]int)
		for name, quota := range accountQuotas {
			proportion := float64(quota) / float64(totalQuota)
			workersPerAccount[name] = max(1, int(float64(count)*proportion))
		}

		// Adjust to exact count
		for sum := sumMap(workersPerAccount); sum < count; sum = sumMap(workersPerAccount) {
			maxAccount := ""
			maxQuota := 0
			for name, quota := range accountQuotas {
				if quota > maxQuota {
					maxQuota = quota
					maxAccount = name
				}
			}
			workersPerAccount[maxAccount]++
		}

		fmt.Printf("\n   Distribution plan:\n")
		for name, wc := range workersPerAccount {
			fmt.Printf("      %s: %d worker(s)\n", name, wc)
		}
		fmt.Println()

		createdCount := 0
		for name, wc := range workersPerAccount {
			client := ft.Clients[name]
			for i := 0; i < wc; i++ {
				worker, err := client.CreateWorker("")
				if err != nil {
					fmt.Printf("  [%d/%d] [%s] Failed: %v\n", createdCount+1, count, name, err)
					continue
				}
				worker.ConfigAccountName = name
				created = append(created, worker)
				createdCount++
				fmt.Printf("  [%d/%d] [%s] %s -> %s\n", createdCount, count, name, worker.Name, worker.URL)
			}
		}
	} else {
		// Default to first account
		var firstClient *CloudflareClient
		var firstName string
		for name, client := range ft.Clients {
			firstClient = client
			firstName = name
			break
		}

		fmt.Printf("   Using account: %s\n", firstName)

		for i := 0; i < count; i++ {
			worker, err := firstClient.CreateWorker("")
			if err != nil {
				fmt.Printf("  [%d/%d] Failed: %v\n", i+1, count, err)
				continue
			}
			worker.ConfigAccountName = firstName
			created = append(created, worker)
			fmt.Printf("  [%d/%d] %s -> %s\n", i+1, count, worker.Name, worker.URL)
		}
	}

	ft.SyncEndpoints()
	fmt.Printf("\nCreated: %d, Failed: %d\n", len(created), count-len(created))

	return nil
}

func (ft *FlareTunnel) ListWorkers(verbose, checkStatus bool) error {
	workers, err := ft.SyncEndpoints()
	if err != nil || len(workers) == 0 {
		fmt.Println("❌ No FlareTunnel endpoints found")
		fmt.Println("💡 Create some with: go run FlareTunnel.go create --count 5")
		return nil
	}

	// Verbose mode: check status as well
	if verbose {
		checkStatus = true // Force status check in verbose mode!
	}

	// Get analytics for all accounts
	allAnalytics := make(map[string]*Analytics)
	for accountName, client := range ft.Clients {
		analytics, _ := client.GetAnalytics()
		allAnalytics[accountName] = analytics
	}

	if checkStatus {
		fmt.Printf("\n🔍 Checking status of %d worker(s)...\n", len(workers))
		fmt.Println("This may take a few seconds...\n")
	}

	fmt.Println()
	table := tablewriter.NewWriter(os.Stdout)
	
	// Build header based on flags
	header := []string{"#", "Account", "Name"}
	if verbose {
		header = append(header, "Created", "Age")
	}
	header = append(header, "URL", "Requests")
	if checkStatus {
		header = append(header, "Status (ms)")
	} else {
		header = append(header, "Status")
	}
	table.SetHeader(header)
	table.SetBorder(true)

	for idx, worker := range workers {
		row := []string{strconv.Itoa(idx), worker.ConfigAccountName, worker.Name}
		
		// Add verbose info (Created, Age)
		if verbose {
			createdStr := "Unknown"
			ageStr := "Unknown"
			
			// Extract timestamp from worker name: flaretunnel-1764721536-kmoiok
			re := regexp.MustCompile(`flaretunnel-(\d+)-`)
			if matches := re.FindStringSubmatch(worker.Name); len(matches) > 1 {
				if timestamp, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
					createdTime := time.Unix(timestamp, 0)
					createdStr = createdTime.Format("2006-01-02 15:04:05")
					
					// Calculate age
					age := time.Since(createdTime)
					if age.Hours() < 1 {
						ageStr = fmt.Sprintf("%dm ago", int(age.Minutes()))
					} else if age.Hours() < 24 {
						ageStr = fmt.Sprintf("%dh ago", int(age.Hours()))
					} else {
						ageStr = fmt.Sprintf("%dd ago", int(age.Hours()/24))
					}
				}
			}
			
			row = append(row, createdStr, ageStr)
		}
		
		// Add URL
		row = append(row, worker.URL)
		
		// Add requests count
		requests := "0"
		if analytics, ok := allAnalytics[worker.ConfigAccountName]; ok && analytics.Success {
			if req, ok := analytics.PerWorker[worker.Name]; ok {
				requests = strconv.Itoa(req)
			}
		}
		row = append(row, requests)
		
		// Add status
		if checkStatus {
			// Test actual worker
			testURL := worker.URL + "?url=" + url.QueryEscape("https://httpbin.org/status/200")
			start := time.Now()
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Get(testURL)
			elapsed := time.Since(start)
			
			if err != nil {
				row = append(row, "❌ Failed")
			} else {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					row = append(row, fmt.Sprintf("✅ %dms", elapsed.Milliseconds()))
				} else {
					row = append(row, fmt.Sprintf("⚠️ %d", resp.StatusCode))
				}
			}
		} else {
			row = append(row, "✅ Active")
		}
		
		table.Append(row)
	}

	table.Render()

	fmt.Println("\n💡 Use worker index with: go run FlareTunnel.go tunnel --workers 0,1,2 --verbose")
	fmt.Println()

	return nil
}

func (ft *FlareTunnel) CleanupWorkers(accountName string) error {
	if accountName != "" {
		client, ok := ft.Clients[accountName]
		if !ok {
			return fmt.Errorf("account '%s' not found", accountName)
		}

		fmt.Printf("\n🗑️  Cleaning up account: %s\n", accountName)
		workers, _ := client.ListWorkers()

		for _, worker := range workers {
			if err := client.DeleteWorker(worker.Name); err != nil {
				fmt.Printf("   ✗ Failed to delete: %s\n", worker.Name)
			} else {
				fmt.Printf("   ✓ Deleted: %s\n", worker.Name)
			}
		}
	} else {
		fmt.Printf("\n🗑️  Cleaning up ALL accounts (%d total)\n", len(ft.Clients))

		for name, client := range ft.Clients {
			fmt.Printf("   Account: %s\n", name)
			workers, _ := client.ListWorkers()

			for _, worker := range workers {
				if err := client.DeleteWorker(worker.Name); err != nil {
					fmt.Printf("   ✗ Failed to delete: %s\n", worker.Name)
				} else {
					fmt.Printf("   ✓ Deleted: %s\n", worker.Name)
				}
			}
		}

		os.Remove(ft.EndpointsFile)
	}

	return nil
}

func (ft *FlareTunnel) TestWorkers(targetURL, method string) error {
	workers, err := ft.LoadEndpoints()
	if err != nil || len(workers) == 0 {
		fmt.Println("❌ No workers available")
		return fmt.Errorf("no workers found")
	}

	fmt.Printf("\nTesting %d FlareTunnel endpoint(s) with %s\n", len(workers), targetURL)

	successCount := 0
	uniqueIPs := make(map[string]bool)

	for _, worker := range workers {
		fmt.Printf("\nTesting endpoint: %s\n", worker.Name)

		testURL := worker.URL + "?url=" + url.QueryEscape(targetURL)
		
		client := &http.Client{Timeout: 30 * time.Second}
		req, err := http.NewRequest(method, testURL, nil)
		if err != nil {
			fmt.Printf("   ✗ Request failed: %v\n", err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("   ✗ Request failed: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			successCount++
			fmt.Printf("   ✓ Request successful! Status: %d\n", resp.StatusCode)

			body, _ := io.ReadAll(resp.Body)
			bodyStr := strings.TrimSpace(string(body))

			// Try to extract IP from common formats
			if strings.Contains(targetURL, "ifconfig.me") {
				fmt.Printf("   Origin IP: %s\n", bodyStr)
				uniqueIPs[bodyStr] = true
			} else if strings.Contains(targetURL, "httpbin.org/ip") {
				var data map[string]interface{}
				if json.Unmarshal(body, &data) == nil {
					if origin, ok := data["origin"].(string); ok {
						fmt.Printf("   Origin IP: %s\n", origin)
						uniqueIPs[origin] = true
					}
				}
			} else {
				fmt.Printf("   Response Length: %d bytes\n", len(body))
			}
		} else {
			fmt.Printf("   ✗ Request failed! Status: %d\n", resp.StatusCode)
		}
	}

	fmt.Printf("\nTest Results:\n")
	fmt.Printf("   Working endpoints: %d/%d\n", successCount, len(workers))
	if len(uniqueIPs) > 0 {
		fmt.Printf("   Unique IP addresses: %d\n", len(uniqueIPs))
		for ip := range uniqueIPs {
			fmt.Printf("      - %s\n", ip)
		}
	}

	return nil
}

func (ft *FlareTunnel) ExportConfig(outputFile string) error {
	if _, err := os.Stat("flaretunnel.json"); os.IsNotExist(err) {
		fmt.Println("❌ No configuration file found (flaretunnel.json)")
		return err
	}

	configData, err := os.ReadFile("flaretunnel.json")
	if err != nil {
		fmt.Printf("❌ Failed to read configuration: %v\n", err)
		return err
	}

	exportData := map[string]interface{}{
		"exported_at": time.Now().Format(time.RFC3339),
		"config":      json.RawMessage(configData),
	}

	data, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		fmt.Printf("❌ Failed to write export file: %v\n", err)
		return err
	}

	var config Config
	json.Unmarshal(configData, &config)

	fmt.Printf("✅ Exported configuration to %s\n", outputFile)
	fmt.Println("\n📊 Summary:")
	fmt.Printf("   Accounts: %d\n", len(config.Accounts))
	for _, acc := range config.Accounts {
		fmt.Printf("      • %s: %s...\n", acc.Name, acc.AccountID[:min(8, len(acc.AccountID))])
	}
	fmt.Println("\n⚠️  WARNING: This file contains API tokens! Keep it secure! 🔒")

	return nil
}

func (ft *FlareTunnel) ImportConfig(inputFile string, merge bool) error {
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		fmt.Printf("❌ Import file not found: %s\n", inputFile)
		return err
	}

	importData, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("❌ Failed to read import file: %v\n", err)
		return err
	}

	// Remove BOM if present
	if len(importData) >= 3 && importData[0] == 0xEF && importData[1] == 0xBB && importData[2] == 0xBF {
		importData = importData[3:]
	}

	var importWrapper map[string]interface{}
	var newConfig Config

	if err := json.Unmarshal(importData, &importWrapper); err != nil {
		fmt.Printf("❌ Failed to parse import file: %v\n", err)
		return err
	}

	// Check if it's an export format or direct config
	if configData, ok := importWrapper["config"]; ok {
		configBytes, _ := json.Marshal(configData)
		json.Unmarshal(configBytes, &newConfig)
	} else {
		json.Unmarshal(importData, &newConfig)
	}

	if len(newConfig.Accounts) == 0 {
		fmt.Println("❌ No accounts found in import file")
		return fmt.Errorf("no accounts in import")
	}

	fmt.Printf("📥 Import file: %s\n", inputFile)
	fmt.Printf("   Accounts: %d\n\n", len(newConfig.Accounts))

	for idx, acc := range newConfig.Accounts {
		fmt.Printf("   %d. %s: %s...\n", idx+1, acc.Name, acc.AccountID[:min(8, len(acc.AccountID))])
	}

	var finalConfig Config

	if merge && fileExists("flaretunnel.json") {
		existingData, _ := os.ReadFile("flaretunnel.json")
		json.Unmarshal(existingData, &finalConfig)

		existingNames := make(map[string]bool)
		for _, acc := range finalConfig.Accounts {
			existingNames[acc.Name] = true
		}

		for _, acc := range newConfig.Accounts {
			if !existingNames[acc.Name] {
				finalConfig.Accounts = append(finalConfig.Accounts, acc)
				fmt.Printf("➕ Added account: %s\n", acc.Name)
			} else {
				fmt.Printf("⚠️  Skipped duplicate: %s\n", acc.Name)
			}
		}
	} else {
		finalConfig = newConfig
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nConfirm import? (y/N): ")
	confirm, _ := reader.ReadString('\n')

	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		fmt.Println("Import cancelled.")
		return nil
	}

	data, _ := json.MarshalIndent(finalConfig, "", "  ")
	if err := os.WriteFile("flaretunnel.json", data, 0644); err != nil {
		fmt.Printf("❌ Failed to save configuration: %v\n", err)
		return err
	}

	fmt.Println("\n✅ Configuration imported!")
	fmt.Printf("📊 Total accounts: %d\n", len(finalConfig.Accounts))

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ====================================================================
// PROXY SERVER
// ====================================================================

type ProxyServer struct {
	Host                 string
	Port                 int
	Workers              []*Worker
	CurrentWorkerIndex   int
	RotationMode         string
	Verbose              bool
	AllowIPAccess        bool
	CACertPath           string
	CAKeyPath            string
	BlacklistPatterns    []string
	InlineBlockPatterns  []string
	BlacklistStats       map[string]int
	UpstreamProxy        string
	UpstreamVerifySSL    bool
	CacheCerts           bool
	NoSSLIntercept       bool
	mutex                sync.Mutex
	certCache            map[string]*tls.Certificate
	certMutex            sync.RWMutex
}

func NewProxyServer(host string, port int) *ProxyServer {
	return &ProxyServer{
		Host:              host,
		Port:              port,
		RotationMode:      "round-robin",
		BlacklistStats:    make(map[string]int),
		certCache:         make(map[string]*tls.Certificate),
	}
}

func (ps *ProxyServer) LoadWorkers(endpointsFile string, workerIndices []int) error {
	data, err := os.ReadFile(endpointsFile)
	if err != nil {
		return err
	}

	var allWorkers []*Worker
	if err := json.Unmarshal(data, &allWorkers); err != nil {
		return err
	}

	if len(workerIndices) > 0 {
		selected := []*Worker{}
		for _, idx := range workerIndices {
			if idx >= 0 && idx < len(allWorkers) {
				selected = append(selected, allWorkers[idx])
			}
		}
		ps.Workers = selected
	} else {
		ps.Workers = allWorkers
	}

	return nil
}

func (ps *ProxyServer) LoadBlacklist(blacklistFile string) error {
	patterns := []string{}

	// Load from file
	if blacklistFile != "" {
		if _, err := os.Stat(blacklistFile); err == nil {
			file, err := os.Open(blacklistFile)
			if err == nil {
				defer file.Close()
				scanner := bufio.NewScanner(file)

				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line != "" && !strings.HasPrefix(line, "#") {
						patterns = append(patterns, line)
					}
				}

				if len(patterns) > 0 {
					fmt.Printf("✅ Loaded %d patterns from %s\n", len(patterns), blacklistFile)
				}
			}
		}
	}

	// Add inline patterns
	if len(ps.InlineBlockPatterns) > 0 {
		patterns = append(patterns, ps.InlineBlockPatterns...)
		fmt.Printf("✅ Added %d inline patterns\n", len(ps.InlineBlockPatterns))
	}

	ps.BlacklistPatterns = patterns

	return nil
}

func (ps *ProxyServer) GetWorkerURL() string {
	if len(ps.Workers) == 0 {
		return ""
	}

	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	if ps.RotationMode == "random" {
		return ps.Workers[time.Now().UnixNano()%int64(len(ps.Workers))].URL
	} else if ps.RotationMode == "round-robin" {
		worker := ps.Workers[ps.CurrentWorkerIndex]
		ps.CurrentWorkerIndex = (ps.CurrentWorkerIndex + 1) % len(ps.Workers)
		return worker.URL
	}

	return ps.Workers[0].URL
}

func (ps *ProxyServer) IsBlacklisted(targetURL string) bool {
	if len(ps.BlacklistPatterns) == 0 {
		return false
	}

	urlLower := strings.ToLower(targetURL)
	parsedURL, _ := url.Parse(targetURL)
	hostname := ""
	path := ""

	if parsedURL != nil {
		hostname = strings.ToLower(parsedURL.Hostname())
		path = strings.ToLower(parsedURL.Path)
	}

	for _, pattern := range ps.BlacklistPatterns {
		patternLower := strings.ToLower(pattern)
		if strings.Contains(hostname, patternLower) ||
			strings.Contains(path, patternLower) ||
			strings.Contains(urlLower, patternLower) ||
			strings.HasSuffix(urlLower, patternLower) {

			ps.mutex.Lock()
			ps.BlacklistStats[pattern]++
			ps.mutex.Unlock()

			return true
		}
	}

	return false
}

func (ps *ProxyServer) HandleHTTP(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.String()
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + r.Host + r.URL.String()
	}

	if ps.IsBlacklisted(targetURL) {
		if ps.Verbose {
			fmt.Printf("🚫 BLOCKED (blacklist): %s\n", targetURL)
		}
		http.Error(w, "Blacklisted", http.StatusForbidden)
		return
	}

	parsedURL, _ := url.Parse(targetURL)
	if !ps.AllowIPAccess && isIPAddress(parsedURL.Hostname()) {
		if ps.Verbose {
			fmt.Printf("🛡️  BLOCKED (IP): %s\n", parsedURL.Hostname())
		}
		http.Error(w, "Direct IP access blocked", http.StatusForbidden)
		return
	}

	workerURL := ps.GetWorkerURL()
	if workerURL == "" {
		http.Error(w, "No workers available", http.StatusServiceUnavailable)
		return
	}

	proxyURL := workerURL + "?url=" + url.QueryEscape(targetURL)

	if ps.Verbose {
		fmt.Printf("\n📤 [%s] %s\n", r.Method, targetURL)
		fmt.Printf("   ↓ via Worker: %s\n", workerURL)
	}

	// Create proxy request
	proxyReq, err := http.NewRequest(r.Method, proxyURL, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for k, v := range r.Header {
		if !strings.EqualFold(k, "Host") && !strings.EqualFold(k, "Connection") {
			proxyReq.Header[k] = v
		}
	}

	// Send request with optional upstream proxy
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !ps.UpstreamVerifySSL},
	}

	if ps.UpstreamProxy != "" {
		proxyURL, err := url.Parse(ps.UpstreamProxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	if ps.Verbose {
		status := "✅"
		if resp.StatusCode >= 400 {
			status = "⚠️"
		}
		fmt.Printf("   ↑ %s %d\n", status, resp.StatusCode)
	}
}

func (ps *ProxyServer) HandleCONNECT(w http.ResponseWriter, r *http.Request) {
	if ps.CACertPath == "" {
		http.Error(w, "HTTPS not supported", http.StatusNotImplemented)
		return
	}

	host := r.Host
	hostname := strings.Split(host, ":")[0]

	if ps.Verbose {
		fmt.Printf("\n🔒 [CONNECT] %s\n", host)
	}

	// Get or generate certificate
	ps.certMutex.RLock()
	cert, exists := ps.certCache[hostname]
	ps.certMutex.RUnlock()

	if !exists {
		newCert, err := generateHostCert(hostname, ps.CACertPath, ps.CAKeyPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cert = newCert

		ps.certMutex.Lock()
		ps.certCache[hostname] = cert
		ps.certMutex.Unlock()
	}

	// Send 200 Connection Established
	w.WriteHeader(http.StatusOK)

	// Hijack connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Wrap with TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		if ps.Verbose {
			fmt.Printf("✗ SSL handshake failed: %v\n", err)
		}
		return
	}

	// Read HTTPS request
	reader := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	targetURL := "https://" + hostname + req.URL.String()

	if ps.IsBlacklisted(targetURL) {
		if ps.Verbose {
			fmt.Printf("   🚫 BLOCKED (blacklist): %s\n", targetURL)
		}
		return
	}

	workerURL := ps.GetWorkerURL()
	if workerURL == "" {
		return
	}

	proxyURL := workerURL + "?url=" + url.QueryEscape(targetURL)

	if ps.Verbose {
		fmt.Printf("   📤 [%s] %s\n", req.Method, targetURL)
		fmt.Printf("      ↓ via Worker: %s\n", workerURL)
	}

	// Create proxy request
	proxyReq, err := http.NewRequest(req.Method, proxyURL, req.Body)
	if err != nil {
		return
	}

	for k, v := range req.Header {
		if !strings.EqualFold(k, "Host") && !strings.EqualFold(k, "Connection") {
			proxyReq.Header[k] = v
		}
	}

	// Setup transport with optional upstream proxy
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !ps.UpstreamVerifySSL},
	}

	if ps.UpstreamProxy != "" {
		upstreamURL, err := url.Parse(ps.UpstreamProxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(upstreamURL)
		}
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check for dropped headers warning from Worker
	if ps.Verbose {
		if dropped := resp.Header.Get("X-Dropped-Headers"); dropped != "" {
			fmt.Printf("      ⚠️  Dropped headers: %s\n", dropped)
			fmt.Println("         💡 Add these to allowedHeaders in WorkerScript if needed")
		}
	}

	// Write response (strip internal header before forwarding to client)
	tlsConn.Write([]byte(fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.StatusCode, resp.Status)))

	for k, v := range resp.Header {
		if strings.EqualFold(k, "X-Dropped-Headers") {
			continue
		}
		for _, vv := range v {
			tlsConn.Write([]byte(fmt.Sprintf("%s: %s\r\n", k, vv)))
		}
	}

	tlsConn.Write([]byte("\r\n"))
	io.Copy(tlsConn, resp.Body)

	if ps.Verbose {
		status := "✅"
		if resp.StatusCode >= 400 {
			status = "⚠️"
		}
		fmt.Printf("      ↑ %s %d\n", status, resp.StatusCode)
	}
}

func (ps *ProxyServer) Start(blacklistFile string) error {
	// Setup SSL
	ps.CACertPath = "flaretunnel_ca.crt"
	ps.CAKeyPath = "flaretunnel_ca.key"

	if !ps.NoSSLIntercept {
		if err := generateCACert(ps.CACertPath, ps.CAKeyPath); err != nil {
			fmt.Printf("⚠️  SSL setup failed: %v\n", err)
			ps.CACertPath = ""
		}
	} else {
		ps.CACertPath = ""
	}

	// Load blacklist
	ps.LoadBlacklist(blacklistFile)

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("🚀 FlareTunnel Tunnel Server Started")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("📡 Listening: %s:%d\n", ps.Host, ps.Port)
	fmt.Printf("⚙️  Workers: %d\n", len(ps.Workers))
	fmt.Printf("🔄 Rotation: %s\n", ps.RotationMode)

	if ps.NoSSLIntercept {
		fmt.Printf("🔒 SSL/HTTPS: ✗ Disabled by --no-ssl-intercept\n")
	} else if ps.CACertPath != "" {
		fmt.Printf("🔒 SSL/HTTPS: ✓ Enabled (HTTPS CONNECT supported)\n")
	} else {
		fmt.Printf("🔒 SSL/HTTPS: ✗ Disabled\n")
	}

	if ps.AllowIPAccess {
		fmt.Printf("🛡️  IP Blocking: ❌ Disabled (--unsafe)\n")
	} else {
		fmt.Printf("🛡️  IP Blocking: ✅ Enabled (saves Worker requests)\n")
	}

	blacklistMsg := fmt.Sprintf("🚫 Blacklist: %d pattern(s)", len(ps.BlacklistPatterns))
	if blacklistFile == "blacklist-minimal.txt" && len(ps.BlacklistPatterns) > 0 {
		blacklistMsg += " ✅ (default: blacklist-minimal.txt)"
	}
	fmt.Println(blacklistMsg)

	if ps.UpstreamProxy != "" {
		fmt.Printf("🔗 Upstream: %s\n", ps.UpstreamProxy)
	} else {
		fmt.Printf("🔗 Upstream: ❌ None (direct to Workers)\n")
	}

	if ps.Verbose {
		fmt.Printf("📝 Verbose: ✅ Enabled\n")
	} else {
		fmt.Printf("📝 Verbose: ❌ Disabled\n")
	}

	fmt.Println("\n📋 Selected Workers:")
	for idx, worker := range ps.Workers {
		workerName := worker.Name
		if len(workerName) > 50 {
			workerName = workerName[:47] + "..."
		}
		fmt.Printf("   [%d] %s\n", idx, workerName)
	}

	if ps.UpstreamProxy != "" {
		fmt.Println("\n🔀 Request Flow:")
		fmt.Printf("   Client → FlareTunnel:%d → %s → Cloudflare Workers → Target\n", ps.Port, ps.UpstreamProxy)
	}

	fmt.Println("\n⚙️  Proxy Configuration:")
	fmt.Printf("   HTTP Proxy:  %s:%d\n", ps.Host, ps.Port)
	fmt.Printf("   HTTPS Proxy: %s:%d\n", ps.Host, ps.Port)

	if ps.CACertPath != "" {
		fmt.Println("\n🔐 For HTTPS without warnings, install CA certificate:")
		fmt.Printf("   📄 File: %s\n", ps.CACertPath)
		fmt.Printf("   💡 Or use verify=False in code\n")
	}

	fmt.Println("\n💡 Tips:")
	if len(ps.BlacklistPatterns) > 0 {
		fmt.Println("   • Blacklist active - saving Worker requests! 💰")
	} else {
		fmt.Println("   • No blacklist - use --blacklist blacklist-minimal.txt to save requests")
	}
	if !ps.AllowIPAccess {
		fmt.Println("   • IP blocking active - Cloudflare doesn't support IPs anyway")
	}
	fmt.Println("   • Press Ctrl+C to stop")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	// Start server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			ps.HandleCONNECT(w, r)
		} else {
			ps.HandleHTTP(w, r)
		}
	})

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", ps.Host, ps.Port),
		Handler: handler,
	}

	return server.ListenAndServe()
}

// ====================================================================
// UTILITY FUNCTIONS
// ====================================================================

func generateWorkerName() string {
	timestamp := time.Now().Unix()
	suffix := randomString(6)
	return fmt.Sprintf("flaretunnel-%d-%s", timestamp, suffix)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
		time.Sleep(1 * time.Nanosecond)
	}
	return string(b)
}

func isIPAddress(hostname string) bool {
	host := strings.Split(hostname, ":")[0]
	ip := net.ParseIP(host)
	return ip != nil
}

func testWorker(workerURL string) bool {
	testURL := workerURL + "?url=" + url.QueryEscape("https://httpbin.org/status/200")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(testURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func sumMap(m map[string]int) int {
	sum := 0
	for _, v := range m {
		sum += v
	}
	return sum
}

// Simple multipart writer
type simpleMultipartWriter struct {
	buf       *bytes.Buffer
	boundary  string
}

func multipartWriter(buf *bytes.Buffer) *simpleMultipartWriter {
	return &simpleMultipartWriter{
		buf:      buf,
		boundary: "----FlareTunnelBoundary" + randomString(16),
	}
}

func (w *simpleMultipartWriter) WriteField(field, value string) {
	w.buf.WriteString("--" + w.boundary + "\r\n")
	w.buf.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=\"%s\"\r\n\r\n", field))
	w.buf.WriteString(value + "\r\n")
}

func (w *simpleMultipartWriter) Close() {
	w.buf.WriteString("--" + w.boundary + "--\r\n")
}

func (w *simpleMultipartWriter) FormDataContentType() string {
	return "multipart/form-data; boundary=" + w.boundary
}

// ====================================================================
// CLI COMMANDS
// ====================================================================

func setupConfig() error {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("🔧 FlareTunnel Multi-Account Configuration")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()
	fmt.Println("Getting Cloudflare Credentials:")
	fmt.Println("1. Sign up at https://cloudflare.com")
	fmt.Println("2. Go to https://dash.cloudflare.com/profile/api-tokens")
	fmt.Println("3. Click Create Token - use 'Edit Cloudflare Workers' template")
	fmt.Println("4. Set account and zone resources to all")
	fmt.Println("5. Copy the token and Account ID")
	fmt.Println()
	fmt.Println("💡 Tip: You can add multiple accounts for more quota!")
	fmt.Println("   Each account = 100,000 requests/day")
	fmt.Println()

	accounts := []Account{}
	reader := bufio.NewReader(os.Stdin)

	for accountNum := 1; ; accountNum++ {
		fmt.Printf("\n📋 Account #%d\n", accountNum)
		fmt.Println(strings.Repeat("-", 40))

		fmt.Printf("Account name (e.g., 'main', 'backup') [account-%d]: ", accountNum)
		accountName, _ := reader.ReadString('\n')
		accountName = strings.TrimSpace(accountName)
		if accountName == "" {
			accountName = fmt.Sprintf("account-%d", accountNum)
		}

		fmt.Print("API token: ")
		apiToken, _ := reader.ReadString('\n')
		apiToken = strings.TrimSpace(apiToken)
		if apiToken == "" {
			if accountNum == 1 {
				fmt.Println("❌ API token is required")
				return fmt.Errorf("no API token provided")
			}
			break
		}

		fmt.Print("Account ID: ")
		accountID, _ := reader.ReadString('\n')
		accountID = strings.TrimSpace(accountID)
		if accountID == "" {
			if accountNum == 1 {
				fmt.Println("❌ Account ID is required")
				return fmt.Errorf("no account ID provided")
			}
			break
		}

		// Try to auto-detect subdomain
		fmt.Print("   Detecting workers.dev subdomain... ")
		tempClient := NewCloudflareClient(apiToken, accountID, "")
		subdomain, err := tempClient.FetchSubdomain()
		if err == nil {
			fmt.Printf("Detected '%s'\n", subdomain)
		} else {
			fmt.Println("Failed")
			fmt.Printf("⚠️  Could not auto-detect subdomain: %v\n", err)
			fmt.Print("   Enter your workers.dev subdomain manually (e.g., 'kleggy00') [leave empty to skip]: ")
			subdomain, _ = reader.ReadString('\n')
			subdomain = strings.TrimSpace(subdomain)
		}

		accounts = append(accounts, Account{
			Name:      accountName,
			APIToken:  apiToken,
			AccountID: accountID,
			Subdomain: subdomain,
		})

		fmt.Printf("✅ Account '%s' added!\n", accountName)

		if accountNum >= 1 {
			fmt.Print("\nAdd another account? (y/N): ")
			addMore, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(addMore)) != "y" {
				break
			}
		}
	}

	if len(accounts) == 0 {
		fmt.Println("❌ No accounts configured")
		return fmt.Errorf("no accounts configured")
	}

	config := Config{Accounts: accounts}
	data, _ := json.MarshalIndent(config, "", "  ")

	if err := os.WriteFile("flaretunnel.json", data, 0644); err != nil {
		fmt.Printf("❌ Error saving configuration: %v\n", err)
		return err
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("✅ Configuration saved!")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("📄 Config file: flaretunnel.json")
	fmt.Printf("📊 Accounts configured: %d\n", len(accounts))
	fmt.Printf("🚀 Total daily quota: %d requests\n", len(accounts)*100000)
	fmt.Println()

	for _, acc := range accounts {
		fmt.Printf("   • %s: %s...\n", acc.Name, acc.AccountID[:8])
	}

	fmt.Println()
	fmt.Println("🎉 FlareTunnel is now configured!")

	return nil
}

func parseWorkerIndices(indicesStr string) []int {
	indices := []int{}
	parts := strings.Split(indicesStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err1 == nil && err2 == nil {
					for i := start; i <= end; i++ {
						indices = append(indices, i)
					}
				}
			}
		} else {
			if idx, err := strconv.Atoi(part); err == nil {
				indices = append(indices, idx)
			}
		}
	}

	return indices
}

// ====================================================================
// MAIN
// ====================================================================

func main() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	command := os.Args[1]

	switch command {
	case "config":
		setupConfig()

	case "create":
		count := 1
		accountName := ""
		distribute := false

		for i := 2; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--count":
				if i+1 < len(os.Args) {
					count, _ = strconv.Atoi(os.Args[i+1])
					i++
				}
			case "--account":
				if i+1 < len(os.Args) {
					accountName = os.Args[i+1]
					i++
				}
			case "--distribute":
				distribute = true
			}
		}

		ft, err := NewFlareTunnel("flaretunnel.json")
		if err != nil {
			fmt.Printf("❌ Configuration error: %v\n", err)
			fmt.Println("Run: go run FlareTunnel.go config")
			return
		}

		ft.CreateWorkers(count, accountName, distribute)

	case "list":
		verbose := false
		checkStatus := false

		for i := 2; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--verbose", "-v":
				verbose = true
			case "--status":
				checkStatus = true
			}
		}

		// If both flags provided, verbose already includes status check
		if verbose && checkStatus {
			fmt.Println("⚠️  Note: --verbose already includes live status check, --status flag is redundant\n")
			// checkStatus is already covered by verbose, no need to set it
		}

		ft, err := NewFlareTunnel("flaretunnel.json")
		if err != nil {
			fmt.Printf("❌ Configuration error: %v\n", err)
			return
		}

		ft.ListWorkers(verbose, checkStatus)

	case "test":
		targetURL := "https://ifconfig.me/ip"
		method := "GET"

		for i := 2; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--url":
				if i+1 < len(os.Args) {
					targetURL = os.Args[i+1]
					i++
				}
			case "--method":
				if i+1 < len(os.Args) {
					method = os.Args[i+1]
					i++
				}
			}
		}

		ft, err := NewFlareTunnel("flaretunnel.json")
		if err != nil {
			fmt.Printf("❌ Configuration error: %v\n", err)
			return
		}

		ft.TestWorkers(targetURL, method)

	case "export":
		outputFile := "flaretunnel_config_backup.json"

		for i := 2; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--output":
				if i+1 < len(os.Args) {
					outputFile = os.Args[i+1]
					i++
				}
			}
		}

		ft, _ := NewFlareTunnel("flaretunnel.json")
		ft.ExportConfig(outputFile)

	case "import":
		inputFile := ""
		merge := false

		for i := 2; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--input":
				if i+1 < len(os.Args) {
					inputFile = os.Args[i+1]
					i++
				}
			case "--merge":
				merge = true
			}
		}

		if inputFile == "" {
			fmt.Println("❌ Error: --input required for import command")
			fmt.Println("Usage: go run FlareTunnel.go import --input config_backup.json [--merge]")
			return
		}

		ft := &FlareTunnel{}
		ft.ImportConfig(inputFile, merge)

	case "cleanup":
		accountName := ""

		for i := 2; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--account":
				if i+1 < len(os.Args) {
					accountName = os.Args[i+1]
					i++
				}
			}
		}

		ft, err := NewFlareTunnel("flaretunnel.json")
		if err != nil {
			fmt.Printf("❌ Configuration error: %v\n", err)
			return
		}

		reader := bufio.NewReader(os.Stdin)
		if accountName != "" {
			fmt.Printf("Delete ALL workers from account '%s'? (y/N): ", accountName)
		} else {
			fmt.Print("Delete ALL FlareTunnel endpoints from ALL accounts? (y/N): ")
		}

		confirm, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(confirm)) == "y" {
			ft.CleanupWorkers(accountName)
		} else {
			fmt.Println("Cleanup cancelled.")
		}

	case "tunnel":
		host := "127.0.0.1"
		port := 8080
		workersStr := ""
		mode := "round-robin"
		verbose := false
		unsafe := false
		blacklist := "blacklist-minimal.txt"
		upstreamProxy := ""
		upstreamVerifySSL := false
		cacheCerts := false
		noSSLIntercept := false
		blockPatterns := []string{}

		for i := 2; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--host":
				if i+1 < len(os.Args) {
					host = os.Args[i+1]
					i++
				}
			case "--port":
				if i+1 < len(os.Args) {
					port, _ = strconv.Atoi(os.Args[i+1])
					i++
				}
			case "--workers":
				if i+1 < len(os.Args) {
					workersStr = os.Args[i+1]
					i++
				}
			case "--mode":
				if i+1 < len(os.Args) {
					mode = os.Args[i+1]
					i++
				}
			case "--verbose", "-v":
				verbose = true
			case "--unsafe":
				unsafe = true
			case "--blacklist":
				if i+1 < len(os.Args) {
					blacklist = os.Args[i+1]
					i++
				}
			case "--upstream-proxy":
				if i+1 < len(os.Args) {
					upstreamProxy = os.Args[i+1]
					i++
				}
			case "--upstream-verify-ssl":
				upstreamVerifySSL = true
			case "--cache-certs":
				cacheCerts = true
			case "--no-ssl-intercept":
				noSSLIntercept = true
			case "--block":
				if i+1 < len(os.Args) {
					blockPatterns = append(blockPatterns, os.Args[i+1])
					i++
				}
			}
		}

		ps := NewProxyServer(host, port)
		ps.RotationMode = mode
		ps.Verbose = verbose
		ps.AllowIPAccess = unsafe
		ps.UpstreamProxy = upstreamProxy
		ps.UpstreamVerifySSL = upstreamVerifySSL
		ps.CacheCerts = cacheCerts
		ps.NoSSLIntercept = noSSLIntercept

		// Add inline block patterns
		if len(blockPatterns) > 0 {
			ps.InlineBlockPatterns = blockPatterns
		}

		var workerIndices []int
		if workersStr != "" {
			workerIndices = parseWorkerIndices(workersStr)
		}

		if err := ps.LoadWorkers("flaretunnel_endpoints.json", workerIndices); err != nil {
			fmt.Printf("❌ Failed to load workers: %v\n", err)
			fmt.Println("Run: go run FlareTunnel.go create --count 5")
			return
		}

		if len(ps.Workers) == 0 {
			fmt.Println("❌ No workers available")
			return
		}

		ps.Start(blacklist)

	default:
		printHelp()
	}
}

func printHelp() {
	help := `
FlareTunnel - Cloudflare Workers Proxy System (Go Version)

Usage: go run FlareTunnel.go <command> [options]

Commands:
  config                    Configure Cloudflare API credentials (interactive)
  create                    Create new Cloudflare Workers
  list                      List all Workers with analytics
  test                      Test Workers with a target URL
  export                    Export configuration to backup file
  import                    Import configuration from backup file
  cleanup                   Delete Workers (prompts for confirmation)
  tunnel                    Start local proxy server

Examples:
  # Configuration
  go run FlareTunnel.go config

  # Create Workers
  go run FlareTunnel.go create --count 5
  go run FlareTunnel.go create --count 10 --distribute
  go run FlareTunnel.go create --count 3 --account main

  # List Workers
  go run FlareTunnel.go list           # Basic list
  go run FlareTunnel.go list --verbose # Detailed + live status check
  go run FlareTunnel.go list --status  # Only live response times

  # Test Workers
  go run FlareTunnel.go test
  go run FlareTunnel.go test --url https://httpbin.org/ip
  go run FlareTunnel.go test --url https://example.com --method POST

  # Export/Import Config
  go run FlareTunnel.go export --output my_backup.json
  go run FlareTunnel.go import --input my_backup.json
  go run FlareTunnel.go import --input config.json --merge

  # Start Tunnel
  go run FlareTunnel.go tunnel --verbose
  go run FlareTunnel.go tunnel --workers 0,1,2 --mode random
  go run FlareTunnel.go tunnel --port 9090 --blacklist blacklist.txt
  go run FlareTunnel.go tunnel --upstream-proxy http://127.0.0.1:8888

  # Cleanup
  go run FlareTunnel.go cleanup
  go run FlareTunnel.go cleanup --account main

Options:
  Create:
    --count N               Number of workers to create (default: 1)
    --account NAME          Create on specific account
    --distribute            Auto-distribute across accounts based on quota

  List:
    --verbose, -v           Show detailed info + live status check (created, age, response times)
    --status                Check only live worker status (response times, no verbose info)

  Test:
    --url URL               Target URL to test (default: https://ifconfig.me/ip)
    --method METHOD         HTTP method (default: GET)

  Export:
    --output FILE           Output file (default: flaretunnel_config_backup.json)

  Import:
    --input FILE            Input config backup file (REQUIRED)
    --merge                 Merge with existing config (skip duplicates)

  Cleanup:
    --account NAME          Delete from specific account only

  Tunnel:
    --host HOST             Bind host (default: 127.0.0.1)
    --port PORT             Bind port (default: 8080)
    --workers INDICES       Worker indices (e.g., '0,1,2' or '0-2')
    --mode MODE             Rotation mode: random, round-robin (default: round-robin)
    --verbose, -v           Enable verbose logging
    --unsafe                Allow IP access (not recommended)
    --upstream-proxy URL    Upstream proxy (e.g., http://127.0.0.1:8080)
    --upstream-verify-ssl   Verify SSL for upstream proxy
    --cache-certs           Cache SSL certs to disk
    --no-ssl-intercept      Disable SSL interception
    --blacklist FILE        Blacklist file (default: blacklist-minimal.txt)
    --block PATTERN         Block pattern (can be used multiple times)
`
	fmt.Println(help)
}

