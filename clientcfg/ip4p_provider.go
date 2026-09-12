/* SPDX-License-Identifier: MIT */

package clientcfg

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

const maxAPIResponseSize = 2 << 20

type txtProvider interface {
	Name() string
	GetTXTRecords(context.Context, string) ([]string, error)
}

func newTXTProvider(config *IP4P, client *http.Client) (txtProvider, error) {
	if config.Provider == "" {
		return nil, nil
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: endpointLookupTimeout}
	}
	switch config.Provider {
	case "cloudflare":
		return &cloudflareProvider{
			apiKey:   config.APIKey,
			zoneID:   config.ZoneID,
			client:   client,
			endpoint: "https://api.cloudflare.com/client/v4",
		}, nil
	case "tencent":
		return &tencentProvider{
			secretID:  config.APIKey,
			secretKey: config.APISecret,
			client:    client,
			endpoint:  "https://dnspod.tencentcloudapi.com/",
			now:       time.Now,
		}, nil
	case "alibaba":
		return &alibabaProvider{
			accessKeyID:     config.APIKey,
			accessKeySecret: config.APISecret,
			client:          client,
			endpoint:        "https://alidns.aliyuncs.com/",
			now:             time.Now,
			nonce:           randomUUID,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported IP4P.Provider %q", config.Provider)
	}
}

type cloudflareProvider struct {
	apiKey   string
	zoneID   string
	client   *http.Client
	endpoint string
}

func (*cloudflareProvider) Name() string { return "cloudflare" }

func (provider *cloudflareProvider) GetTXTRecords(ctx context.Context, domain string) ([]string, error) {
	requestURL := strings.TrimRight(provider.endpoint, "/") + "/zones/" + url.PathEscape(provider.zoneID) + "/dns_records"
	query := url.Values{}
	query.Set("type", "TXT")
	query.Set("name", domain)
	query.Set("match", "all")
	requestURL += "?" + query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+provider.apiKey)
	request.Header.Set("Accept", "application/json")
	response, err := doAPIRequest(provider.client, request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := readAPIResponse(response)
	if err != nil {
		return nil, err
	}
	var result struct {
		Success bool `json:"success"`
		Result  []struct {
			Content string `json:"content"`
			Type    string `json:"type"`
			Name    string `json:"name"`
		} `json:"result"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode cloudflare response: %w", err)
	}
	if !result.Success {
		if len(result.Errors) != 0 {
			return nil, fmt.Errorf("cloudflare API: %s", result.Errors[0].Message)
		}
		return nil, fmt.Errorf("cloudflare API request was not successful")
	}
	var records []string
	for _, record := range result.Result {
		if strings.EqualFold(record.Type, "TXT") && sameDomain(record.Name, domain) {
			records = append(records, record.Content)
		}
	}
	return records, nil
}

type tencentProvider struct {
	secretID  string
	secretKey string
	client    *http.Client
	endpoint  string
	now       func() time.Time
}

func (*tencentProvider) Name() string { return "tencent" }

func (provider *tencentProvider) GetTXTRecords(ctx context.Context, domain string) ([]string, error) {
	root, subdomain, err := splitDNSName(domain)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(struct {
		Domain       string `json:"Domain"`
		SubDomain    string `json:"SubDomain"`
		RecordType   string `json:"RecordType"`
		ErrorOnEmpty string `json:"ErrorOnEmpty"`
	}{root, subdomain, "TXT", "no"})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("Host", request.URL.Host)
	timestamp := provider.now().UTC()
	request.Header.Set("X-TC-Action", "DescribeRecordList")
	request.Header.Set("X-TC-Version", "2021-03-23")
	request.Header.Set("X-TC-Timestamp", fmt.Sprint(timestamp.Unix()))
	request.Header.Set("Authorization", tencentAuthorization(provider.secretID, provider.secretKey, request.URL.Host, payload, timestamp))

	response, err := doAPIRequest(provider.client, request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := readAPIResponse(response)
	if err != nil {
		return nil, err
	}
	var result struct {
		Response struct {
			RecordList []struct {
				Value string `json:"Value"`
				Type  string `json:"Type"`
				Name  string `json:"Name"`
			} `json:"RecordList"`
			Error struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode tencent response: %w", err)
	}
	if result.Response.Error.Code != "" {
		return nil, fmt.Errorf("tencent API %s: %s", result.Response.Error.Code, result.Response.Error.Message)
	}
	var records []string
	for _, record := range result.Response.RecordList {
		if strings.EqualFold(record.Type, "TXT") && strings.EqualFold(record.Name, subdomain) {
			records = append(records, record.Value)
		}
	}
	return records, nil
}

func tencentAuthorization(secretID, secretKey, host string, payload []byte, now time.Time) string {
	const service = "dnspod"
	date := now.UTC().Format("2006-01-02")
	timestamp := now.UTC().Unix()
	canonicalHeaders := "content-type:application/json; charset=utf-8\n" + "host:" + host + "\n"
	canonicalRequest := "POST\n/\n\n" + canonicalHeaders + "\ncontent-type;host\n" + sha256Hex(payload)
	credentialScope := date + "/" + service + "/tc3_request"
	stringToSign := "TC3-HMAC-SHA256\n" + fmt.Sprint(timestamp) + "\n" + credentialScope + "\n" + sha256Hex([]byte(canonicalRequest))
	secretDate := hmacSHA256([]byte("TC3"+secretKey), []byte(date))
	secretService := hmacSHA256(secretDate, []byte(service))
	secretSigning := hmacSHA256(secretService, []byte("tc3_request"))
	signature := hex.EncodeToString(hmacSHA256(secretSigning, []byte(stringToSign)))
	return "TC3-HMAC-SHA256 Credential=" + secretID + "/" + credentialScope + ", SignedHeaders=content-type;host, Signature=" + signature
}

type alibabaProvider struct {
	accessKeyID     string
	accessKeySecret string
	client          *http.Client
	endpoint        string
	now             func() time.Time
	nonce           func() (string, error)
}

func (*alibabaProvider) Name() string { return "alibaba" }

func (provider *alibabaProvider) GetTXTRecords(ctx context.Context, domain string) ([]string, error) {
	root, subdomain, err := splitDNSName(domain)
	if err != nil {
		return nil, err
	}
	nonce, err := provider.nonce()
	if err != nil {
		return nil, fmt.Errorf("generate alibaba request nonce: %w", err)
	}
	params := map[string]string{
		"Format":           "JSON",
		"Version":          "2015-01-09",
		"AccessKeyId":      provider.accessKeyID,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"SignatureNonce":   nonce,
		"Timestamp":        provider.now().UTC().Format("2006-01-02T15:04:05Z"),
		"Action":           "DescribeDomainRecords",
		"DomainName":       root,
		"RRKeyWord":        subdomain,
		"Type":             "TXT",
		"SearchMode":       "COMBINATION",
		"PageSize":         "500",
	}
	canonical := alibabaCanonicalQuery(params)
	stringToSign := "GET&" + alibabaEscape("/") + "&" + alibabaEscape(canonical)
	signature := hmac.New(sha1.New, []byte(provider.accessKeySecret+"&"))
	signature.Write([]byte(stringToSign))
	params["Signature"] = base64.StdEncoding.EncodeToString(signature.Sum(nil))
	requestURL := strings.TrimRight(provider.endpoint, "?") + "?" + alibabaCanonicalQuery(params)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := doAPIRequest(provider.client, request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := readAPIResponse(response)
	if err != nil {
		return nil, err
	}
	var result struct {
		DomainRecords struct {
			Record []struct {
				Value  string `json:"Value"`
				Type   string `json:"Type"`
				RR     string `json:"RR"`
				Status string `json:"Status"`
			} `json:"Record"`
		} `json:"DomainRecords"`
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode alibaba response: %w", err)
	}
	if result.Code != "" {
		return nil, fmt.Errorf("alibaba API %s: %s", result.Code, result.Message)
	}
	var records []string
	for _, record := range result.DomainRecords.Record {
		if strings.EqualFold(record.Type, "TXT") && strings.EqualFold(record.RR, subdomain) && !strings.EqualFold(record.Status, "Disable") {
			records = append(records, record.Value)
		}
	}
	return records, nil
}

func splitDNSName(domain string) (root, subdomain string, err error) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	root, err = publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "", "", fmt.Errorf("determine root domain for %q: %w", domain, err)
	}
	if domain == root {
		return root, "@", nil
	}
	subdomain = strings.TrimSuffix(domain, "."+root)
	if subdomain == "" || subdomain == domain {
		return "", "", fmt.Errorf("determine subdomain for %q", domain)
	}
	return root, subdomain, nil
}

func alibabaCanonicalQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, alibabaEscape(key)+"="+alibabaEscape(params[key]))
	}
	return strings.Join(parts, "&")
}

func alibabaEscape(value string) string {
	return strings.NewReplacer("+", "%20", "*", "%2A", "%7E", "~").Replace(url.QueryEscape(value))
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func randomUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func sameDomain(first, second string) bool {
	return strings.EqualFold(strings.TrimSuffix(first, "."), strings.TrimSuffix(second, "."))
}

func doAPIRequest(client *http.Client, request *http.Request) (*http.Response, error) {
	response, err := client.Do(request)
	if err == nil {
		return response, nil
	}
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return nil, urlError.Err
	}
	return nil, err
}

func readAPIResponse(response *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, maxAPIResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxAPIResponseSize {
		return nil, fmt.Errorf("DNS provider response is too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("DNS provider returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}
