/* SPDX-License-Identifier: MIT */

package clientcfg

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCloudflareProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		if got := request.URL.Query().Get("type"); got != "TXT" {
			t.Errorf("type = %q", got)
		}
		if got := request.URL.Query().Get("name"); got != "ip4p.example.com" {
			t.Errorf("name = %q", got)
		}
		fmt.Fprint(response, `{"success":true,"result":[{"type":"TXT","name":"ip4p.example.com","content":"record-one"},{"type":"A","name":"ip4p.example.com","content":"ignored"}]}`)
	}))
	defer server.Close()
	provider := &cloudflareProvider{apiKey: "test-token", zoneID: "test-zone", client: server.Client(), endpoint: server.URL}
	records, err := provider.GetTXTRecords(context.Background(), "ip4p.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0] != "record-one" {
		t.Fatalf("records = %v", records)
	}
}

func TestTencentProvider(t *testing.T) {
	fixedTime := time.Unix(1700000000, 0).UTC()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s", request.Method)
		}
		if !strings.HasPrefix(request.Header.Get("Authorization"), "TC3-HMAC-SHA256 Credential=secret-id/") {
			t.Errorf("unexpected Authorization header")
		}
		var payload map[string]string
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if payload["Domain"] != "example.co.uk" || payload["SubDomain"] != "ip4p" || payload["RecordType"] != "TXT" {
			t.Errorf("payload = %#v", payload)
		}
		fmt.Fprint(response, `{"Response":{"RecordList":[{"Type":"TXT","Name":"ip4p","Value":"record-two"}],"RequestId":"test"}}`)
	}))
	defer server.Close()
	provider := &tencentProvider{
		secretID: "secret-id", secretKey: "secret-key", client: server.Client(), endpoint: server.URL,
		now: func() time.Time { return fixedTime },
	}
	records, err := provider.GetTXTRecords(context.Background(), "ip4p.example.co.uk")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0] != "record-two" {
		t.Fatalf("records = %v", records)
	}
}

func TestAlibabaProvider(t *testing.T) {
	fixedTime := time.Date(2026, time.September, 12, 1, 2, 3, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		for key, want := range map[string]string{
			"Action": "DescribeDomainRecords", "DomainName": "example.com", "RRKeyWord": "ip4p", "Type": "TXT",
		} {
			if got := query.Get(key); got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
		if query.Get("Signature") == "" {
			t.Error("Signature is empty")
		}
		fmt.Fprint(response, `{"DomainRecords":{"Record":[{"Type":"TXT","RR":"ip4p","Status":"Enable","Value":"record-three"}]}}`)
	}))
	defer server.Close()
	provider := &alibabaProvider{
		accessKeyID: "access-id", accessKeySecret: "access-secret", client: server.Client(), endpoint: server.URL,
		now: func() time.Time { return fixedTime }, nonce: func() (string, error) { return "fixed-nonce", nil },
	}
	records, err := provider.GetTXTRecords(context.Background(), "ip4p.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0] != "record-three" {
		t.Fatalf("records = %v", records)
	}
}

func TestAlibabaCanonicalSignatureParameters(t *testing.T) {
	params := map[string]string{"Space": "a b", "Tilde": "~", "Star": "*"}
	query, err := url.QueryUnescape(alibabaCanonicalQuery(params))
	if err != nil {
		t.Fatal(err)
	}
	if query != "Space=a b&Star=*&Tilde=~" {
		t.Fatalf("canonical query = %q", query)
	}
}
