// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apigee

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/apigee/apigee-remote-service-cli/v2/testutil"
)

func oauthTestServer(t *testing.T) *httptest.Server {
	m := http.NewServeMux()
	resp := OAuthResponse{AccessToken: "token"}
	m.HandleFunc("/oauth", (func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	return httptest.NewServer(m)
}

func TestNewEdgeClient(t *testing.T) {
	ts := oauthTestServer(t)
	defer ts.Close()
	opts := &EdgeClientOptions{
		InsecureSkipVerify: true,
		Auth:               &EdgeAuth{SkipAuth: false, Username: "hi", Password: "secret", MFAToken: "mfa"},
		Debug:              true,
	}
	SetOAuthURL(ts.URL + "/oauth")
	_, err := NewEdgeClient(opts)
	if err != nil {
		t.Errorf("want no error got %v", err)
	}
}

func TestStreamToString(t *testing.T) {
	in := "test"
	if out := StreamToString(strings.NewReader(in)); in != out {
		t.Errorf("want %s got %s", in, out)
	}
}

func TestBool(t *testing.T) {
	in := true
	if out := *Bool(in); in != out {
		t.Errorf("want %v got %v", in, out)
	}
}

func TestInt(t *testing.T) {
	in := 123
	if out := *Int(in); in != out {
		t.Errorf("want %d got %d", in, out)
	}
}

func TestString(t *testing.T) {
	in := "test"
	if out := *String(in); in != out {
		t.Errorf("want %s got %s", in, out)
	}
}

func TestOnRequestCompleted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	c := &EdgeClient{client: http.DefaultClient, BaseURL: u, BaseURLEnv: u, auth: &EdgeAuth{BearerToken: "token"}}
	count := 0
	c.OnRequestCompleted(func(req *http.Request, res *http.Response) { count += 1 })
	req, _ := c.NewRequest(http.MethodGet, ts.URL, nil)
	_, _ = c.Do(req, nil)
	if count != 1 {
		t.Errorf("want count to be 1, got %d", count)
	}
}

func TestAuthHeader(t *testing.T) {
	u, _ := url.Parse("http://dummy.url")
	c1 := &EdgeClient{client: http.DefaultClient, BaseURL: u, BaseURLEnv: u, auth: &EdgeAuth{BearerToken: "token"}}
	req1, _ := c1.NewRequest(http.MethodGet, "", nil)
	if h := req1.Header.Get("Authorization"); h != "Bearer token" {
		t.Errorf("got %s", h)
	}

	c2 := &EdgeClient{client: http.DefaultClient, BaseURL: u, BaseURLEnv: u, auth: &EdgeAuth{Username: "hi", Password: "secret"}}
	req2, _ := c2.NewRequest(http.MethodGet, "", nil)
	if h := req2.Header.Get("Authorization"); h != "Basic aGk6c2VjcmV0" {
		t.Errorf("got %s", h)
	}
}

func TestNetrcRetrieval(t *testing.T) {
	cred := []byte(`machine api.enterprise.apigee.com
	login hi
	password secret`)
	tmpFile, _ := os.CreateTemp("", ".netrc")
	_, _ = tmpFile.Write(cred)
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, err := retrieveAuthFromNetrc("not a path", "dummy")
	testutil.ErrorContains(t, err, "no such file")
	auth, _ := retrieveAuthFromNetrc(tmpFile.Name(), "api.enterprise.apigee.com")
	if auth.Username != "hi" {
		t.Errorf("got %s", auth.Username)
	}
}

func TestMutualTLSWithCerts(t *testing.T) {
	ts := newMutualTLSServer()
	defer ts.Close()
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(ts.Certificate())
	opts := &EdgeClientOptions{MgmtURL: ts.URL, Org: "org", Env: "env", RootCAs: caCertPool, Certificates: ts.TLS.Certificates, Auth: &EdgeAuth{SkipAuth: true}}
	c, _ := NewEdgeClient(opts)
	req, _ := c.NewRequest(http.MethodGet, "", nil)
	_, err := c.Do(req, nil)
	if err != nil {
		t.Errorf("got %v", err)
	}
}

func TestEdgeClientErrorPaths(t *testing.T) {
	// 1. CheckResponse error
	resp := &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader(`{"error": {"message": "not found"}}`)),
	}
	if err := CheckResponse(resp); err == nil {
		t.Error("expected error")
	}

	// 2. OAuth Failure
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": {"message": "unauthorized"}}`))
	}))
	defer server.Close()
	oldURL := OAuthURL
	SetOAuthURL(server.URL)
	defer SetOAuthURL(oldURL)
	c := &EdgeClient{client: http.DefaultClient, auth: &EdgeAuth{Username: "u", Password: "p"}}
	if err := c.getOAuthToken(); err == nil {
		t.Error("expected oauth error")
	}

	// 3. Debug dump error
	debugDump(nil, fmt.Errorf("forced error"))
}

func newMutualTLSServer() *httptest.Server {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	ts.TLS = &tls.Config{RootCAs: x509.NewCertPool(), ClientAuth: tls.RequireAnyClientCert}
	ts.StartTLS()
	ts.TLS.RootCAs.AddCert(ts.Certificate())
	return ts
}

func TestEdgeClient_SurgicalErrorHits(t *testing.T) {
	
	t.Run("NetrcDeepErrors", func(t *testing.T) {
		_, err := retrieveAuthFromNetrc("/tmp/non-existent-netrc-123", "host")
		if err == nil {
			t.Error("expected error for invalid path")
		}

		tmpFile, _ := os.CreateTemp("", "netrc")
		defer func() { _ = os.Remove(tmpFile.Name()) }()
		_ = os.WriteFile(tmpFile.Name(), []byte("machine other.com\nlogin u\npassword p"), 0644)
		_, err = retrieveAuthFromNetrc(tmpFile.Name(), "missing.com")
		if err == nil {
			t.Error("expected error for missing machine")
		}
	})

	
	t.Run("NewClientURLParseError", func(t *testing.T) {
		opts := &EdgeClientOptions{
			// Using a control character (null byte) or invalid escape sequence
			MgmtURL: string([]byte{0x7f}),
			Org:     "org",
			Auth:    &EdgeAuth{SkipAuth: true},
		}
		_, err := NewEdgeClient(opts)
		if err == nil {
			t.Error("expected error for malformed MgmtURL")
		}
	})

	// 3. OAuth Token creation/CheckResponse errors
	t.Run("OAuthDeepErrors", func(t *testing.T) {
		oldOAuth := OAuthURL
		SetOAuthURL("http:// invalid-url")
		defer SetOAuthURL(oldOAuth)
		c := &EdgeClient{auth: &EdgeAuth{Username: "u", Password: "p"}}
		_ = c.getOAuthToken()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`not json`))
		}))
		defer server.Close()
		c.client = http.DefaultClient
		SetOAuthURL(server.URL)
		_ = c.getOAuthToken()
	})

	// 4.Do() and CheckResponse body errors
	t.Run("DoAndCheckResponseErrors", func(t *testing.T) {
		u, _ := url.Parse("http://localhost:1")
		c := &EdgeClient{client: http.DefaultClient, BaseURL: u, BaseURLEnv: u}
		req, _ := http.NewRequest(http.MethodGet, u.String(), nil)

		
		_, _ = c.Do(req, nil)

		_, _ = c.Do(req, &errorWriter{})

		badResp := &http.Response{
			StatusCode: 500,
			Body:       io.NopCloser(&errReader{}),
		}
		_ = CheckResponse(badResp)
	})
}

type errorWriter struct{}

func (e *errorWriter) Write(p []byte) (n int, err error) { return 0, fmt.Errorf("write error") }

type errReader struct{}

func (e *errReader) Read(p []byte) (n int, err error) { return 0, fmt.Errorf("read error") }


func TestErrorResponse_Error(t *testing.T) {
	
	er := &ErrorResponse{
		Response: &http.Response{
			StatusCode: 404,
			Request:    &http.Request{Method: "GET"},
		},
		Message: ResponseErrorMessage{Message: "not found"},
	}
	
	_ = er.Error()
}