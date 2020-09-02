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

// Package apigee provides a client for administering Apigee Edge.
package apigee

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"

	"github.com/bgentry/go-netrc/netrc"
)

const (
	libraryVersion  = "0.1.0"
	defaultBaseURL  = "https://api.enterprise.apigee.com"
	basicAuthHeader = "Basic ZWRnZWNsaTplZGdlY2xpc2VjcmV0"
	userAgent       = "go-apigee-edge/" + libraryVersion
	appJSON         = "application/json"
	octetStream     = "application/octet-stream"
)

// OAuthURL is the oauth token endpoint
var OAuthURL = "https://login.apigee.com/oauth/token"

// EdgeClient manages communication with Apigee Edge V1 Admin API.
type EdgeClient struct {
	// HTTP client used to communicate with the Edge API.
	client *http.Client

	auth  *EdgeAuth
	debug bool

	// Base URL for API requests.
	BaseURL *url.URL

	// Base URL for API requests.
	BaseURLEnv *url.URL

	// User agent for client
	UserAgent string

	// Services used for communicating with the API
	Proxies ProxiesService

	KVMService KVMService

	CacheService CacheService
	// Account           AccountService
	// Actions           ActionsService
	// Domains           DomainsService
	// DropletActions    DropletActionsService
	// Images            ImagesService
	// ImageActions      ImageActionsService
	// Keys              KeysService
	// Regions           RegionsService
	// Sizes             SizesService
	// FloatingIPs       FloatingIPsService
	// FloatingIPActions FloatingIPActionsService
	// Storage           StorageService
	// StorageActions    StorageActionsService
	// Tags              TagsService

	IsGCPManaged bool

	// Optional function called after every successful request made to the DO APIs
	onRequestCompleted RequestCompletionCallback
}

// RequestCompletionCallback defines the type of the request callback function
type RequestCompletionCallback func(*http.Request, *http.Response)

// ListOptions holds optional parameters to various List methods
type ListOptions struct {
	// to ask for expanded results
	Expand bool `url:"expand"`
}

// Response wraps the standard http.Response returned from Apigee Edge. (why?)
type Response struct {
	*http.Response
}

// An ErrorResponse reports the error caused by an API request
type ErrorResponse struct {
	// HTTP response that caused this error
	Response *http.Response

	// Error message - maybe the json for this is "fault"
	// Message string `json:"message"`

	// Error message - maybe the json for this is "fault"
	Message ResponseErrorMessage `json:"error"`
}

// ResponseErrorMessage is a component of an ErrorResponse
type ResponseErrorMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

// EdgeClientOptions sets options for accessing edge APIs
type EdgeClientOptions struct {

	// MgmtURL is the Admin base URL. Optional. For example, if using OPDK this might be
	// http://192.168.10.56:8080. It defaults to https://api.enterprise.apigee.com.
	MgmtURL string

	// Specify the Edge organization name.
	Org string

	//Specify the Edge environment name.
	Env string

	// Required. Authentication information for the Edge Management server.
	Auth *EdgeAuth

	// Optional. Warning: if set to true, HTTP Basic Auth base64 blobs will appear in output.
	Debug bool

	// Optional. For hybrid and NG must be true.
	GCPManaged bool

	// Optional. Skip cert verification.
	InsecureSkipVerify bool
}

// EdgeAuth holds information about how to authenticate to the Edge Management server.
type EdgeAuth struct {
	// Optional. The path to the .netrc file that holds credentials for the Edge Management server.
	// By default, this is ${HOME}/.netrc .  If you specify a Password, this option is ignored.
	NetrcPath string

	// Optional. The username to use when authenticating to the Edge Management server.
	// Ignored if you specify a NetrcPath.
	Username string

	// Optional. Used if you explicitly specify a Password.
	Password string

	// Optional. Required if MFA (multi-factor authorization) is enabled.
	MFAToken string

	// if set to true, no auth will be set
	SkipAuth bool

	// BearerToken token for OAuth or SAML
	BearerToken string
}

// ApplyTo applies the auth info onto a request
func (auth *EdgeAuth) ApplyTo(req *http.Request) {
	if auth.BearerToken != "" {
		req.Header.Add("Authorization", "Bearer "+auth.BearerToken)
	} else {
		req.SetBasicAuth(auth.Username, auth.Password)
	}
}

func retrieveAuthFromNetrc(netrcPath, host string) (*EdgeAuth, error) {
	if netrcPath == "" {
		netrcPath = os.ExpandEnv("${HOME}/.netrc")
	}
	n, e := netrc.ParseFile(netrcPath)
	if e != nil {
		fmt.Printf("while parsing .netrc, error:\n%#v\n", e)
		return nil, e
	}
	machine := n.FindMachine(host) // eg, "api.enterprise.apigee.com"
	if machine == nil || machine.Password == "" {
		msg := fmt.Sprintf("while scanning %s, cannot find machine:%s", netrcPath, host)
		return nil, errors.New(msg)
	}
	auth := &EdgeAuth{Username: machine.Login, Password: machine.Password}
	return auth, nil
}

// NewEdgeClient returns a new EdgeClient.
func NewEdgeClient(o *EdgeClientOptions) (*EdgeClient, error) {
	httpClient := http.DefaultClient

	if o.InsecureSkipVerify {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		httpClient = &http.Client{Transport: tr}
	}

	mgmtURL := o.MgmtURL
	if o.MgmtURL == "" {
		mgmtURL = defaultBaseURL
	}
	baseURL, err := url.Parse(mgmtURL)
	if err != nil {
		return nil, err
	}
	baseURLEnv, err := url.Parse(mgmtURL)
	if err != nil {
		return nil, err
	}

	baseURL.Path = path.Join(baseURL.Path, "v1/organizations/", o.Org, "/")
	baseURLEnv.Path = path.Join(baseURLEnv.Path, "v1/organizations/", o.Org, "environments/", o.Env)

	c := &EdgeClient{
		client:       httpClient,
		BaseURL:      baseURL,
		BaseURLEnv:   baseURLEnv,
		UserAgent:    userAgent,
		IsGCPManaged: o.GCPManaged,
	}
	c.Proxies = &ProxiesServiceOp{client: c}
	c.KVMService = &KVMServiceOp{client: c}
	c.CacheService = &CacheServiceOp{client: c}

	if !o.Auth.SkipAuth {
		var e error
		if o.Auth == nil || (o.Auth.Password == "" && o.Auth.BearerToken == "") {
			c.auth, e = retrieveAuthFromNetrc(o.Auth.NetrcPath, baseURL.Host)
		} else {
			c.auth = &EdgeAuth{
				Username:    o.Auth.Username,
				Password:    o.Auth.Password,
				BearerToken: o.Auth.BearerToken,
				MFAToken:    o.Auth.MFAToken,
			}
		}
		if e != nil {
			return nil, e
		}
		// not overriding if auth token is given
		// otherwise enforcing oauth on legacy saas
		if o.Auth.BearerToken == "" && o.MgmtURL == defaultBaseURL {
			c.auth.MFAToken = o.Auth.MFAToken
			e = c.getOAuthToken()
			if e != nil {
				return nil, e
			}
		}
	}

	if o.Debug {
		c.debug = true
		c.onRequestCompleted = func(req *http.Request, resp *http.Response) {
			debugDump(httputil.DumpResponse(resp, true))
		}
	}

	return c, nil
}

func (c *EdgeClient) getOAuthToken() error {
	req, err := http.NewRequest(http.MethodPost, OAuthURL, nil)
	if err != nil {
		return err
	}
	q := req.URL.Query()
	q.Set("username", c.auth.Username)
	q.Set("password", c.auth.Password)
	q.Set("grant_type", "password")
	if c.auth.MFAToken != "" {
		q.Set("mfa_token", c.auth.MFAToken)
	}
	req.URL.RawQuery = q.Encode()
	req.Header.Add("Content-type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", basicAuthHeader)
	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	if res != nil {
		defer res.Body.Close()
	}
	if err := CheckResponse(res); err != nil {
		var errorResponse *ErrorResponse
		if errors.As(err, &errorResponse) {
			return fmt.Errorf("%d %v", res.StatusCode, errorResponse.Message)
		}
		return fmt.Errorf("%d", res.StatusCode)
	}
	body := &OAuthResponse{}
	if err := json.NewDecoder(res.Body).Decode(body); err != nil {
		return err
	}
	c.auth.BearerToken = body.AccessToken
	return nil
}

// NewRequest creates an API request. A relative URL can be provided in urlStr,
// which will be resolved to the BaseURL of the Client. Relative URLS should
// always be specified without a preceding slash. If specified, the value
// pointed to by body is JSON encoded and included in as the request body.
// The current environment path element will be included in the URL.
func (c *EdgeClient) NewRequest(method, urlStr string, body interface{}) (*http.Request, error) {
	return c.newRequest(method, urlStr, body, true)
}

// NewRequestNoEnv creates an API request as NewRequest, but does not include the environment path element.
func (c *EdgeClient) NewRequestNoEnv(method, urlStr string, body interface{}) (*http.Request, error) {
	return c.newRequest(method, urlStr, body, false)
}

func (c *EdgeClient) newRequest(method, urlStr string, body interface{}, includeEnv bool) (*http.Request, error) {
	rel, err := url.Parse(urlStr)
	ctype := ""
	if err != nil {
		return nil, err
	}
	u := c.BaseURL.ResolveReference(rel)

	if includeEnv {
		u.Path = path.Join(c.BaseURLEnv.Path, rel.Path)
	} else {
		u.Path = path.Join(c.BaseURL.Path, rel.Path)
	}

	var req *http.Request
	if body != nil {
		switch body := body.(type) {
		default:
			ctype = appJSON
			buf := new(bytes.Buffer)
			err = json.NewEncoder(buf).Encode(body)
			if err != nil {
				return nil, err
			}
			req, err = http.NewRequest(method, u.String(), buf)
		case io.Reader:
			ctype = octetStream
			req, err = http.NewRequest(method, u.String(), body)
		}
	} else {
		req, err = http.NewRequest(method, u.String(), nil)
	}

	if err != nil {
		return nil, err
	}

	if ctype != "" {
		req.Header.Add("Content-Type", ctype)
	}
	req.Header.Add("Accept", appJSON)
	req.Header.Add("User-Agent", c.UserAgent)
	if c.auth != nil {
		c.auth.ApplyTo(req)
	}
	return req, nil
}

// OnRequestCompleted sets the request completion callback for the API
func (c *EdgeClient) OnRequestCompleted(rc RequestCompletionCallback) {
	c.onRequestCompleted = rc
}

// newResponse creates a new Response for the provided http.Response
func newResponse(r *http.Response) *Response {
	response := Response{Response: r}

	return &response
}

func debugDump(data []byte, err error) {
	if err == nil {
		fmt.Fprintf(os.Stderr, "%s\n\n", data)
	} else {
		log.Fatalf("%s\n\n", err)
	}
}

// Do sends an API request and returns the API response. The API response is
// JSON decoded and stored in the value pointed to by v, or returned as an error
// if an API error has occurred. If v implements the io.Writer interface, the
// raw response will be written to v, without attempting to decode it.
func (c *EdgeClient) Do(req *http.Request, v interface{}) (*Response, error) {
	if c.debug {
		debugDump(httputil.DumpRequestOut(req, true))
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if c.onRequestCompleted != nil {
		c.onRequestCompleted(req, resp)
	}

	defer func() {
		if rerr := resp.Body.Close(); err == nil {
			err = rerr
		}
	}()

	response := newResponse(resp)

	err = CheckResponse(resp)
	if err != nil {
		return response, err
	}

	if v != nil {
		if w, ok := v.(io.Writer); ok {
			_, err := io.Copy(w, resp.Body)
			if err != nil {
				return nil, err
			}
		} else {
			err := json.NewDecoder(resp.Body).Decode(v)
			if err != nil {
				return nil, err
			}
		}
	}

	return response, err
}

func (r *ErrorResponse) Error() string {
	return fmt.Sprintf("%v %v: %d %v",
		r.Response.Request.Method, r.Response.Request.URL, r.Response.StatusCode, r.Message)
}

// CheckResponse checks the API response for errors, and returns them if
// present. A response is considered an error if it has a status code outside
// the 200 range. API error responses are expected to have either no response
// body, or a JSON response body that maps to ErrorResponse. Any other response
// body will be silently ignored.
func CheckResponse(r *http.Response) error {
	if c := r.StatusCode; c >= 200 && c <= 299 {
		return nil
	}

	errorResponse := &ErrorResponse{Response: r}
	data, err := ioutil.ReadAll(r.Body)
	if err == nil && len(data) > 0 {
		err := json.Unmarshal(data, errorResponse)
		if err != nil {
			errorResponse.Message = ResponseErrorMessage{
				Message: string(data),
			}
		}
	}

	return errorResponse
}

// String is a helper routine that allocates a new string value
// to store v and returns a pointer to it.
func String(v string) *string {
	p := new(string)
	*p = v
	return p
}

// Int is a helper routine that allocates a new int32 value
// to store v and returns a pointer to it, but unlike Int32
// its argument value is an int.
func Int(v int) *int {
	p := new(int)
	*p = v
	return p
}

// Bool is a helper routine that allocates a new bool value
// to store v and returns a pointer to it.
func Bool(v bool) *bool {
	p := new(bool)
	*p = v
	return p
}

// StreamToString converts a reader to a string
func StreamToString(stream io.Reader) string {
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(stream)
	return buf.String()
}

// SetOAuthURL sets the OAuth url
func SetOAuthURL(url string) {
	OAuthURL = url
}

// OAuthResponse represents the response from the token request
type OAuthResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    uint32 `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
	JTI          string `json:"jti,omitempty"`
}
