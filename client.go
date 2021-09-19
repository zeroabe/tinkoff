// Package tinkoff allows to send token-signed requests to Tinkoff Acquiring API and parse incoming HTTP notifications
package tinkoff

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
)

const (
	APIV2BaseURL = "https://securepay.tinkoff.ru/v2"
)

// Client is the main entity which execute request against the Tinkoff Acquiring API endpoint
type (
	Client interface {
		SetBaseURL(baseURL string)
		Init(request *InitRequest) (*InitResponse, error)
		ParseNotification(requestBody io.Reader) (*Notification, error)
		GetNotificationSuccessResponse() string
		GetState(request *GetStateRequest) (*GetStateResponse, error)
		//PostRequest(url string, request RequestInterface) (*http.Response, error)
		Resend() (*ResendResponse, error)
		Cancel(request *CancelRequest) (*CancelResponse, error)
		Confirm(request *ConfirmRequest) (*ConfirmResponse, error)
	}

	client struct {
		terminalKey string
		password    string
		baseURL     string
	}
)

// NewClient returns new Client instance
func NewClient(terminalKey, password string) Client {
	return &client{
		terminalKey: terminalKey,
		password:    password,
		baseURL:     APIV2BaseURL,
	}
}

// SetBaseURL allows to change default API endpoint
func (c *client) SetBaseURL(baseURL string) {
	c.baseURL = baseURL
}

func (c *client) decodeResponse(response *http.Response, result interface{}) error {
	return json.NewDecoder(response.Body).Decode(result)
}

// PostRequest will automatically sign the request with token
// Use BaseRequest type to implement any API request
func (c *client) PostRequest(url string, request RequestInterface) (*http.Response, error) {
	c.secureRequest(request)
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(c.baseURL+url, "application/json", bytes.NewReader(data))
	return resp, err
}

func (c *client) secureRequest(request RequestInterface) {
	request.SetTerminalKey(c.terminalKey)

	v := request.GetValuesForToken()
	v["TerminalKey"] = c.terminalKey
	v["Password"] = c.password
	request.SetToken(generateToken(v))
}

func generateToken(v map[string]string) string {
	keys := make([]string, 0)
	for key := range v {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for _, key := range keys {
		b.WriteString(v[key])
	}
	sum := sha256.Sum256(b.Bytes())
	return fmt.Sprintf("%x", sum)
}
