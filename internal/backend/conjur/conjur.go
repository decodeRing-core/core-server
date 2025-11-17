package conjur

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Conjur is a backend for CyberArk Conjur
type Conjur struct {
	Address     string
	Account     string
	AdminKey    string
	NoSSLVerify bool
	client      *http.Client
}

// New creates a new Conjur backend
func New(address, account, adminKey string, noSSLVerify bool) (*Conjur, error) {
	transport := &http.Transport{}
	if noSSLVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Conjur{
		Address:     address,
		Account:     account,
		AdminKey:    adminKey,
		NoSSLVerify: noSSLVerify,
		client:      &http.Client{Transport: transport},
	}, nil
}

func (c *Conjur) getAccessToken() (string, error) {
	url := fmt.Sprintf("%s/authn/%s/admin/authenticate", c.Address, c.Account)
	body := strings.NewReader(c.AdminKey)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("User-Agent", "dcdr")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	buf := new(strings.Builder)
	if _, err := io.Copy(buf, resp.Body); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// GetSecret retrieves a secret from Conjur
func (c *Conjur) GetSecret(mountPath, secretPath string) (map[string]interface{}, error) {
	token, err := c.getAccessToken()
	if err != nil {
		return nil, err
	}

	// The secret ID must be in the format: <account>:<kind>:<id>
	// We'll use the mountPath as the account and the secretPath as the id.
	secretID := fmt.Sprintf("%s:variable:%s", mountPath, secretPath)

	// The URL is for the secrets endpoint.
	url := fmt.Sprintf("%s/secrets/%s/values/latest", c.Address, secretID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Token token=\"%s\"", base64.StdEncoding.EncodeToString([]byte(token))))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	buf := new(strings.Builder)
	if _, err := io.Copy(buf, resp.Body); err != nil {
		return nil, err
	}

	return map[string]interface{}{"secret": buf.String()}, nil
}

// PutSecret creates or updates a secret in Conjur
func (c *Conjur) PutSecret(mountPath, secretPath string, data map[string]interface{}) error {
	token, err := c.getAccessToken()
	if err != nil {
		return err
	}

	// In Conjur, secrets are created as variables. The secret path is the variable ID.
	// The data is a map, but Conjur only stores a single value for a secret.
	// We'll take the first value from the map and use that as the secret.
	var secretValue string
	for _, v := range data {
		secretValue = fmt.Sprintf("%v", v)
		break
	}

	// The secret ID must be in the format: <account>:<kind>:<id>
	// We'll use the mountPath as the account and the secretPath as the id.
	secretID := fmt.Sprintf("%s:variable:%s", mountPath, secretPath)

	// The request body is the secret value.
	body := strings.NewReader(secretValue)

	// The URL is for the secrets endpoint.
	url := fmt.Sprintf("%s/secrets/%s/values", c.Address, secretID)

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Authorization", fmt.Sprintf("Token token=\"%s\"", base64.StdEncoding.EncodeToString([]byte(token))))

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// DeleteSecret deletes a secret from Conjur
func (c *Conjur) DeleteSecret(mountPath, secretPath string) error {
	return c.PutSecret(mountPath, secretPath, map[string]interface{}{"secret": ""})
}

// TaintSecret taints a secret in Conjur
func (c *Conjur) TaintSecret(mountPath, secretPath string) error {
	secret, err := c.GetSecret(mountPath, secretPath)
	if err != nil {
		return err
	}

	taintedPath := secretPath + ".tainted"
	if err := c.PutSecret(mountPath, taintedPath, secret); err != nil {
		return err
	}

	return c.DeleteSecret(mountPath, secretPath)
}

// UntaintSecret untaints a secret in Conjur
func (c *Conjur) UntaintSecret(mountPath, secretPath string) error {
	taintedPath := secretPath + ".tainted"
	secret, err := c.GetSecret(mountPath, taintedPath)
	if err != nil {
		return err
	}

	if err := c.PutSecret(mountPath, secretPath, secret); err != nil {
		return err
	}

	return c.DeleteSecret(mountPath, taintedPath)
}

func (c *Conjur) Ping() error {
	req, err := http.NewRequest("GET", c.Address, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if !strings.Contains(string(body), "Your Conjur server is running!") {
		return fmt.Errorf("unexpected response body: %s", string(body))
	}

	return nil
}

// GetType returns the type of the backend
func (c *Conjur) GetType() string {
	return "conjur"
}
