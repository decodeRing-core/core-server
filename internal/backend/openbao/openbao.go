package openbao

import (
	"context"

	baoapi "github.com/openbao/openbao/api/v2"
)

// OpenBaoBackend is a secrets backend for OpenBao
type OpenBaoBackend struct {
	client *baoapi.Client
}

// NewOpenBaoBackend creates a new OpenBao backend
func NewOpenBaoBackend(addr, token string) (*OpenBaoBackend, error) {
	config := &baoapi.Config{
		Address: addr,
	}

	client, err := baoapi.NewClient(config)
	if err != nil {
		return nil, err
	}

	client.SetToken(token)

	return &OpenBaoBackend{client: client}, nil
}

// GetSecret retrieves a secret from OpenBao
func (v *OpenBaoBackend) GetSecret(mountPath, secretPath string) (map[string]interface{}, error) {
	secret, err := v.client.KVv2(mountPath).Get(context.Background(), secretPath)
	if err != nil {
		return nil, err
	}

	return secret.Data, nil
}

// PutSecret writes a secret to OpenBao
func (v *OpenBaoBackend) PutSecret(mountPath, secretPath string, data map[string]interface{}) error {
	_, err := v.client.KVv2(mountPath).Put(context.Background(), secretPath, data)
	return err
}

// DeleteSecret deletes a secret from OpenBao
func (v *OpenBaoBackend) DeleteSecret(mountPath, secretPath string) error {
	return v.client.KVv2(mountPath).Delete(context.Background(), secretPath)
}

// TaintSecret taints a secret in OpenBao by moving it to a tainted path
func (v *OpenBaoBackend) TaintSecret(mountPath, secretPath string) error {
	secret, err := v.GetSecret(mountPath, secretPath)
	if err != nil {
		return err
	}

	taintedPath := "tainted/" + secretPath
	if err := v.PutSecret(mountPath, taintedPath, secret); err != nil {
		return err
	}

	return v.DeleteSecret(mountPath, secretPath)
}

// UntaintSecret untaints a secret in OpenBao by moving it from a tainted path
func (v *OpenBaoBackend) UntaintSecret(mountPath, secretPath string) error {
	taintedPath := "tainted/" + secretPath
	secret, err := v.GetSecret(mountPath, taintedPath)
	if err != nil {
		return err
	}

	if err := v.PutSecret(mountPath, secretPath, secret); err != nil {
		return err
	}

	return v.DeleteSecret(mountPath, taintedPath)
}

// Ping checks if the backend is reachable
func (v *OpenBaoBackend) Ping() error {
	_, err := v.client.Sys().Health()
	return err
}

// GetType returns the type of the backend
func (v *OpenBaoBackend) GetType() string {
	return "openbao"
}
