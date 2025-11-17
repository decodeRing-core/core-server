package vault

import (
	"context"

	"github.com/hashicorp/vault/api"
)

// VaultBackend is a secrets backend for HashiCorp Vault
type VaultBackend struct {
	client *api.Client
}

// NewVaultBackend creates a new Vault backend
func NewVaultBackend(addr, token string) (*VaultBackend, error) {
	config := &api.Config{
		Address: addr,
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}

	client.SetToken(token)

	return &VaultBackend{client: client}, nil
}

// GetSecret retrieves a secret from Vault
func (v *VaultBackend) GetSecret(mountPath, secretPath string) (map[string]interface{}, error) {
	secret, err := v.client.KVv2(mountPath).Get(context.Background(), secretPath)
	if err != nil {
		return nil, err
	}

	return secret.Data, nil
}

// PutSecret writes a secret to Vault
func (v *VaultBackend) PutSecret(mountPath, secretPath string, data map[string]interface{}) error {
	_, err := v.client.KVv2(mountPath).Put(context.Background(), secretPath, data)
	return err
}

// DeleteSecret deletes a secret from Vault
func (v *VaultBackend) DeleteSecret(mountPath, secretPath string) error {
	return v.client.KVv2(mountPath).Delete(context.Background(), secretPath)
}

// TaintSecret taints a secret in Vault by moving it to a tainted path
func (v *VaultBackend) TaintSecret(mountPath, secretPath string) error {
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

// UntaintSecret untaints a secret in Vault by moving it from a tainted path
func (v *VaultBackend) UntaintSecret(mountPath, secretPath string) error {
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
func (v *VaultBackend) Ping() error {
	_, err := v.client.Sys().Health()
	return err
}

// GetType returns the type of the backend
func (v *VaultBackend) GetType() string {
	return "vault"
}
