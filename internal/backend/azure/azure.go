package azure

import (
	"context"
	"fmt"
	"strings"
	"time"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// AzureKV is a backend for Azure Key Vault
type AzureKV struct {
	client   *azsecrets.Client
	vaultURL string
}

// New creates a new Azure Key Vault backend
func New(vaultURL, clientID, clientSecret, tenantID string) (*AzureKV, error) {
	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return &AzureKV{
		client:   client,
		vaultURL: vaultURL,
	}, nil
}

// GetSecret retrieves a secret from Azure Key Vault
func (a *AzureKV) GetSecret(mountPath, secretPath string) (map[string]interface{}, error) {
	secretName := secretPath
	resp, err := a.client.GetSecret(context.Background(), secretName, "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	return map[string]interface{}{
		secretName: *resp.Value,
	}, nil
}

// PutSecret creates or updates a secret in Azure Key Vault
func (a *AzureKV) PutSecret(mountPath, secretPath string, data map[string]interface{}) error {
	secretName := secretPath
	secretValue, ok := data["value"].(string)
	if !ok {
		return fmt.Errorf("value must be a string")
	}

	params := azsecrets.SetSecretParameters{
		Value: &secretValue,
	}
	_, err := a.client.SetSecret(context.Background(), secretName, params, nil)
	if err != nil {
		return fmt.Errorf("failed to set secret: %w", err)
	}

	return nil
}

// DeleteSecret deletes a secret from Azure Key Vault
func (a *AzureKV) DeleteSecret(mountPath, secretPath string) error {
	secretName := secretPath
	_, err := a.client.DeleteSecret(context.Background(), secretName, nil)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	time.Sleep(5 * time.Second)

	_, err = a.client.PurgeDeletedSecret(context.Background(), secretName, nil)
	if err != nil {
		return fmt.Errorf("failed to purge secret: %w", err)
	}

	return nil
}

// TaintSecret tags a secret in Azure Key Vault as tainted
func (a *AzureKV) TaintSecret(mountPath, secretPath string) error {
	secretName := secretPath
	getResp, err := a.client.GetSecret(context.Background(), secretName, "", nil)
	if err != nil {
		return fmt.Errorf("failed to get secret for tainting: %w", err)
	}

	id := *getResp.ID
	lastSlash := strings.LastIndex(string(id), "/")
	version := string(id)[lastSlash+1:]

	tags := getResp.Tags
	if tags == nil {
		tags = make(map[string]*string)
	}
	trueStr := "true"
	tags["dcdr-tainted"] = &trueStr

	params := azsecrets.UpdateSecretPropertiesParameters{
		Tags: tags,
	}

	_, err = a.client.UpdateSecretProperties(context.Background(), secretName, version, params, nil)
	if err != nil {
		return fmt.Errorf("failed to taint secret: %w", err)
	}

	return nil
}

// UntaintSecret removes the tainted tag from a secret in Azure Key Vault
func (a *AzureKV) UntaintSecret(mountPath, secretPath string) error {
	secretName := secretPath
	getResp, err := a.client.GetSecret(context.Background(), secretName, "", nil)
	if err != nil {
		return fmt.Errorf("failed to get secret for untainting: %w", err)
	}

	id := *getResp.ID
	lastSlash := strings.LastIndex(string(id), "/")
	version := string(id)[lastSlash+1:]

	tags := getResp.Tags
	if tags != nil {
		delete(tags, "dcdr-tainted")
	}

	params := azsecrets.UpdateSecretPropertiesParameters{
		Tags: tags,
	}

	_, err = a.client.UpdateSecretProperties(context.Background(), secretName, version, params, nil)
	if err != nil {
		return fmt.Errorf("failed to untaint secret: %w", err)
	}

	return nil
}

// Ping checks if the backend is available
func (a *AzureKV) Ping() error {
	// A simple way to check connectivity is to try to get a non-existent secret.
	// This is not ideal, but there is no dedicated ping method.
	_, err := a.client.GetSecret(context.Background(), "dcdr-ping", "", nil)
	if err != nil {
		// We expect a "NotFound" error, which means we are connected.
		// Any other error means we are not.
		// This is a bit of a hack, but it works.
		if err.Error() == "Request failed with status code: 404" {
			return nil
		}
		return fmt.Errorf("failed to ping Azure Key Vault: %w", err)
	}
	return nil
}

// GetType returns the type of the backend
func (a *AzureKV) GetType() string {
	return "azure"
}
