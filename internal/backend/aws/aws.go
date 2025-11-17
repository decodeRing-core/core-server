package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// AWSClient represents the AWS Secrets Manager client
type AWSClient struct {
	Client *secretsmanager.Client
}

// NewAWSClient creates a new AWS Secrets Manager client
func NewAWSClient(region, accessKeyID, secretAccessKey string) (*AWSClient, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS config: %w", err)
	}

	return &AWSClient{
		Client: secretsmanager.NewFromConfig(cfg),
	}, nil
}

// GetSecret retrieves a secret from AWS Secrets Manager
func (c *AWSClient) GetSecret(mountPath, secretPath string) (map[string]interface{}, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretPath),
	}

	result, err := c.Client.GetSecretValue(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret value: %w", err)
	}

	var secretData map[string]interface{}
	if err := json.Unmarshal([]byte(*result.SecretString), &secretData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret string: %w", err)
	}

	return secretData, nil
}

// PutSecret creates or updates a secret in AWS Secrets Manager
func (c *AWSClient) PutSecret(mountPath, secretPath string, data map[string]interface{}) error {
	secretBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal secret data: %w", err)
	}

	// Check if the secret exists
	_, err = c.Client.DescribeSecret(context.TODO(), &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretPath),
	})

	if err != nil {
		// Secret does not exist, create it
		createInput := &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretPath),
			SecretString: aws.String(string(secretBytes)),
		}
		_, createErr := c.Client.CreateSecret(context.TODO(), createInput)
		if createErr != nil {
			return fmt.Errorf("failed to create secret: %w", createErr)
		}
	} else {
		// Secret exists, update it
		putInput := &secretsmanager.PutSecretValueInput{
			SecretId:     aws.String(secretPath),
			SecretString: aws.String(string(secretBytes)),
		}
		_, putErr := c.Client.PutSecretValue(context.TODO(), putInput)
		if putErr != nil {
			return fmt.Errorf("failed to put secret value: %w", putErr)
		}
	}

	return nil
}

// DeleteSecret deletes a secret from AWS Secrets Manager.
func (c *AWSClient) DeleteSecret(mountPath, secretPath string) error {
	input := &secretsmanager.DeleteSecretInput{
		SecretId: aws.String(secretPath),
	}

	_, err := c.Client.DeleteSecret(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	return nil
}

// TaintSecret adds a tag to the secret to mark it as tainted.
func (c *AWSClient) TaintSecret(mountPath, secretPath string) error {
	input := &secretsmanager.TagResourceInput{
		SecretId: aws.String(secretPath),
		Tags: []types.Tag{
			{
				Key:   aws.String("dcdr-tainted"),
				Value: aws.String("true"),
			},
		},
	}

	_, err := c.Client.TagResource(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to tag secret: %w", err)
	}

	return nil
}

// UntaintSecret removes the tainted tag from the secret.
func (c *AWSClient) UntaintSecret(mountPath, secretPath string) error {
	input := &secretsmanager.UntagResourceInput{
		SecretId: aws.String(secretPath),
		TagKeys:  []string{"dcdr-tainted"},
	}

	_, err := c.Client.UntagResource(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to untag secret: %w", err)
	}

	return nil
}

// Ping checks if the AWS Secrets Manager is accessible
func (c *AWSClient) Ping() error {
	// The DescribeRegions call is a simple, low-cost way to verify credentials and connectivity.
	_, err := c.Client.ListSecrets(context.TODO(), &secretsmanager.ListSecretsInput{MaxResults: aws.Int32(1)})
	if err != nil {
		return fmt.Errorf("failed to ping AWS Secrets Manager: %w", err)
	}
	return nil
}

// GetType returns the type of the backend
func (c *AWSClient) GetType() string {
	return "aws"
}
