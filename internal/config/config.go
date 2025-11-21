package config

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// BackendConfig holds the configuration for a single backend
type BackendConfig struct {
	Name                string
	Type                string
	MountPath           string
	VaultAddr           string
	VaultToken          string
	BaoAddr             string
	BaoToken            string
	ConjurAddr          string
	ConjurAccount       string
	ConjurAdminKey      string
	NoSSLVerify         bool
	Region              string
	AWSAccessKeyID      string
	AWSSecretAccessKey  string
	AzureVaultURL       string
	AzureClientID       string
	AzureClientSecret   string
	AzureTenantID       string
}

// Config holds the application configuration
type Config struct {
	Backends             []BackendConfig
	DBUser           string
	DBPassword       string
	DBName           string
	DBHost           string
	DBPort           string
	DcdrPort         string
	UseSSL           bool
	SSLCertFile      string
	SSLKeyFile       string
	NoSSLVerify      bool
	DcdrUi           bool
	BackendConfigDir string
	AccessLog        string
	ErrorLog         string
	AuditEnabled      bool
	StagingPath      string
	AuditCleanupInterval time.Duration
	AuditRetention   time.Duration
}

// Load loads the configuration from environment variables
func Load(configFile string) *Config {
	err := godotenv.Overload(configFile)
	if err != nil {
		log.Printf("Warning: could not load config file %s, using environment variables", configFile)
	}

	cfg := &Config{
		DBUser:           getEnv("DB_USER", "user"),
		DBPassword:       getEnv("DB_PASSWORD", "password"),
		DBName:           getEnv("DB_NAME", "dcdr"),
		DBHost:           getEnv("DB_HOST", "localhost"),
		DBPort:           getEnv("DB_PORT", "5432"),
		DcdrPort:         getEnv("DCDR_PORT", "8080"),
		UseSSL:           getEnvAsBool("DCDR_USE_SSL", false),
		SSLCertFile:      getEnv("DCDR_SSL_CERT_FILE", ""),
		SSLKeyFile:       getEnv("DCDR_SSL_KEY_FILE", ""),
		NoSSLVerify:      getEnvAsBool("NO_TLS_VERIFY", false),
		DcdrUi:           getEnvAsBool("DCDR_UI", false),
		BackendConfigDir: getEnv("BACKEND_CONFIG_DIR", "config/backends.d"),
		AccessLog:        getEnv("ACCESS_LOG", "logs/access.log"),
		ErrorLog:         getEnv("ERROR_LOG", "logs/error.log"),
		AuditEnabled:     getEnvAsBool("AUDIT_ENABLED", false),
		StagingPath:      getEnv("STAGING_PATH", "/tmp/dcdr"),
		AuditCleanupInterval: getEnvAsDuration("AUDIT_CLEANUP_INTERVAL", "1h"),
		AuditRetention:   getEnvAsDuration("AUDIT_RETENTION", "0"),
	}

	backendFiles, err := filepath.Glob(filepath.Join(cfg.BackendConfigDir, "*.cfg"))
	if err != nil {
		log.Fatalf("Failed to read backend config files: %v", err)
	}

	for _, file := range backendFiles {
		env, err := godotenv.Read(file)
		if err != nil {
			log.Printf("Error loading backend config file %s: %v", file, err)
			continue
		}

		noSSLVerify, _ := strconv.ParseBool(env["NO_SSL_VERIFY"])
		cfg.Backends = append(cfg.Backends, BackendConfig{
			Name:           env["BACKEND_NAME"],
			Type:           env["BACKEND_TYPE"],
			MountPath:      env["MOUNT_PATH"],
			VaultAddr:      env["VAULT_ADDR"],
			VaultToken:     env["VAULT_TOKEN"],
			BaoAddr:        env["BAO_ADDR"],
			BaoToken:       env["BAO_TOKEN"],
			ConjurAddr:     env["CONJUR_ADDR"],
			ConjurAccount:  env["CONJUR_ACCOUNT"],
			ConjurAdminKey: env["CONJUR_ADMIN_KEY"],
			NoSSLVerify:    noSSLVerify,
			Region:             env["REGION"],
			AWSAccessKeyID:     env["AWS_ACCESS_KEY_ID"],
			AWSSecretAccessKey: env["AWS_SECRET_ACCESS_KEY"],
			AzureVaultURL:      env["AZURE_VAULT_URL"],
			AzureClientID:      env["AZURE_CLIENT_ID"],
			AzureClientSecret:  env["AZURE_CLIENT_SECRET"],
			AzureTenantID:      env["AZURE_TENANT_ID"],
		})
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// getEnvAsBool retrieves an environment variable as a boolean value.
func getEnvAsBool(name string, defaultVal bool) bool {
	valStr := getEnv(name, "")
	if val, err := strconv.ParseBool(valStr); err == nil {
		return val
	}
	return defaultVal
}

func getEnvAsDuration(name string, defaultVal string) time.Duration {
	valStr := getEnv(name, defaultVal)

	if valStr == "0" {
		return 0
	}

	// default to minutes if no unit is specified
	if _, err := strconv.Atoi(valStr); err == nil {
		valStr += "m"
	}

	d, err := time.ParseDuration(valStr)
	if err != nil {
		log.Printf("Invalid duration format for %s: %s. Using default: %s", name, valStr, defaultVal)
		d, _ = time.ParseDuration(defaultVal)
	}

	if name == "AUDIT_RETENTION" && d > 0 && d < 5*time.Minute {
		log.Printf("AUDIT_RETENTION is set to %s, which is less than the minimum of 5m. Defaulting to 5m.", valStr)
		return 5 * time.Minute
	}

	return d
}
