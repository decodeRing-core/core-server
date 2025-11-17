package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"dcdr.local/internal/api"
	"dcdr.local/internal/backend"
	"dcdr.local/internal/backend/aws"
	"dcdr.local/internal/backend/azure"
	"dcdr.local/internal/backend/conjur"
	"dcdr.local/internal/backend/openbao"
	"dcdr.local/internal/backend/vault"
	"dcdr.local/internal/config"
	"dcdr.local/internal/middleware"
	"dcdr.local/internal/ui"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	ginSwagger "github.com/swaggo/gin-swagger"
	swaggerFiles "github.com/swaggo/files"
	"embed"
	"io/fs"
	
)

//go:embed all:ui
var uiFS embed.FS

//go:embed api/swagger.yaml
var swaggerSpec []byte

func main() {
	ui.SetTemplates(uiFS)
	flag.Usage = func() {
		fmt.Println("Usage: dcdr-server [options] [command]")
		fmt.Println("\nOptions:")
		fmt.Println("  --config string   path to server config file (default \"config/server.cfg\")")
		fmt.Println("\nCommands:")
		fmt.Println("  generate-ssl [--out <path>]   Generate a self-signed SSL certificate")
		fmt.Println("  verify         Verify backend connections")
		fmt.Println("  help           Show this help message")
	}

	configPath := flag.String("config", "config/server.cfg", "path to server config file")
	flag.Parse()

	args := flag.Args()
	if len(args) > 0 {
		switch args[0] {
		case "generate-ssl":
			generateSSLCmd := flag.NewFlagSet("generate-ssl", flag.ExitOnError)
			outPath := generateSSLCmd.String("out", "config/ssl", "output path for generated files")
			generateSSLCmd.Parse(args[1:])
			generateSSL(*outPath)
			return
		case "verify":
			cfg := config.Load(*configPath)
			verifyBackends(cfg)
			return
		case "-h", "--help", "help":
			flag.Usage()
			return
		default:
			flag.Usage()
			return
		}
	}

	cfg := config.Load(*configPath)

	// Open the access log file
	if err := os.MkdirAll("logs", 0755); err != nil {
		log.Printf("Warning: could not create log directory: %v", err)
	}
	accessLog, err := os.OpenFile(cfg.AccessLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open access log file: %v", err)
	}
	defer accessLog.Close()
	accessLogger := log.New(accessLog, "", 0)

	db, err := sql.Open("postgres", fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBHost, cfg.DBPort))
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	hub := api.NewHub(db)
	go hub.Run()

	// Check if key shards exist
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM key_shards").Scan(&count)
	if err != nil {
		log.Fatalf("Failed to query key_shards table: %v", err)
	}

	if count == 0 {
		fmt.Println("First run detected. Generating key shards...")
		shards, err := generateAndStoreKeyShards(db)
		if err != nil {
			log.Fatalf("Failed to generate and store key shards: %v", err)
		}
		fmt.Println("Key shards generated and stored successfully.")
		fmt.Println("Please save these shards in a secure location:")
		for _, shard := range shards {
			fmt.Println(shard)
		}

		// Generate root token
		rootToken, err := generateRootToken(db, shards)
		if err != nil {
			log.Fatalf("Failed to generate root token: %v", err)
		}
		fmt.Println("Root token generated successfully.")
		fmt.Println("Please use this token for the root user:")
		fmt.Println(rootToken)
	}

	backends := make(map[string]backend.Backend)
	for _, backendCfg := range cfg.Backends {
		switch backendCfg.Type {
		case "vault":
			vaultBackend, err := vault.NewVaultBackend(backendCfg.VaultAddr, backendCfg.VaultToken)
			if err != nil {
				log.Printf("Failed to create Vault backend %s: %v", backendCfg.Name, err)
			} else {
				backends[backendCfg.Name] = vaultBackend
			}
		case "openbao":
			openBaoBackend, err := openbao.NewOpenBaoBackend(backendCfg.BaoAddr, backendCfg.BaoToken)
			if err != nil {
				log.Printf("Failed to create OpenBao backend %s: %v", backendCfg.Name, err)
			} else {
				backends[backendCfg.Name] = openBaoBackend
			}
		case "conjur":
			conjurBackend, err := conjur.New(backendCfg.ConjurAddr, backendCfg.ConjurAccount, backendCfg.ConjurAdminKey, backendCfg.NoSSLVerify)
			if err != nil {
				log.Printf("Failed to create Conjur backend %s: %v", backendCfg.Name, err)
			} else {
				backends[backendCfg.Name] = conjurBackend
			}
		case "aws":
			awsBackend, err := aws.NewAWSClient(backendCfg.Region, backendCfg.AWSAccessKeyID, backendCfg.AWSSecretAccessKey)
			if err != nil {
				log.Printf("Failed to create AWS backend %s: %v", backendCfg.Name, err)
			} else {
				backends[backendCfg.Name] = awsBackend
			}
		case "azure":
			azureBackend, err := azure.New(backendCfg.AzureVaultURL, backendCfg.AzureClientID, backendCfg.AzureClientSecret, backendCfg.AzureTenantID)
			if err != nil {
				log.Printf("Failed to create Azure backend %s: %v", backendCfg.Name, err)
			} else {
				backends[backendCfg.Name] = azureBackend
			}
		}
	}

	r := gin.Default()
	r.Use(middleware.Logger(accessLog, cfg.ErrorLog))
	if cfg.AuditEnabled {
		r.Use(middleware.AuditLogger(db, hub))
	}
	r.SetTrustedProxies([]string{"127.0.0.1"})

	// Serve the UI
	fs, err := fs.Sub(uiFS, "ui")
	if err != nil {
		log.Fatal(err)
	}
	r.StaticFS("/static", http.FS(fs))
	


	r.GET("/api/swagger.yaml", func(c *gin.Context) {
		c.Header("Content-Type", "application/x-yaml")
		c.String(http.StatusOK, string(swaggerSpec))
	})

	r.GET("/api-docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, ginSwagger.URL("/api/swagger.yaml")))
	r.GET("/api-docs", func(c *gin.Context) {
			c.Redirect(http.StatusMovedPermanently, "/api-docs/index.html")
		})

	ui.SetupRouter(r, cfg, db, backends)
	api.SetupRouter(r, cfg, db, backends, hub)

	addr := fmt.Sprintf(":%s", cfg.DcdrPort)

	tlsConfig := &tls.Config{}
	if cfg.UseSSL {
		cert, err := tls.LoadX509KeyPair(cfg.SSLCertFile, cfg.SSLKeyFile)
		if err != nil {
			log.Fatalf("Failed to load SSL certificate: %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if cfg.NoSSLVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	srv := &http.Server{
		Addr:      addr,
		Handler:   r,
		TLSConfig: tlsConfig,
	}

	go func() {
		// service connections
		if cfg.UseSSL {
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("listen: %s\n", err)
			}
		} else {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("listen: %s\n", err)
			}
		}
	}()

	log.Printf("Starting server on %s", addr)
	accessLogger.Printf("Server started at %s, listening on %s", time.Now().Format(time.RFC3339), addr)
	if cfg.AuditEnabled {
		accessLogger.Printf("Audit Logs Enabled")
		accessLogger.Printf("Audit Retention set to: %s", cfg.AuditRetention.String())
		go cleanupAuditLogs(db, cfg.AuditCleanupInterval, cfg.AuditRetention, accessLogger)
	}

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal, 1)
	// kill (no param) default send syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can't be caught, so don't need to add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Println("Shutting down server...")
	accessLogger.Printf("Server shutting down at %s due to signal %v", time.Now().Format(time.RFC3339), sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exiting")
}

func cleanupAuditLogs(db *sql.DB, interval time.Duration, retention time.Duration, accessLogger *log.Logger) {
	if retention == 0 {
		return // Keep logs indefinitely
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		accessLogger.Printf("STARTING Audit Log Cleanup at %s", time.Now().Format(time.RFC3339))
		cutoff := time.Now().Add(-retention)
		result, err := db.Exec("DELETE FROM audit_log WHERE timestamp < $1", cutoff)
		if err != nil {
			log.Printf("Failed to cleanup audit logs: %v", err)
			continue
		}
	
rowsAffected, _ := result.RowsAffected()
		accessLogger.Printf("COMPLETED Audit Log Cleanup at %s. %d audit log entries were expunged.", time.Now().Format(time.RFC3339), rowsAffected)
	}
}

func verifyBackends(cfg *config.Config) {
	fmt.Println("Verifying backend connections...")
	for _, backendCfg := range cfg.Backends {
		var backend backend.Backend
		var err error
		switch backendCfg.Type {
		case "vault":
			backend, err = vault.NewVaultBackend(backendCfg.VaultAddr, backendCfg.VaultToken)
		case "openbao":
			backend, err = openbao.NewOpenBaoBackend(backendCfg.BaoAddr, backendCfg.BaoToken)
		case "conjur":
			backend, err = conjur.New(backendCfg.ConjurAddr, backendCfg.ConjurAccount, backendCfg.ConjurAdminKey, backendCfg.NoSSLVerify)
		case "aws":
			backend, err = aws.NewAWSClient(backendCfg.Region, backendCfg.AWSAccessKeyID, backendCfg.AWSSecretAccessKey)
		case "azure":
			backend, err = azure.New(backendCfg.AzureVaultURL, backendCfg.AzureClientID, backendCfg.AzureClientSecret, backendCfg.AzureTenantID)
		default:
			fmt.Printf("Backend '%s': SKIPPED (unknown type '%s')\n", backendCfg.Name, backendCfg.Type)
			continue
		}

		if err != nil {
			fmt.Printf("Backend '%s': FAILED to create client - %v\n", backendCfg.Name, err)
			continue
		}

		if err := backend.Ping(); err != nil {
			fmt.Printf("Backend '%s': FAILED - %v\n", backendCfg.Name, err)
		} else {
			fmt.Printf("Backend '%s': OK\n", backendCfg.Name)
		}
	}
}

func generateAndStoreKeyShards(db *sql.DB) ([]string, error) {
	// For this example, we'll generate 3 simple "shards".
	// In a real application, you would use a proper secret sharing library.
	shards := make([]string, 3)
	for i := 0; i < 3; i++ {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		shards[i] = fmt.Sprintf("shard%d_%x", i+1, b)
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() // Rollback in case of error

	stmt, err := tx.Prepare("INSERT INTO key_shards (shard) VALUES ($1)")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	for _, shard := range shards {
		if _, err := stmt.Exec(shard); err != nil {
			return nil, err
		}
	}

	return shards, tx.Commit()
}

func generateRootToken(db *sql.DB, shards []string) (string, error) {
	// Combine shards to create a "master key".
	// This is a simplistic example.
	masterKey := ""
	for _, s := range shards {
		masterKey += s
	}

	// Create a token for the root user.
	token, err := generateRandomString(26)
	if err != nil {
		return "", err
	}

	// Store the token in the database for the root user.
	// First, check if the root user exists.
	var userID int
	err = db.QueryRow("SELECT id FROM users WHERE username = 'root'").Scan(&userID)
	if err == sql.ErrNoRows {
		// Create the root user if it doesn't exist.
		_, err = db.Exec("INSERT INTO users (username, email, password_hash, is_admin) VALUES ('root', 'root@localhost', '', true)")
		if err != nil {
			return "", err
		}
		err = db.QueryRow("SELECT id FROM users WHERE username = 'root'").Scan(&userID)
		if err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}

	// Store the token as an API key for the root user.
	_, err = db.Exec("INSERT INTO api_keys (user_id, api_key) VALUES ($1, $2)", userID, token)
	if err != nil {
		return "", err
	}

	return token, nil
}

func generateRandomString(length int) (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		result[i] = chars[num.Int64()]
	}
	return string(result), nil
}

func generateSSL(outPath string) {
	certPath := filepath.Join(outPath, "dcdr.crt")
	keyPath := filepath.Join(outPath, "dcdr.key")

	if err := os.MkdirAll(outPath, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"dcdr"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}


certOut, err := os.Create(certPath)
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.Create(keyPath)
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	fmt.Println("Self-signed SSL certificate and private key generated.")
	fmt.Println("Please update your config/server.cfg with the following lines:")


certAbsPath, _ := filepath.Abs(certPath)
	keyAbsPath, _ := filepath.Abs(keyPath)

	fmt.Printf("DCDR_USE_SSL=true\nDCDR_SSL_CERT_FILE=%s\nDCDR_SSL_KEY_FILE=%s\n", certAbsPath, keyAbsPath)
}
