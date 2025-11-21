package api

import (
	"database/sql"
	"dcdr.local/internal/config"
	"fmt"
	"net/http"
	"strings"
	"os"
	"path/filepath"
	"archive/zip"
	"encoding/csv"
	"encoding/json"
	"github.com/google/uuid"
	"time"
	"log"
	"io"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"dcdr.local/internal/backend"
)

func auditWrapper(action string, handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("audit_action", action)
		handler(c)
	}
}

// AppRegistrationRequest is the request to register an application
type AppRegistrationRequest struct {
	AppName string `json:"app_name"`
}

// SecretCreationRequest is the request to create a secret
type SecretCreationRequest struct {
	AppID      string                 `json:"app_id"`
	SecretName string                 `json:"secret_name"`
	Backend    string                 `json:"backend"`
	MountPath  string                 `json:"mount_path"`
	Data       map[string]interface{} `json:"data"`
}

// SecretRequest is the request for secret operations
type SecretRequest struct {
	AppID      string `json:"app_id"`
	SecretName string `json:"secret_name"`
}

func AuthMiddleware(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for an active session first
		session := sessions.Default(c)
		sessionUserID := session.Get("userID")

		if sessionUserID != nil {
			c.Set("userID", sessionUserID)
			c.Set("is_root", session.Get("isRoot"))
			c.Next()
			return
		}

		// Fallback to token-based authentication
		var token string
		cookieToken, _ := c.Cookie("dcdr-session")
		token = cookieToken

		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			var bearerToken string
			if _, err := fmt.Sscanf(authHeader, "Bearer %s", &bearerToken); err == nil {
				token = bearerToken
			}
		}

		// For websocket connections, the token may be passed as a query parameter
		if token == "" && c.Request.URL.Path == "/api/dcdrAudit/stream" {
			token = c.Query("token")
		}

		if token == "" {
			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			} else {
				c.Redirect(http.StatusFound, "/login")
			}
			c.Abort()
			return
		}

		// Check for root user
		var userID int
		err := db.QueryRow("SELECT user_id FROM api_keys WHERE api_key = $1", token).Scan(&userID)
		if err == nil {
			c.Set("userID", userID)
			c.Set("is_root", true)
			c.Next()
			return
		}
		if err != sql.ErrNoRows {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// Check for application user
		var appUserID, appID string
		var status string
		err = db.QueryRow("SELECT user_id, app_id, status FROM application_users WHERE token = $1", token).Scan(&appUserID, &appID, &status)
		if err != nil {
			if err == sql.ErrNoRows {
				if strings.HasPrefix(c.Request.URL.Path, "/api/") {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				} else {
					c.Redirect(http.StatusFound, "/login")
				}
				c.Abort()
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		if status != "active" {
			c.JSON(http.StatusForbidden, gin.H{"error": "user is not active"})
			c.Abort()
			return
		}

		c.Set("userID", appUserID)
		c.Set("appID", appID)
		c.Set("is_root", false)
		c.Next()
	}
}

// SetupRouter sets up the Gin router
func SetupRouter(r *gin.Engine, cfg *config.Config, db *sql.DB, backends map[string]backend.Backend, hub *Hub) {
	api := r.Group("/api")
	{
		// Health check
		api.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		// Unauthenticated API routes
		api.POST("/dcdrAuth", auditWrapper("dcdrAuth", dcdrAuth(db)))
		api.GET("/dcdrIdent", dcdrIdent)
		

		authed := api.Group("/")
		authed.Use(AuthMiddleware(db))
		{
			authed.POST("/dcdrRegister", auditWrapper("dcdrRegister", dcdrRegister(db)))
			authed.POST("/dcdrCreateSecret", auditWrapper("dcdrCreateSecret", DcdrCreateSecret(cfg, db, backends)))
			authed.POST("/dcdrGet", auditWrapper("dcdrGet", DcdrGet(cfg, db, backends)))
			authed.POST("/dcdrTaint", auditWrapper("dcdrTaint", dcdrTaint(db, backends)))
			authed.POST("dcdrUntaint", auditWrapper("dcdrUntaint", dcdrUntaint(db, backends)))
			authed.POST("/dcdrDestroy", auditWrapper("dcdrDestroy", dcdrDestroy(cfg, db, backends)))
			authed.POST("/dcdrIsTainted", auditWrapper("dcdrIsTainted", dcdrIsTainted(db, backends)))
			authed.POST("/dcdrRotate", auditWrapper("dcdrRotate", dcdrRotate(db, backends)))
			authed.GET("/dcdrListApps", auditWrapper("dcdrListApps", dcdrListApps(db)))
			authed.POST("/dcdrListSecrets", auditWrapper("dcdrListSecrets", dcdrListSecrets(db)))
			authed.GET("/dcdrListBackends", auditWrapper("dcdrListBackends", dcdrListBackends(cfg, db)))
			authed.POST("/dcdrDeleteApp", auditWrapper("dcdrDeleteApp", dcdrDeleteApp(db)))
			authed.GET("/dcdrWhoami", auditWrapper("dcdrWhoami", dcdrWhoami(db)))
			authed.GET("/dcdrAudit/download", auditWrapper("downloadAuditLog", downloadAuditLog(db, cfg)))
			authed.GET("/dcdrAudit/stream", auditWrapper("streamAuditLog", streamAuditLog(hub)))

			appUser := authed.Group("/dcdrAppUser")
			{
				appUser.POST("/create", auditWrapper("createAppUser", CreateAppUser(db)))
				appUser.GET("/list", auditWrapper("listAppUsers", ListAppUsers(db)))
				appUser.POST("/suspend", auditWrapper("suspendAppUser", SuspendAppUser(db)))
				appUser.POST("/unsuspend", auditWrapper("unsuspendAppUser", UnsuspendAppUser(db)))
				appUser.POST("/delete", auditWrapper("deleteAppUser", DeleteAppUser(db)))
				appUser.POST("/getToken", auditWrapper("getAppUserToken", GetAppUserToken(db)))
			}

			ui := authed.Group("/ui")
			{
				ui.GET("/backends", auditWrapper("listBackendsUI", dcdrListBackendsUI(cfg, db)))
				ui.GET("/applications", auditWrapper("listAppsUI", dcdrListApps(db)))
				ui.GET("/applications/:id/secrets", auditWrapper("listSecretsUI", dcdrListSecrets(db)))
				
				ui.GET("/user", auditWrapper("whoamiUI", dcdrWhoamiUI(db)))
			}
			authed.POST("/logout", auditWrapper("logout", dcdrLogout))
		}
	}
}

func dcdrAuth(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Set("denied", true)
			c.Set("reason", "authorization header required")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header required"})
			return
		}

		token := ""
		if _, err := fmt.Sscanf(authHeader, "Bearer %s", &token); err != nil {
			c.Set("denied", true)
			c.Set("reason", "invalid token format")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token format"})
			return
		}

		// Check if the token is valid (either root or application user)
		var userID int
		err := db.QueryRow("SELECT user_id FROM api_keys WHERE api_key = $1", token).Scan(&userID)
		if err != nil && err != sql.ErrNoRows {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if err == sql.ErrNoRows {
			var appUserID string
			var status string
			err = db.QueryRow("SELECT user_id, status FROM application_users WHERE token = $1", token).Scan(&appUserID, &status)
			if err != nil {
				c.Set("denied", true)
				c.Set("reason", "invalid token")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
				return
			}
			if status != "active" {
				c.Set("denied", true)
				c.Set("reason", "user is not active")
				c.JSON(http.StatusForbidden, gin.H{"error": "user is not active"})
				return
			}
		}

		log.Printf("token: %s", token)
		//log.Printf("cookie: %s", cookieToken)
		log.Printf("authHeader: %s", authHeader)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

type AppDeleteRequest struct {
	AppID string `json:"app_id"`
}

func dcdrDeleteApp(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			c.Set("denied", true)
			c.Set("reason", "Permission Denied")
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission Denied"})
			return
		}
		var req AppDeleteRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Check if there are any secrets associated with the app
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM secret_backend_mapping WHERE app_id = $1", req.AppID).Scan(&count)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if count > 0 {
			c.Set("denied", true)
			c.Set("reason", "cannot delete app with associated secrets")
			c.JSON(http.StatusConflict, gin.H{"error": "cannot delete app with associated secrets"})
			return
		}

		// Delete the app
		_, err = db.Exec("DELETE FROM applications WHERE app_id = $1", req.AppID)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.Set("denied", false)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func dcdrRegister(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			c.Set("denied", true)
			c.Set("reason", "Permission Denied")
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission Denied"})
			return
		}
		var req AppRegistrationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var appID string
		// Check if the app already exists
		err := db.QueryRow("SELECT app_id FROM applications WHERE app_name = $1", req.AppName).Scan(&appID)
		if err != nil && err != sql.ErrNoRows {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// If the app exists, return the existing app_id
		if err == nil {
			c.Set("denied", false)
			c.JSON(http.StatusOK, gin.H{"app_id": appID})
			return
		}

		// If the app does not exist, create it
		err = db.QueryRow("INSERT INTO applications (app_name) VALUES ($1) RETURNING app_id", req.AppName).Scan(&appID)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.Set("denied", false)
		c.JSON(http.StatusOK, gin.H{"app_id": appID})
	}
}

func CreateSecretLogic(req SecretCreationRequest, cfg *config.Config, db *sql.DB, backends map[string]backend.Backend) error {
	var backendCfg *config.BackendConfig
	for i := range cfg.Backends {
		if cfg.Backends[i].Name == req.Backend {
			backendCfg = &cfg.Backends[i]
			break
		}
	}

	if backendCfg == nil {
		return &APIError{StatusCode: http.StatusBadRequest, Message: "backend not found"}
	}

	backend, ok := backends[backendCfg.Name]
	if !ok {
		// This should not happen if backendCfg is found
		return &APIError{StatusCode: http.StatusInternalServerError, Message: "internal server error: backend mismatch"}
	}

	secretPath := req.SecretName
	if backendCfg.Type == "vault" {
		secretPath = fmt.Sprintf("data/%s/%s", req.AppID, req.SecretName)
	} else if backendCfg.Type == "azure" {
		secretPath = fmt.Sprintf("%s-%s", req.AppID, req.SecretName)
	} else {
		secretPath = fmt.Sprintf("data/%s/%s", req.AppID, req.SecretName)
	}
	err := backend.PutSecret(req.MountPath, secretPath, req.Data)
	if err != nil {
		return &APIError{StatusCode: http.StatusInternalServerError, Message: fmt.Sprintf("error writing secret to %s: %s", backendCfg.Name, err.Error())}
	}

	_, err = db.Exec("INSERT INTO secret_backend_mapping (app_id, secret_name, backend, mount_path) VALUES ($1, $2, $3, $4) ON CONFLICT(app_id, secret_name) DO UPDATE SET backend = $3, mount_path = $4, updated_at = NOW()", req.AppID, req.SecretName, backendCfg.Name, req.MountPath)
	if err != nil {
		return &APIError{StatusCode: http.StatusInternalServerError, Message: err.Error()}
	}

	return nil
}

func DcdrCreateSecret(cfg *config.Config, db *sql.DB, backends map[string]backend.Backend) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SecretCreationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			appID, _ := c.Get("appID")
			if req.AppID != appID.(string) {
				c.Set("denied", true)
				c.Set("reason", "Permission Denied")
				c.JSON(http.StatusForbidden, gin.H{"error": "Permission Denied"})
				return
			}
		}

		err := CreateSecretLogic(req, cfg, db, backends)
		if err != nil {
			if apiErr, ok := err.(*APIError); ok {
				c.Set("denied", true)
				c.Set("reason", apiErr.Message)
				c.JSON(apiErr.StatusCode, gin.H{"error": apiErr.Message})
			} else {
				c.Set("denied", true)
				c.Set("reason", err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			}
			return
		}

		c.Set("denied", false)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

// APIError represents an error with an associated HTTP status code.

type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return e.Message
}

// GetSecretLogic contains the business logic for retrieving a secret.
func GetSecretLogic(appID, secretName string, cfg *config.Config, db *sql.DB, backends map[string]backend.Backend) (map[string]interface{}, error) {
	var backendName, mountPath string
	var tainted bool
	err := db.QueryRow("SELECT backend, mount_path, tainted FROM secret_backend_mapping WHERE app_id = $1 AND secret_name = $2", appID, secretName).Scan(&backendName, &mountPath, &tainted)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, &APIError{StatusCode: http.StatusNotFound, Message: "secret not found"}
		}
		return nil, &APIError{StatusCode: http.StatusInternalServerError, Message: err.Error()}
	}

	if tainted {
		return nil, &APIError{StatusCode: http.StatusForbidden, Message: "secret is tainted"}
	}

	var backendCfg *config.BackendConfig
	for i := range cfg.Backends {
		if cfg.Backends[i].Name == backendName {
			backendCfg = &cfg.Backends[i]
			break
		}
	}

	if backendCfg == nil {
		return nil, &APIError{StatusCode: http.StatusInternalServerError, Message: "backend configuration not found for secret"}
	}

	backend, ok := backends[backendName]
	if !ok {
		return nil, &APIError{StatusCode: http.StatusInternalServerError, Message: "backend not found"}
	}

	secretPath := secretName
	if backendCfg.Type == "vault" {
		secretPath = fmt.Sprintf("data/%s/%s", appID, secretName)
	} else if backendCfg.Type == "azure" {
		secretPath = fmt.Sprintf("%s-%s", appID, secretName)
	} else {
		    secretPath = fmt.Sprintf("data/%s/%s", appID, secretName)
	}
	secret, err := backend.GetSecret(mountPath, secretPath)
	if err != nil {
		return nil, &APIError{StatusCode: http.StatusInternalServerError, Message: err.Error()}
	}

	return secret, nil
}

func DcdrGet(cfg *config.Config, db *sql.DB, backends map[string]backend.Backend) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SecretRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			appID, _ := c.Get("appID")
			if req.AppID != appID.(string) {
				c.Set("denied", true)
				c.Set("reason", "Permission Denied")
				c.JSON(http.StatusForbidden, gin.H{"error": "Permission Denied"})
				return
			}
		}

		secret, err := GetSecretLogic(req.AppID, req.SecretName, cfg, db, backends)
		if err != nil {
			if apiErr, ok := err.(*APIError); ok {
				c.Set("denied", true)
				c.Set("reason", apiErr.Message)
				c.JSON(apiErr.StatusCode, gin.H{"error": apiErr.Message})
			} else {
				c.Set("denied", true)
				c.Set("reason", err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			}
			return
		}

		c.Set("denied", false)
		c.JSON(http.StatusOK, secret)
	}
}

func dcdrTaint(db *sql.DB, backends map[string]backend.Backend) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SecretRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			appID, _ := c.Get("appID")
			if req.AppID != appID.(string) {
				c.Set("denied", true)
				c.Set("reason", "Permission Denied")
				c.JSON(http.StatusForbidden, gin.H{"error": "Permission Denied"})
				return
			}
		}

		var backendName, mountPath string
		err := db.QueryRow("SELECT backend, mount_path FROM secret_backend_mapping WHERE app_id = $1 AND secret_name = $2", req.AppID, req.SecretName).Scan(&backendName, &mountPath)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", "secret not found")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "secret not found"})
			return
		}

		backend, ok := backends[backendName]
		if !ok {
			c.Set("denied", true)
			c.Set("reason", "backend not found")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "backend not found"})
			return
		}

		secretPath := req.SecretName
		if backend.GetType() == "vault" {
			secretPath = fmt.Sprintf("data/%s/%s", req.AppID, req.SecretName)
		} else if backend.GetType() == "azure" {
			secretPath = fmt.Sprintf("%s-%s", req.AppID, req.SecretName)
		} else {
			secretPath = fmt.Sprintf("data/%s/%s", req.AppID, req.SecretName)
		}
		if err := backend.TaintSecret(mountPath, secretPath); err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		_, err = db.Exec("UPDATE secret_backend_mapping SET tainted = TRUE, updated_at = NOW() WHERE app_id = $1 AND secret_name = $2", req.AppID, req.SecretName)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.Set("denied", false)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func dcdrUntaint(db *sql.DB, backends map[string]backend.Backend) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SecretRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			appID, _ := c.Get("appID")
			if req.AppID != appID.(string) {
				c.Set("denied", true)
				c.Set("reason", "Permission Denied")
				c.JSON(http.StatusForbidden, gin.H{"error": "Permission Denied"})
				return
			}
		}

		var backendName, mountPath string
		err := db.QueryRow("SELECT backend, mount_path FROM secret_backend_mapping WHERE app_id = $1 AND secret_name = $2", req.AppID, req.SecretName).Scan(&backendName, &mountPath)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", "secret not found")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "secret not found"})
			return
		}

		backend, ok := backends[backendName]
		if !ok {
			c.Set("denied", true)
			c.Set("reason", "backend not found")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "backend not found"})
			return
		}

		secretPath := req.SecretName
		if backend.GetType() == "vault" {
			secretPath = fmt.Sprintf("data/%s/%s", req.AppID, req.SecretName)
		} else if backend.GetType() == "azure" {
			secretPath = fmt.Sprintf("%s-%s", req.AppID, req.SecretName)
		} else {
			secretPath = fmt.Sprintf("data/%s/%s", req.AppID, req.SecretName)
		}
		if err := backend.UntaintSecret(mountPath, secretPath); err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		_, err = db.Exec("UPDATE secret_backend_mapping SET tainted = FALSE, updated_at = NOW() WHERE app_id = $1 AND secret_name = $2", req.AppID, req.SecretName)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.Set("denied", false)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func dcdrDestroy(cfg *config.Config, db *sql.DB, backends map[string]backend.Backend) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SecretRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			appID, _ := c.Get("appID")
			if req.AppID != appID.(string) {
				c.Set("denied", true)
				c.Set("reason", "Permission Denied")
				c.JSON(http.StatusForbidden, gin.H{"error": "Permission Denied"})
				return
			}
		}

		var backendName, mountPath string
		err := db.QueryRow("SELECT backend, mount_path FROM secret_backend_mapping WHERE app_id = $1 AND secret_name = $2", req.AppID, req.SecretName).Scan(&backendName, &mountPath)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", "secret not found")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "secret not found"})
			return
		}

		var backendCfg *config.BackendConfig
		for i := range cfg.Backends {
			if cfg.Backends[i].Name == backendName {
				backendCfg = &cfg.Backends[i]
				break
			}
		}

		if backendCfg == nil {
			c.Set("denied", true)
			c.Set("reason", "backend configuration not found for secret")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "backend configuration not found for secret"})
			return
		}

		backend, ok := backends[backendName]
		if !ok {
			c.Set("denied", true)
			c.Set("reason", "backend not found")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "backend not found"})
			return
		}

		secretPath := req.SecretName
		if backendCfg.Type == "vault" {
			secretPath = fmt.Sprintf("data/%s/%s", req.AppID, req.SecretName)
		} else if backendCfg.Type == "azure" {
			secretPath = fmt.Sprintf("%s-%s", req.AppID, req.SecretName)
		} else {
			secretPath = fmt.Sprintf("data/%s/%s", req.AppID, req.SecretName)
		}
		err = backend.DeleteSecret(mountPath, secretPath)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		_, err = db.Exec("DELETE FROM secret_backend_mapping WHERE app_id = $1 AND secret_name = $2", req.AppID, req.SecretName)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.Set("denied", false)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func dcdrIsTainted(db *sql.DB, backends map[string]backend.Backend) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SecretRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var tainted bool
		err := db.QueryRow("SELECT tainted FROM secret_backend_mapping WHERE app_id = $1 AND secret_name = $2", req.AppID, req.SecretName).Scan(&tainted)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", "secret not found")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "secret not found"})
			return
		}

		c.Set("denied", false)
		c.JSON(http.StatusOK, gin.H{"tainted": tainted})
	}
}

func dcdrIdent(c *gin.Context) {
	// In a real implementation, this would be a more persistent instance ID
	c.JSON(http.StatusOK, gin.H{"instance_id": "dummy-instance-id"})
}

func dcdrRotate(db *sql.DB, backends map[string]backend.Backend) gin.HandlerFunc {
	return func(c *gin.Context) {
		// In a real implementation, this would involve generating a new secret
		// and writing it to the backend.
		c.Set("denied", true)
		c.Set("reason", "not implemented")
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
	}
}

func dcdrListApps(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			appID, _ := c.Get("appID")
			rows, err := db.Query("SELECT app_id, app_name FROM applications WHERE app_id = $1", appID)
			if err != nil {
				c.Set("denied", true)
				c.Set("reason", err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			defer rows.Close()

			apps := make([]map[string]string, 0)
			for rows.Next() {
				var appID, appName string
				if err := rows.Scan(&appID, &appName); err != nil {
					c.Set("denied", true)
					c.Set("reason", err.Error())
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				apps = append(apps, map[string]string{"app_id": appID, "app_name": appName})
			}

			c.Set("denied", false)
			c.JSON(http.StatusOK, apps)
			return
		}

		rows, err := db.Query("SELECT app_id, app_name FROM applications")
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		apps := make([]map[string]string, 0)
		for rows.Next() {
			var appID, appName string
			if err := rows.Scan(&appID, &appName); err != nil {
				c.Set("denied", true)
				c.Set("reason", err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			apps = append(apps, map[string]string{"app_id": appID, "app_name": appName})
		}

		c.Set("denied", false)
		c.JSON(http.StatusOK, apps)
	}
}

func dcdrWhoami(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		isRoot, _ := c.Get("is_root")
		if isRoot.(bool) {
			userID, _ := c.Get("userID")
			c.Set("denied", false)
			c.JSON(http.StatusOK, gin.H{"user_id": userID, "user_name": "root", "is_root": true})
			return
		}

		userID, _ := c.Get("userID")
		appID, _ := c.Get("appID")

		var userName, appName string
		err := db.QueryRow("SELECT user_name FROM application_users WHERE user_id = $1", userID).Scan(&userName)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		err = db.QueryRow("SELECT app_name FROM applications WHERE app_id = $1", appID).Scan(&appName)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.Set("denied", false)
		c.JSON(http.StatusOK, gin.H{"user_id": userID, "user_name": userName, "app_id": appID, "app_name": appName, "is_root": false})
	}
}

func dcdrWhoamiUI(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		isRoot, _ := c.Get("is_root")
		if isRoot.(bool) {
			userID, _ := c.Get("userID")
			c.Set("denied", false)
			c.JSON(http.StatusOK, gin.H{"user_id": userID, "user_name": "root", "is_root": true})
			return
		}

		userID, _ := c.Get("userID")
		appID, _ := c.Get("appID")

		var userName, appName string
		err := db.QueryRow("SELECT user_name FROM application_users WHERE user_id = $1", userID).Scan(&userName)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		err = db.QueryRow("SELECT app_name FROM applications WHERE app_id = $1", appID).Scan(&appName)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.Set("denied", false)
		c.JSON(http.StatusOK, gin.H{"user_id": userID, "user_name": userName, "app_id": appID, "app_name": appName, "is_root": false})
	}
}

func dcdrListBackends(cfg *config.Config, db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		backends := make([]map[string]interface{}, 0)
		for _, backendCfg := range cfg.Backends {
			var numApplications, numSecrets int
			db.QueryRow(`
				SELECT COUNT(DISTINCT app_id), COUNT(*)
				FROM secret_backend_mapping
				WHERE backend = $1
			`, backendCfg.Name).Scan(&numApplications, &numSecrets)

			backends = append(backends, map[string]interface{}{
				"backend":          backendCfg.Name,
				"num_applications": numApplications,
				"num_secrets":      numSecrets,
				"type":             backendCfg.Type,
			})
		}

		c.Set("denied", false)
		c.JSON(http.StatusOK, backends)
	}
}

func dcdrListBackendsUI(cfg *config.Config, db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		backends := make([]map[string]interface{}, 0)
		for _, backendCfg := range cfg.Backends {
			var numApplications, numSecrets int
			db.QueryRow(`
				SELECT COUNT(DISTINCT app_id), COUNT(*)
				FROM secret_backend_mapping
				WHERE backend = $1
			`, backendCfg.Name).Scan(&numApplications, &numSecrets)

			var addr string
			switch backendCfg.Type {
			case "vault":
				addr = backendCfg.VaultAddr
			case "openbao":
				addr = backendCfg.BaoAddr
			}

			backends = append(backends, map[string]interface{}{
				"backend":          backendCfg.Name,
				"num_applications": numApplications,
				"num_secrets":      numSecrets,
				"addr":             addr,
				"type":             backendCfg.Type,
			})
		}

		c.Set("denied", false)
		c.JSON(http.StatusOK, backends)
	}
}

func dcdrListSecrets(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			appID, _ := c.Get("appID")
			rows, err := db.Query("SELECT secret_name, backend, mount_path, tainted FROM secret_backend_mapping WHERE app_id = $1", appID)
			if err != nil {
				c.Set("denied", true)
				c.Set("reason", err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			defer rows.Close()

			secrets := make([]map[string]interface{}, 0)
			for rows.Next() {
				var secretName, backend, mountPath string
				var tainted bool
				if err := rows.Scan(&secretName, &backend, &mountPath, &tainted); err != nil {
					c.Set("denied", true)
					c.Set("reason", err.Error())
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				secrets = append(secrets, map[string]interface{}{
					"secret_name": secretName,
					"backend":     backend,
					"mount_path":  mountPath,
					"tainted":     tainted,
				})
			}

			c.Set("denied", false)
			c.JSON(http.StatusOK, secrets)
			return
		}

		var appID string
		if c.Request.Method == "POST" {
			var req SecretRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.Set("denied", true)
				c.Set("reason", err.Error())
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			appID = req.AppID
		} else {
			appID = c.Param("id")
		}

		rows, err := db.Query("SELECT secret_name, backend, mount_path, tainted FROM secret_backend_mapping WHERE app_id = $1", appID)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		secrets := make([]map[string]interface{}, 0)
		for rows.Next() {
			var secretName, backend, mountPath string
			var tainted bool
			if err := rows.Scan(&secretName, &backend, &mountPath, &tainted); err != nil {
				c.Set("denied", true)
				c.Set("reason", err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			secrets = append(secrets, map[string]interface{}{
				"secret_name": secretName,
				"backend":     backend,
				"mount_path":  mountPath,
				"tainted":     tainted,
			})
		}

		c.Set("denied", false)
		c.JSON(http.StatusOK, secrets)
	}
}



func dcdrLogout(c *gin.Context) {
	c.SetCookie("dcdr-session", "", -1, "/", "", false, true)
	c.Set("denied", false)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub *Hub

	// The websocket connection.
	conn *websocket.Conn

	// Buffered channel of outbound messages.
	send chan []byte
}

// readPump pumps messages from the websocket connection to the hub.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}
	}
}

// writePump pumps messages from the hub to the websocket connection.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// serveWs handles websocket requests from the peer.
func serveWs(hub *Hub, c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println(err)
		return
	}
	client := &Client{hub: hub, conn: conn, send: make(chan []byte, 256)}
	client.hub.register <- client

	// Allow collection of memory referenced by the caller by doing all work in
	// new goroutines.
	go client.writePump()
	go client.readPump()
}

func streamAuditLog(hub *Hub) gin.HandlerFunc {
	return func(c *gin.Context) {
		serveWs(hub, c)
	}
}

func downloadAuditLog(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			c.Set("denied", true)
			c.Set("reason", "Permission Denied")
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission Denied"})
			return
		}

		format := c.DefaultQuery("format", "csv")
		if format != "csv" && format != "json" {
			c.Set("denied", true)
			c.Set("reason", "Invalid format")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid format. Must be csv or json."})
			return
		}

		// Create a temporary directory for the audit logs
	tempDir := filepath.Join(cfg.StagingPath, uuid.New().String())
		if err := os.MkdirAll(tempDir, 0755); err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer os.RemoveAll(tempDir)

		// Fetch audit logs from the database
		rows, err := db.Query("SELECT timestamp, user_id, app_id, action, denied, reason FROM audit_log ORDER BY timestamp DESC")
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		// Create the zip file with a dynamic name
		timestamp := time.Now().Format("2006-01-02-15-04-05")
		zipFileName := fmt.Sprintf("dcdr-audit-logs-%s.zip", timestamp)
		zipFilePath := filepath.Join(tempDir, zipFileName)
		zipFile, err := os.Create(zipFilePath)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		zipWriter := zip.NewWriter(zipFile)

		fileNum := 1
		var fileSize int64
		var csvWriter *csv.Writer
		var jsonWriter io.Writer

		// Function to create a new file in the zip
		createNewFile := func() error {
			fileName := fmt.Sprintf("dcdr-audit-logs-%s-%d.%s", time.Now().Format("2006-01-02-15-04-05"), fileNum, format)
			file, err := zipWriter.Create(fileName)
			if err != nil {
				return err
			}
			if format == "csv" {
				csvWriter = csv.NewWriter(file)
				csvWriter.Write([]string{"timestamp", "user_id", "app_id", "action", "denied", "reason"})
			} else {
				jsonWriter = file
			}
			fileSize = 0
			fileNum++
			return nil
		}

		if err := createNewFile(); err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		for rows.Next() {
			var timestamp time.Time
			var userID sql.NullString
			var appID, action, reason sql.NullString
			var denied bool

			if err := rows.Scan(&timestamp, &userID, &appID, &action, &denied, &reason); err != nil {
				log.Printf("Failed to scan audit log row: %v", err)
				continue
			}

			// Check file size and create a new file if necessary
			if fileSize > 10*1024*1024 { // 10MB
				if err := createNewFile(); err != nil {
					c.Set("denied", true)
					c.Set("reason", err.Error())
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
			}

			if format == "csv" {
				record := []string{
					timestamp.Format(time.RFC3339),
					userID.String,
					appID.String,
					action.String,
					fmt.Sprintf("%t", denied),
					reason.String,
				}
				csvWriter.Write(record)
				csvWriter.Flush()
				// This is a rough estimate of the size
				fileSize += int64(len(strings.Join(record, ",")))
			} else {
				entry := gin.H{
					"timestamp": timestamp.Format(time.RFC3339),
					"user_id":   userID.String,
					"app_id":    appID.String,
					"action":    action.String,
					"denied":    denied,
					"reason":    reason.String,
				}
				jsonBytes, _ := json.Marshal(entry)
				jsonWriter.Write(jsonBytes)
				jsonWriter.Write([]byte("\n"))
				fileSize += int64(len(jsonBytes))
			}
		}

		// It's crucial to close the zipWriter and zipFile before serving the file
		zipWriter.Close()
		zipFile.Close()

		c.Header("Content-Type", "application/zip")
		c.Header("Content-Disposition", "attachment; filename="+zipFileName)
		c.File(zipFilePath)
		c.Set("denied", false)
	}
}