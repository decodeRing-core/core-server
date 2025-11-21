package ui

import (
	"crypto/rand"
	"database/sql"
	"dcdr.local/internal/api"
	"dcdr.local/internal/backend"
	"dcdr.local/internal/config"
	"encoding/hex"
	"html/template"
	"net/http"
	"fmt"
	"embed"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

var tpls *template.Template

func SetTemplates(fs embed.FS) {
	tpls = template.Must(template.ParseFS(fs,
		"ui/templates/layout.html",
		"ui/templates/login.html",
		"ui/templates/backends.html",
		"ui/templates/users.html",
		"ui/templates/applications.html",
		"ui/templates/application.html",
		"ui/templates/secrets.html",
		"ui/templates/secret_value.html",
		"ui/templates/token.html",
		"ui/templates/audit.html",
	))
}

func auditWrapper(action string, handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("audit_action", action)
		handler(c)
	}
}

func SetupRouter(r *gin.Engine, cfg *config.Config, db *sql.DB, backends map[string]backend.Backend) {
	store := cookie.NewStore([]byte("secret"))
	store.Options(sessions.Options{MaxAge: 300, HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode, Path: "/"})
	r.Use(sessions.Sessions("dcdr-session", store))

	// Login and Logout
	r.GET("/login", func(c *gin.Context) {
		tpls.ExecuteTemplate(c.Writer, "login.html", nil)
	})
	r.POST("/login", auditWrapper("login", loginHandler(db, tpls)))
	r.POST("/logout", auditWrapper("logout", logoutHandler))

	// Authenticated Routes
	authed := r.Group("/")
	authed.Use(AuthMiddleware())
	{
		authed.GET("/", auditWrapper("backendsPage", backendsPageHandler(db, cfg, tpls)))
		authed.GET("/applications", auditWrapper("applicationsPage", applicationsPageHandler(db, tpls)))
		authed.GET("/application/:id", auditWrapper("applicationPage", applicationPageHandler(db, tpls)))
		authed.POST("/applications/create", auditWrapper("createApplication", createApplicationHandler(db)))
		authed.POST("/applications/:id/delete", auditWrapper("deleteApplication", deleteApplicationHandler(db)))
		authed.GET("/applications/:id/secrets", auditWrapper("secretsPage", secretsPageHandler(db, tpls)))
		authed.POST("/applications/:id/secrets/create", auditWrapper("createSecret", createSecretHandler(db, cfg, backends)))
		authed.POST("/applications/:id/secrets/:secret_name/taint", auditWrapper("taintSecret", taintSecretHandler(db)))
		authed.POST("/applications/:id/secrets/:secret_name/untaint", auditWrapper("untaintSecret", untaintSecretHandler(db)))
		authed.POST("/applications/:id/secrets/:secret_name/destroy", auditWrapper("destroySecret", destroySecretHandler(db, cfg, backends)))
		authed.POST("/applications/:id/secrets/:secret_name/get", auditWrapper("getSecret", getSecretHandler(db, cfg, tpls, backends)))
		authed.GET("/users", auditWrapper("usersPage", usersPageHandler(db, tpls)))
		authed.GET("/applications/:id/users", auditWrapper("listAppUsersForAppUI", applicationUsersPageHandler(db, tpls)))
		authed.POST("/users/create", auditWrapper("createUser", createUserHandler(db)))
		authed.POST("/users/:id/token", auditWrapper("getUserToken", getUserTokenHandler(db, tpls)))
		authed.POST("/users/:id/suspend", auditWrapper("suspendUser", suspendUserHandler(db)))
		authed.POST("/users/:id/unsuspend", auditWrapper("unsuspendUser", unsuspendUserHandler(db)))
		authed.POST("/users/:id/delete", auditWrapper("deleteUser", deleteUserHandler(db)))
		authed.GET("/audit", auditWrapper("auditLogPage", auditLogPageHandler(tpls)))
	}
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("userID")
		if userID == nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		// Refresh the session on activity
		session.Options(sessions.Options{MaxAge: 300})
		session.Save()
		c.Next()
	}
}

func loginHandler(db *sql.DB, tpls *template.Template) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.PostForm("token")
		var isRoot bool
		var username string
		var appID string
		var userID interface{}

		var rootUserID int
		err := db.QueryRow("SELECT user_id FROM api_keys WHERE api_key = $1", token).Scan(&rootUserID)
		if err == nil {
			isRoot = true
			username = "root"
			userID = rootUserID
		} else if err == sql.ErrNoRows {
			var status string
			var appUserID string
			err = db.QueryRow("SELECT user_id, status, user_name, app_id FROM application_users WHERE token = $1", token).Scan(&appUserID, &status, &username, &appID)
			if err != nil || status != "active" {
				c.Set("denied", true)
				c.Set("reason", "Invalid token or inactive user")
				tpls.ExecuteTemplate(c.Writer, "login.html", gin.H{"Error": "Invalid token or inactive user"})
				return
			}
			userID = appUserID
		} else {
			c.Set("denied", true)
			c.Set("reason", "Database error")
			tpls.ExecuteTemplate(c.Writer, "login.html", gin.H{"Error": "Database error"})
			return
		}

		session := sessions.Default(c)
		session.Set("userID", userID)
		session.Set("isRoot", isRoot)
		session.Set("username", username)
		session.Set("appID", appID)
		session.Save()
		c.Set("denied", false)
		c.Redirect(http.StatusFound, "/")
	}
}

func logoutHandler(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Set("denied", false)
	c.Redirect(http.StatusFound, "/login")
}

func backendsPageHandler(db *sql.DB, cfg *config.Config, tpls *template.Template) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		if isRoot, ok := session.Get("isRoot").(bool); ok && !isRoot {
			if appID, ok := session.Get("appID").(string); ok && appID != "" {
				c.Redirect(http.StatusFound, "/applications/"+appID+"/secrets")
				c.Abort()
				return
			}
		}

		data := gin.H{
			"Title":    "Secrets Backends",
			"Username": session.Get("username"),
			"IsRoot":   session.Get("isRoot"),
			"Backends": getBackends(db, cfg),
		}
		fmt.Printf("data: %v\n", data)
		c.Header("Content-Type", "text/html")
		c.Set("denied", false)
		tpls.ExecuteTemplate(c.Writer, "layout", data)
	}
}

func applicationsPageHandler(db *sql.DB, tpls *template.Template) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		if !session.Get("isRoot").(bool) {
			c.Set("denied", true)
			c.Set("reason", "Permission Denied")
			c.Redirect(http.StatusFound, "/application/"+session.Get("appID").(string))
			c.Abort()
			return
		}

		data := gin.H{
			"Title":        "Applications",
			"Username":     session.Get("username"),
			"IsRoot":       session.Get("isRoot"),
			"Applications": getApplications(db),
		}
		c.Header("Content-Type", "text/html")
		c.Set("denied", false)
		tpls.ExecuteTemplate(c.Writer, "layout", data)
	}
}

func applicationPageHandler(db *sql.DB, tpls *template.Template) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		appID := c.Param("id")

		if !session.Get("isRoot").(bool) && session.Get("appID").(string) != appID {
			c.Set("denied", true)
			c.Set("reason", "Permission Denied")
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		appName, _ := getSecretsForApplication(db, appID)
		data := gin.H{
			"Title":    "Application",
			"Username": session.Get("username"),
			"IsRoot":   session.Get("isRoot"),
			"AppName":  appName,
			"AppID":    appID,
		}
		c.Set("denied", false)
		tpls.ExecuteTemplate(c.Writer, "layout", data)
	}
}

func usersPageHandler(db *sql.DB, tpls *template.Template) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		data := gin.H{
			"Title":        "User Management",
			"Username":     session.Get("username"),
			"IsRoot":       session.Get("isRoot"),
			"Applications": getUsersWithDetails(db),
		}
		c.Header("Content-Type", "text/html")
		c.Set("denied", false)
		tpls.ExecuteTemplate(c.Writer, "layout", data)
	}
}

func createApplicationHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		appName := c.PostForm("appName")
		if appName != "" {
			_, err := db.Exec("INSERT INTO applications (app_name) VALUES ($1)", appName)
			if err != nil {
				c.Set("denied", true)
				c.Set("reason", err.Error())
				c.String(http.StatusInternalServerError, "Error creating application: "+err.Error())
				return
			}
		}
		c.Set("denied", false)
		c.Redirect(http.StatusFound, "/applications")
	}
}

func deleteApplicationHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		appID := c.Param("id")
		// Add check for secrets before deleting
		_, err := db.Exec("DELETE FROM applications WHERE app_id = $1", appID)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.String(http.StatusInternalServerError, "Error deleting application: "+err.Error())
			return
		}
		c.Set("denied", false)
		c.Redirect(http.StatusFound, "/applications")
	}
}

// --- Data Fetching Functions ---

func getBackends(db *sql.DB, cfg *config.Config) []gin.H {
	backends := make([]gin.H, 0)
	for _, backendCfg := range cfg.Backends {
		var numApplications, numSecrets int
		err := db.QueryRow(`
			SELECT COUNT(DISTINCT app_id), COUNT(*)
			FROM secret_backend_mapping
			WHERE backend = $1
		`, backendCfg.Name).Scan(&numApplications, &numSecrets)
		if err != nil && err != sql.ErrNoRows {
			// Log error in a real app
			continue
		}

		var addr string
		switch backendCfg.Type {
		case "vault":
			addr = backendCfg.VaultAddr
		case "openbao":
			addr = backendCfg.BaoAddr
		case "conjur":
			addr = backendCfg.ConjurAddr
		}

		backends = append(backends, gin.H{
			"Name":       backendCfg.Name,
			"Type":       backendCfg.Type,
			"NumApps":    numApplications,
			"NumSecrets": numSecrets,
			"Addr":       addr,
		})
	}
	return backends
}

func getApplications(db *sql.DB) []gin.H {

rows, err := db.Query("SELECT app_id, app_name FROM applications ORDER BY app_name")
	if err != nil {
		return nil
	}
	defer rows.Close()

	apps := make([]gin.H, 0)
	for rows.Next() {
		var appID, appName string
		if err := rows.Scan(&appID, &appName); err != nil {
			continue
		}
		apps = append(apps, gin.H{"ID": appID, "Name": appName})
	}
	return apps
}

func getUsersWithDetails(db *sql.DB) []gin.H {
	apps := getApplications(db)
	for i, app := range apps {
		rows, err := db.Query("SELECT user_id, user_name, status FROM application_users WHERE app_id = $1 ORDER BY user_name", app["ID"])
		if err != nil {
			continue
		}
		
		users := make([]gin.H, 0)
		for rows.Next() {
			var userID, userName, status string
			if err := rows.Scan(&userID, &userName, &status); err != nil {
				continue
			}
			users = append(users, gin.H{"ID": userID, "Name": userName, "Status": status})
		}
	
rows.Close()
		apps[i]["Users"] = users
	}
	return apps
}

func createUserHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		appID := c.PostForm("appId")
		userName := c.PostForm("userName")

		if appID != "" && userName != "" {
			// Generate a random token
			tokenBytes := make([]byte, 16)
			if _, err := rand.Read(tokenBytes); err != nil {
				c.Set("denied", true)
				c.Set("reason", err.Error())
				c.String(http.StatusInternalServerError, "Error generating token: "+err.Error())
				return
			}
			token := hex.EncodeToString(tokenBytes)

			// Insert new user
			_, err := db.Exec("INSERT INTO application_users (app_id, user_name, token, status) VALUES ($1, $2, $3, 'active')", appID, userName, token)
			if err != nil {
				c.Set("denied", true)
				c.Set("reason", err.Error())
				c.String(http.StatusInternalServerError, "Error creating user: "+err.Error())
				return
			}
		}
		c.Set("denied", false)
		c.Redirect(http.StatusFound, "/users")
	}
}

func getUserTokenHandler(db *sql.DB, tpls *template.Template) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := c.Param("id")
		var token, userName string
		err := db.QueryRow("SELECT token, user_name FROM application_users WHERE user_id = $1", userID).Scan(&token, &userName)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.String(http.StatusInternalServerError, "Error getting token: "+err.Error())
			return
		}
		data := gin.H{
			"Title":    "User Token",
			"Username": session.Get("username"),
			"IsRoot":   session.Get("isRoot"),
			"Token":    token,
			"TokenUser": userName,
		}
		c.Set("denied", false)
		tpls.ExecuteTemplate(c.Writer, "layout", data)
	}
}

func suspendUserHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")
		_, err := db.Exec("UPDATE application_users SET status = 'suspended' WHERE user_id = $1", userID)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.String(http.StatusInternalServerError, "Error suspending user: "+err.Error())
			return
		}
		c.Set("denied", false)
		c.Redirect(http.StatusFound, "/users")
	}
}

func unsuspendUserHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")
		_, err := db.Exec("UPDATE application_users SET status = 'active' WHERE user_id = $1", userID)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.String(http.StatusInternalServerError, "Error unsuspending user: "+err.Error())
			return
		}
		c.Set("denied", false)
		c.Redirect(http.StatusFound, "/users")
	}
}

func deleteUserHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")
		_, err := db.Exec("DELETE FROM application_users WHERE user_id = $1", userID)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.String(http.StatusInternalServerError, "Error deleting user: "+err.Error())
			return
		}
		c.Set("denied", false)
		c.Redirect(http.StatusFound, "/users")
	}
}

func applicationUsersPageHandler(db *sql.DB, tpls *template.Template) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		appID := c.Param("id")

		if !session.Get("isRoot").(bool) && session.Get("appID").(string) != appID {
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		appName, _ := getSecretsForApplication(db, appID)
		data := gin.H{
			"Title":        "Application Users",
			"Username":     session.Get("username"),
			"IsRoot":       session.Get("isRoot"),
			"AppName":      appName,
			"AppID":        appID,
			"Applications": getUsersWithDetails(db),
		}
		c.Header("Content-Type", "text/html")
		tpls.ExecuteTemplate(c.Writer, "layout", data)
	}
}

func auditLogPageHandler(tpls *template.Template) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		if !session.Get("isRoot").(bool) {
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		data := gin.H{
			"Title":    "Audit Logs",
			"Username": session.Get("username"),
			"IsRoot":   session.Get("isRoot"),
		}
		c.Header("Content-Type", "text/html")
		tpls.ExecuteTemplate(c.Writer, "layout", data)
	}
}

func getSecretsForApplication(db *sql.DB, appID string) (string, []gin.H) {
	var appName string
	db.QueryRow("SELECT app_name FROM applications WHERE app_id = $1", appID).Scan(&appName)


rows, err := db.Query(`
		SELECT s.secret_name, s.backend, s.mount_path, s.tainted
		FROM secret_backend_mapping s
		WHERE s.app_id = $1
		ORDER BY s.secret_name
	`, appID)
	if err != nil {
		return appName, nil
	}
	defer rows.Close()

	secrets := make([]gin.H, 0)
	for rows.Next() {
		var secretName, backend, path string
		var tainted bool
		if err := rows.Scan(&secretName, &backend, &path, &tainted); err != nil {
			continue
		}
		secrets = append(secrets, gin.H{
			"Name":    secretName,
			"Backend": backend,
			"Path":    path,
			"Tainted": tainted,
		})
	}
	return appName, secrets
}

func secretsPageHandler(db *sql.DB, tpls *template.Template) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		appID := c.Param("id")

		if !session.Get("isRoot").(bool) && session.Get("appID").(string) != appID {
			c.Set("denied", true)
			c.Set("reason", "Permission Denied")
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		appName, secrets := getSecretsForApplication(db, appID)
		data := gin.H{
			"Title":    "Application Secrets",
			"Username": session.Get("username"),
			"IsRoot":   session.Get("isRoot"),
			"AppName":  appName,
			"AppID":    appID,
			"Secrets":  secrets,
		}
		c.Set("denied", false)
		tpls.ExecuteTemplate(c.Writer, "layout", data)
	}
}

func createSecretHandler(db *sql.DB, cfg *config.Config, backends map[string]backend.Backend) gin.HandlerFunc {
	return func(c *gin.Context) {
		appID := c.Param("id")
		secretName := c.PostForm("secretName")
		backendName := c.PostForm("backend")
		mountPath := c.PostForm("mountPath")
		secretKey := c.PostForm("secretKey")
		secretValue := c.PostForm("secretValue")

		if secretName != "" && backendName != "" && mountPath != "" && secretKey != "" && secretValue != "" {
			req := api.SecretCreationRequest{
				AppID:      appID,
				SecretName: secretName,
				Backend:    backendName,
				MountPath:  mountPath,
				Data:       map[string]interface{}{secretKey: secretValue},
			}

			err := api.CreateSecretLogic(req, cfg, db, backends)
			if err != nil {
				c.Set("denied", true)
				if apiErr, ok := err.(*api.APIError); ok {
					c.Set("reason", apiErr.Message)
					c.String(apiErr.StatusCode, apiErr.Message)
				} else {
					c.Set("reason", err.Error())
					c.String(http.StatusInternalServerError, err.Error())
				}
				return
			}
		}
		c.Set("denied", false)
		c.Redirect(http.StatusFound, "/applications/"+appID+"/secrets")
	}
}

func taintSecretHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		appID := c.Param("id")
		secretName := c.Param("secret_name")
		_, err := db.Exec("UPDATE secret_backend_mapping SET tainted = true WHERE app_id = $1 AND secret_name = $2", appID, secretName)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.String(http.StatusInternalServerError, "Error tainting secret: "+err.Error())
			return
		}
		c.Set("denied", false)
		c.Redirect(http.StatusFound, "/applications/"+appID+"/secrets")
	}
}

func untaintSecretHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		appID := c.Param("id")
		secretName := c.Param("secret_name")
		_, err := db.Exec("UPDATE secret_backend_mapping SET tainted = false WHERE app_id = $1 AND secret_name = $2", appID, secretName)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", err.Error())
			c.String(http.StatusInternalServerError, "Error untainting secret: "+err.Error())
			return
		}
		c.Set("denied", false)
		c.Redirect(http.StatusFound, "/applications/"+appID+"/secrets")
	}
}

func destroySecretHandler(db *sql.DB, cfg *config.Config, backends map[string]backend.Backend) gin.HandlerFunc {
	return func(c *gin.Context) {
		appID := c.Param("id")
		secretName := c.Param("secret_name")

		var backendName, mountPath string
		err := db.QueryRow("SELECT backend, mount_path FROM secret_backend_mapping WHERE app_id = $1 AND secret_name = $2", appID, secretName).Scan(&backendName, &mountPath)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", "Error getting secret metadata: "+err.Error())
			c.String(http.StatusInternalServerError, "Error getting secret metadata: "+err.Error())
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
			c.Set("reason", "Backend configuration not found for secret")
			c.String(http.StatusInternalServerError, "Backend configuration not found for secret")
			return
		}

		backend, ok := backends[backendName]
		if !ok {
			c.Set("denied", true)
			c.Set("reason", "Backend not found")
			c.String(http.StatusInternalServerError, "Backend not found")
			return
		}

		secretPath := secretName
		if backendCfg.Type == "vault" {
			secretPath = fmt.Sprintf("data/%s/%s", appID, secretName)
		} else if backendCfg.Type == "azure" {
			secretPath = fmt.Sprintf("%s-%s", appID, secretName)
		} else {
			secretPath = fmt.Sprintf("%s/%s", appID, secretName)
		}

		err = backend.DeleteSecret(mountPath, secretPath)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", "Error deleting secret from backend: "+err.Error())
			c.String(http.StatusInternalServerError, "Error deleting secret from backend: "+err.Error())
			return
		}

		_, err = db.Exec("DELETE FROM secret_backend_mapping WHERE app_id = $1 AND secret_name = $2", appID, secretName)
		if err != nil {
			c.Set("denied", true)
			c.Set("reason", "Error destroying secret: "+err.Error())
			c.String(http.StatusInternalServerError, "Error destroying secret: "+err.Error())
			return
		}
		c.Set("denied", false)
		c.Redirect(http.StatusFound, "/applications/"+appID+"/secrets")
	}
}



func getSecretHandler(db *sql.DB, cfg *config.Config, tpls *template.Template, backends map[string]backend.Backend) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		appID := c.Param("id")
		secretName := c.Param("secret_name")

		secret, err := api.GetSecretLogic(appID, secretName, cfg, db, backends)
		if err != nil {
			c.Set("denied", true)
			if apiErr, ok := err.(*api.APIError); ok {
				c.Set("reason", apiErr.Message)
				c.String(apiErr.StatusCode, apiErr.Message)
			} else {
				c.Set("reason", err.Error())
				c.String(http.StatusInternalServerError, err.Error())
			}
			return
		}

		data := gin.H{
			"Title":      "Secret Value",
			"Username":   session.Get("username"),
			"IsRoot":     session.Get("isRoot"),
			"SecretName": secretName,
			"AppID":      appID,
			"Secret":     secret,
		}
		c.Set("denied", false)
		tpls.ExecuteTemplate(c.Writer, "layout", data)
	}
}
