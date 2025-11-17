package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
)

// CreateAppUserRequest is the request to create an application user
type CreateAppUserRequest struct {
	AppID    string `json:"app_id"`
	UserName string `json:"user_name"`
}

func CreateAppUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission Denied"})
			return
		}

		var req CreateAppUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		token, err := generateRandomString(26)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
			return
		}

		var userID string
		err = db.QueryRow("INSERT INTO application_users (app_id, user_name, token) VALUES ($1, $2, $3) RETURNING user_id", req.AppID, req.UserName, token).Scan(&userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"user_id":   userID,
			"user_name": req.UserName,
			"token":     token,
		})
	}
}

func ListAppUsers(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission Denied"})
			return
		}

		rows, err := db.Query(`
			SELECT u.user_id, u.user_name, a.app_id, a.app_name, u.status
			FROM application_users u
			JOIN applications a ON u.app_id = a.app_id
			ORDER BY a.app_name, u.user_name
		`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		users := make([]map[string]string, 0)
		for rows.Next() {
			var userID, userName, appID, appName, status string
			if err := rows.Scan(&userID, &userName, &appID, &appName, &status); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			users = append(users, map[string]string{
				"user_id":    userID,
				"user_name":  userName,
				"app_id":     appID,
				"app_name":   appName,
				"status":     status,
			})
		}

		c.JSON(http.StatusOK, users)
	}
}

// AppUserStatusRequest is the request to change an application user's status
type AppUserStatusRequest struct {
	UserID string `json:"user_id"`
	AppID  string `json:"app_id"`
}

func SuspendAppUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission Denied"})
			return
		}

		var req AppUserStatusRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		_, err := db.Exec("UPDATE application_users SET status = 'suspended', updated_at = NOW() WHERE user_id = $1 AND app_id = $2", req.UserID, req.AppID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func UnsuspendAppUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission Denied"})
			return
		}

		var req AppUserStatusRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		_, err := db.Exec("UPDATE application_users SET status = 'active', updated_at = NOW() WHERE user_id = $1 AND app_id = $2", req.UserID, req.AppID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func DeleteAppUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission Denied"})
			return
		}

		var req AppUserStatusRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		_, err := db.Exec("DELETE FROM application_users WHERE user_id = $1 AND app_id = $2", req.UserID, req.AppID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func GetAppUserToken(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		isRoot, _ := c.Get("is_root")
		if !isRoot.(bool) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission Denied"})
			return
		}

		var req AppUserStatusRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var token sql.NullString
		err := db.QueryRow("SELECT token FROM application_users WHERE user_id = $1", req.UserID).Scan(&token)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if !token.Valid {
			c.JSON(http.StatusNotFound, gin.H{"error": "token not found or user deleted"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": token.String})
	}
}

func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
