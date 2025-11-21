package middleware

import (
	"database/sql"
	"dcdr.local/internal/api"
	"log"
	"time"
	"strconv"

	"github.com/gin-gonic/gin"
)

func AuditLogger(db *sql.DB, hub *api.Hub) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// We will get the audit information from the context
		action, exists := c.Get("audit_action")
		if !exists {
			// If no action is set, we don't log anything
			return
		}

		userID, _ := c.Get("userID")
		appID, _ := c.Get("appID")
		denied, ok := c.Get("denied")
		if !ok {
			denied = false
		}
		reason, _ := c.Get("reason")

		_, err := db.Exec("INSERT INTO audit_log (user_id, app_id, action, denied, reason) VALUES ($1, $2, $3, $4, $5)",
			userID,
			appID,
			action,
			denied,
			reason,
		)

		if err != nil {
			log.Printf("Failed to write to audit log: %v", err)
		}

		// Broadcast the audit log entry to the hub
		entry := &api.AuditLogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
		}
		if userID, ok := c.Get("userID"); ok {
			switch v := userID.(type) {
			case string:
				entry.UserID = v
			case int:
				entry.UserID = strconv.Itoa(v)
			}
		}
		if appID, ok := c.Get("appID"); ok {
			if appID, ok := appID.(string); ok {
				entry.AppID = appID
			}
		}
		if action, ok := c.Get("audit_action"); ok {
			if action, ok := action.(string); ok {
				entry.Action = action
			}
		}
		if denied, ok := c.Get("denied"); ok {
			if denied, ok := denied.(bool); ok {
				entry.Denied = denied
			}
		}
		if reason, ok := c.Get("reason"); ok {
			if reason, ok := reason.(string); ok {
				entry.Reason = reason
			}
		}
		hub.BroadcastAuditLogEntry(entry)
	}
}
