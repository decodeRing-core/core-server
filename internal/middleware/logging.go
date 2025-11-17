package middleware

import (
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

func Logger(accessLog *os.File, errorLogPath string) gin.HandlerFunc {
	accessLogger := log.New(accessLog, "", 0)

	errorLog, err := os.OpenFile(errorLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open error log file: %v", err)
	}
	errorLogger := log.New(errorLog, "", log.LstdFlags)

	return func(c *gin.Context) {
		// Start timer
		start := time.Now()

		// Process request
		c.Next()

		// Stop timer
		latency := time.Since(start)

		// Log access
		accessLogger.Printf("%s - %s - %s [%s] \"%s %s\" %d %s",
			c.ClientIP(),
			c.GetString("userID"), // This needs to be to be set in the context by a previous middleware
			c.GetString("appID"),  // This needs to be set in the context by a previous middleware
			time.Now().Format(time.RFC3339),
			c.Request.Method,
			c.Request.URL.Path,
			c.Writer.Status(),
			latency,
		)

		// Log errors
		if len(c.Errors) > 0 {
			for _, e := range c.Errors {
				errorLogger.Printf("%s - %s - %s: %s",
					c.ClientIP(),
					c.GetString("userID"), // This needs to be set in the context by a previous middleware
					c.GetString("appID"),  // This needs to be set in the context by a previous middleware
					e.Err.Error(),
				)
			}
		}
	}
}
