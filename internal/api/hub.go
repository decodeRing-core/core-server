package api

import (
	"database/sql"
	"encoding/json"
	"log"
	"time"
)

// Hub maintains the set of active clients and broadcasts messages to the
// clients.
type Hub struct {
	// Registered clients.
	clients map[*Client]bool

	// Inbound messages from the clients.
	broadcast chan []byte

	// Register requests from the clients.
	register chan *Client

	// Unregister requests from clients.
	unregister chan *Client

	// Database connection.
	db *sql.DB
}

func NewHub(db *sql.DB) *Hub {
	return &Hub{
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
		db:         db,
	}
}

func (h *Hub) sendInitialAuditLogs(client *Client) {
	rows, err := h.db.Query("SELECT timestamp, user_id, app_id, action, denied, reason FROM audit_log ORDER BY timestamp DESC LIMIT 100")
	if err != nil {
		log.Printf("Error fetching initial audit logs: %v", err)
		return
	}
	defer rows.Close()

	var entries []*AuditLogEntry
	for rows.Next() {
		var entry AuditLogEntry
		var timestamp time.Time
		var userID, appID, action, reason sql.NullString
		var denied bool

		if err := rows.Scan(&timestamp, &userID, &appID, &action, &denied, &reason); err != nil {
			log.Printf("Error scanning audit log row: %v", err)
			continue
		}

		entry.Timestamp = timestamp.Format(time.RFC3339)
		entry.UserID = userID.String
		entry.AppID = appID.String
		entry.Action = action.String
		entry.Denied = denied
		entry.Reason = reason.String

		entries = append(entries, &entry)
	}

	// Send entries in reverse order so they appear chronologically
	for i := len(entries) - 1; i >= 0; i-- {
		jsonBytes, _ := json.Marshal(entries[i])
		client.send <- jsonBytes
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
			go h.sendInitialAuditLogs(client)
		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
		case message := <-h.broadcast:
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
		}
	}
}

// AuditLogEntry represents a single audit log entry.

type AuditLogEntry struct {
	Timestamp string      `json:"timestamp"`
	UserID    string      `json:"user_id"`
	AppID     string      `json:"app_id"`
	Action    string      `json:"action"`
	Denied    bool        `json:"denied"`
	Reason    string      `json:"reason"`
}

func (h *Hub) BroadcastAuditLogEntry(entry *AuditLogEntry) {
	jsonBytes, _ := json.Marshal(entry)
	h.broadcast <- jsonBytes
}
