package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// pongWait is the maximum time to wait for a pong response from the peer.
	pongWait = 60 * time.Second

	// pingPeriod is how often to send pings to the peer. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// maxMessageSize is the maximum size of a single WebSocket message.
	maxMessageSize = 65536 // 64KB

	// writeWait is the time allowed to write a message to the peer.
	writeWait = 10 * time.Second
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // Non-browser clients (no Origin header) are allowed
		}
		if corsAllowedOrigins == "*" {
			return true
		}
		for _, allowed := range strings.Split(corsAllowedOrigins, ",") {
			allowed = strings.TrimSpace(allowed)
			if allowed == origin || allowed == "*" {
				return true
			}
		}
		return false
	},
}

// Connection represents a single WebSocket connection (agent or client)
type Connection struct {
	hub      *Hub
	connType string // "agent" or "client"
	id       string // agent_id or user_id
	deviceID string // device_id identifying this specific device/session (multi-device)
	conn     *websocket.Conn
	send     chan []byte
	// connectedAt tracks when this connection was established
	connectedAt time.Time
	// lastHeartbeat tracks the last time the agent sent a heartbeat message
	// Only meaningful for agent connections when agent presence heartbeat is enabled
	lastHeartbeat time.Time
	// status is the agent's current availability ("online", "busy", "idle")
	// Only meaningful for agent connections
	status string
}

// Hub manages all active connections
// offlineQueue buffers messages for disconnected clients/agents.
var offlineQueue *OfflineQueue

// agentPresenceInterval is how often agents should send heartbeats (configurable via AGENT_HEARTBEAT_INTERVAL env)
var agentPresenceInterval = 30 * time.Second

// agentPresenceTimeout is how long before an agent without heartbeats is considered stale (configurable via AGENT_HEARTBEAT_TIMEOUT env)
var agentPresenceTimeout = 90 * time.Second

// agentPresenceEnabled controls whether agent presence heartbeat monitoring is active (configurable via AGENT_HEARTBEAT_ENABLED env)
var agentPresenceEnabled = false

// Hub manages all active connections
type Hub struct {
	mu              sync.RWMutex
	agents          map[string]*Connection   // agent_id -> Connection (single agent session)
	clientConns     map[string][]*Connection // user_id -> []*Connection (multi-device: one user, many devices)
	register        chan *Connection
	unregister      chan *Connection
	broadcast       chan []byte
	done            chan struct{}

	// counters for metrics
	messagesRouted atomic.Int64

	// staleAgents counts how many agents have been disconnected for missed heartbeats
	staleAgents atomic.Int64
}

func newHub() *Hub {
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour) // 100 msgs per user, 7 day TTL
	h := &Hub{
		agents:     make(map[string]*Connection),
		clientConns: make(map[string][]*Connection),
		register:   make(chan *Connection),
		unregister: make(chan *Connection),
		broadcast:  make(chan []byte),
		done:       make(chan struct{}),
	}
	if agentPresenceEnabled {
		go h.monitorAgentHeartbeats()
	}
	return h
}

func (h *Hub) run() {
	for {
		select {
		case <-h.done:
			return

		case conn := <-h.register:
			h.mu.Lock()
			if conn.connType == "agent" {
				// Set initial heartbeat timestamp on connect
				conn.lastHeartbeat = time.Now()

				// Replace existing agent connection if any
				if old, ok := h.agents[conn.id]; ok {
					log.Printf("Agent %s reconnecting, closing old connection", conn.id)
					close(old.send)
				}
				h.agents[conn.id] = conn
				log.Printf("Agent connected: %s", conn.id)
				if ServerMetrics != nil { ServerMetrics.ConnectionsTotal.Add(1) }
				// Broadcast presence: agent online
				h.broadcastPresence(conn.id, "agent", true)
			} else {
				// Multi-device: append this connection to the user's device list
				// If same device_id reconnects, replace only that device's connection
				didReplace := false
				for i, existing := range h.clientConns[conn.id] {
					if existing.deviceID == conn.deviceID && conn.deviceID != "" {
						log.Printf("Client %s device %s reconnecting, closing old connection", conn.id, conn.deviceID)
						close(existing.send)
						h.clientConns[conn.id][i] = conn
						didReplace = true
						break
					}
				}
				if !didReplace {
					h.clientConns[conn.id] = append(h.clientConns[conn.id], conn)
				}
				log.Printf("Client connected: %s (device: %s, total devices: %d)", conn.id, conn.deviceID, len(h.clientConns[conn.id]))
				if ServerMetrics != nil { ServerMetrics.ConnectionsTotal.Add(1) }
			}
			h.mu.Unlock()

		case conn := <-h.unregister:
			h.mu.Lock()
			if conn.connType == "agent" {
				if existing, ok := h.agents[conn.id]; ok && existing == conn {
					delete(h.agents, conn.id)
					close(conn.send)
					log.Printf("Agent disconnected: %s", conn.id)
					// Broadcast presence: agent offline
					h.broadcastPresence(conn.id, "agent", false)
				}
			} else {
				// Remove only this specific connection from the user's device list
				conns := h.clientConns[conn.id]
				for i, existing := range conns {
					if existing == conn {
						// Remove without preserving order
						conns[i] = conns[len(conns)-1]
						conns = conns[:len(conns)-1]
						break
					}
				}
				if len(conns) == 0 {
					delete(h.clientConns, conn.id)
				} else {
					h.clientConns[conn.id] = conns
				}
				close(conn.send)
				log.Printf("Client disconnected: %s (device: %s, remaining devices: %d)", conn.id, conn.deviceID, len(conns))
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.RLock()
			for _, conn := range h.agents {
				select {
				case conn.send <- message:
				default:
					// Buffer full, skip
				}
			}
			for _, conns := range h.clientConns {
				for _, conn := range conns {
					select {
					case conn.send <- message:
					default:
					}
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Stop signals the hub to stop running.
func (h *Hub) Stop() {
	close(h.done)
}

// monitorAgentHeartbeats periodically checks agent connections for stale heartbeats
// and disconnects agents that haven't sent a heartbeat within the timeout period.
func (h *Hub) monitorAgentHeartbeats() {
	if agentPresenceInterval == 0 {
		return
	}

	ticker := time.NewTicker(agentPresenceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			h.checkStaleAgents()
		}
	}
}

// checkStaleAgents disconnects agents that have not sent a heartbeat within the timeout.
// It sends stale connections through the unregister channel for proper cleanup.
func (h *Hub) checkStaleAgents() {
	now := time.Now()
	var staleConns []*Connection

	h.mu.RLock()
	for id, conn := range h.agents {
		if now.Sub(conn.lastHeartbeat) > agentPresenceTimeout {
			log.Printf("Agent %s heartbeat stale (last: %v, timeout: %v), disconnecting", id, conn.lastHeartbeat, agentPresenceTimeout)
			h.staleAgents.Add(1)
			staleConns = append(staleConns, conn)
		}
	}
	h.mu.RUnlock()

	// Unregister stale connections through the hub's normal cleanup path
	for _, conn := range staleConns {
		h.unregister <- conn
	}
}

// TouchHeartbeat updates the last heartbeat timestamp for a connection.
func (h *Hub) TouchHeartbeat(conn *Connection) {
	h.mu.Lock()
	defer h.mu.Unlock()
	conn.lastHeartbeat = time.Now()
}

// StaleAgentCount returns the total number of agents disconnected for missed heartbeats.
func (h *Hub) StaleAgentCount() int64 {
	return h.staleAgents.Load()
}

// GetAgent returns a connection for a given agent ID
func (h *Hub) GetAgent(agentID string) *Connection {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.agents[agentID]
}

// GetClient returns the first connection for a given user ID.
// For multi-device scenarios, use GetClientConns instead.
func (h *Hub) GetClient(userID string) *Connection {
	h.mu.RLock()
	defer h.mu.RUnlock()
	conns := h.clientConns[userID]
	if len(conns) == 0 {
		return nil
	}
	return conns[0]
}

// GetClientConns returns all connections for a given user ID (multi-device).
func (h *Hub) GetClientConns(userID string) []*Connection {
	h.mu.RLock()
	defer h.mu.RUnlock()
	result := make([]*Connection, len(h.clientConns[userID]))
	copy(result, h.clientConns[userID])
	return result
}

// AgentCount returns the number of connected agents
func (h *Hub) AgentCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.agents)
}

// ClientCount returns the number of unique connected client users
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clientConns)
}

// broadcastPresence sends a presence_update event to all connected clients
// broadcastPresence sends a presence_update event to all connected clients.
// MUST be called with h.mu held (called from run() under Lock).
func (h *Hub) broadcastPresence(id string, connType string, online bool) {
	event := OutgoingMessage{
		Type: "presence_update",
		Data: map[string]interface{}{
			"id":     id,
			"type":   connType,
			"online": online,
		},
	}
	data, _ := json.Marshal(event)

	// Broadcast to all connected clients
	// No lock needed: caller (run()) holds h.mu.Lock()
	for _, conns := range h.clientConns {
		for _, client := range conns {
			select {
			case client.send <- data:
			default:
			}
		}
	}
}

// ClientConnCount returns the total number of client connections (including multiple devices per user)
func (h *Hub) ClientConnCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	total := 0
	for _, conns := range h.clientConns {
		total += len(conns)
	}
	return total
}

// AgentStatus returns the current status of a connected agent, or "offline" if not connected
func (h *Hub) AgentStatus(agentID string) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if conn, ok := h.agents[agentID]; ok {
		if conn.status != "" {
			return conn.status
		}
		return "online"
	}
	return "offline"
}

// SetAgentStatus updates the status of a connected agent
func (h *Hub) SetAgentStatus(agentID, status string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if conn, ok := h.agents[agentID]; ok {
		conn.status = status
	}
}

// AgentInfo holds metadata about a connected agent for listing
// (DB fields merged with live status from hub)
type AgentInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Model       string `json:"model"`
	Personality string `json:"personality"`
	Specialty   string `json:"specialty"`
	Status      string `json:"status"`
	ConnectedAt string `json:"connected_at,omitempty"`
}

// readPump reads messages from the WebSocket connection.
// It sets up a pong handler that resets the read deadline,
// ensuring stale connections are detected and cleaned up.
func (c *Connection) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))

	// Set pong handler: when we receive a pong, reset the read deadline
	c.conn.SetPongHandler(func(appData string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("Error reading from %s %s: %v", c.connType, c.id, err)
			}
			break
		}

		c.hub.messagesRouted.Add(1)
		if ServerMetrics != nil { ServerMetrics.MessagesIn.Add(1) }

		log.Printf("Received from %s %s: %s", c.connType, c.id, string(message))
		routeMessage(c, message)
	}
}

// writePump writes messages to the WebSocket connection.
// It sends pings on a ticker to keep the connection alive.
// If a write fails or the send channel is closed, the connection is cleaned up.
func (c *Connection) writePump() {
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
				// Channel closed by hub (unregister or replace), close connection
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if ServerMetrics != nil { ServerMetrics.MessagesOut.Add(1) }
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("Error writing to %s %s: %v", c.connType, c.id, err)
				return
			}

		case <-ticker.C:
			// Send ping to keep connection alive
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("Error sending ping to %s %s: %v", c.connType, c.id, err)
				return
			}
		}
	}
}