package main

import (
	"log"
	"net/http"
	"sync"
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
		// TODO: Restrict origins in production
		return true
	},
}

// Connection represents a single WebSocket connection (agent or client)
type Connection struct {
	hub      *Hub
	connType string // "agent" or "client"
	id       string // agent_id or user_id
	conn     *websocket.Conn
	send     chan []byte
	// connectedAt tracks when this connection was established
	connectedAt time.Time
}

// Hub manages all active connections
type Hub struct {
	mu         sync.RWMutex
	agents     map[string]*Connection // agent_id -> Connection
	clients    map[string]*Connection // user_id -> Connection
	register   chan *Connection
	unregister chan *Connection
	broadcast  chan []byte

	// counters for metrics
	messagesRouted int64
}

func newHub() *Hub {
	return &Hub{
		agents:     make(map[string]*Connection),
		clients:    make(map[string]*Connection),
		register:   make(chan *Connection),
		unregister: make(chan *Connection),
		broadcast:  make(chan []byte),
	}
}

func (h *Hub) run() {
	for {
		select {
		case conn := <-h.register:
			h.mu.Lock()
			if conn.connType == "agent" {
				// Replace existing connection if any
				if old, ok := h.agents[conn.id]; ok {
					log.Printf("Agent %s reconnecting, closing old connection", conn.id)
					close(old.send)
				}
				h.agents[conn.id] = conn
				log.Printf("Agent connected: %s", conn.id)
			} else {
				if old, ok := h.clients[conn.id]; ok {
					log.Printf("Client %s reconnecting, closing old connection", conn.id)
					close(old.send)
				}
				h.clients[conn.id] = conn
				log.Printf("Client connected: %s", conn.id)
			}
			h.mu.Unlock()

		case conn := <-h.unregister:
			h.mu.Lock()
			if conn.connType == "agent" {
				if existing, ok := h.agents[conn.id]; ok && existing == conn {
					delete(h.agents, conn.id)
					close(conn.send)
					log.Printf("Agent disconnected: %s", conn.id)
				}
			} else {
				if existing, ok := h.clients[conn.id]; ok && existing == conn {
					delete(h.clients, conn.id)
					close(conn.send)
					log.Printf("Client disconnected: %s", conn.id)
				}
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
			for _, conn := range h.clients {
				select {
				case conn.send <- message:
				default:
				}
			}
			h.mu.RUnlock()
		}
	}
}

// GetAgent returns a connection for a given agent ID
func (h *Hub) GetAgent(agentID string) *Connection {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.agents[agentID]
}

// GetClient returns a connection for a given user ID
func (h *Hub) GetClient(userID string) *Connection {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.clients[userID]
}

// AgentCount returns the number of connected agents
func (h *Hub) AgentCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.agents)
}

// ClientCount returns the number of connected clients
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
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

		c.hub.mu.Lock()
		c.hub.messagesRouted++
		c.hub.mu.Unlock()

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