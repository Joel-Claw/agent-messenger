package main

import (
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
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
}

// Hub manages all active connections
type Hub struct {
	mu          sync.RWMutex
	agents      map[string]*Connection // agent_id -> Connection
	clients     map[string]*Connection // user_id -> Connection
	register    chan *Connection
	unregister  chan *Connection
	broadcast   chan []byte
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
					close(old.send)
				}
				h.agents[conn.id] = conn
				log.Printf("Agent connected: %s", conn.id)
			} else {
				if old, ok := h.clients[conn.id]; ok {
					close(old.send)
				}
				h.clients[conn.id] = conn
				log.Printf("Client connected: %s", conn.id)
			}
			h.mu.Unlock()

		case conn := <-h.unregister:
			h.mu.Lock()
			if conn.connType == "agent" {
				if _, ok := h.agents[conn.id]; ok {
					delete(h.agents, conn.id)
					close(conn.send)
					log.Printf("Agent disconnected: %s", conn.id)
				}
			} else {
				if _, ok := h.clients[conn.id]; ok {
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

// readPump reads messages from the WebSocket connection
func (c *Connection) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(65536) // 64KB max message size
	// TODO: Set read deadline for heartbeat

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("Error reading from %s %s: %v", c.connType, c.id, err)
			}
			break
		}

		log.Printf("Received from %s %s: %s", c.connType, c.id, string(message))
		// TODO: Route message based on type (Task 3)
		_ = message
	}
}

// writePump writes messages to the WebSocket connection
func (c *Connection) writePump() {
	defer func() {
		c.conn.Close()
	}()

	for {
		message, ok := <-c.send
		if !ok {
			// Channel closed, close connection
			c.conn.WriteMessage(websocket.CloseMessage, []byte{})
			return
		}

		if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
			log.Printf("Error writing to %s %s: %v", c.connType, c.id, err)
			return
		}
	}
}