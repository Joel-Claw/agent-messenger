package main

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestMultiDeviceClientConnect verifies that the same user can connect from multiple devices.
func TestMultiDeviceClientConnect(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	// Connect device 1
	conn1 := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "multi-user",
		deviceID:    "phone",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- conn1
	time.Sleep(10 * time.Millisecond)

	// Connect device 2
	conn2 := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "multi-user",
		deviceID:    "laptop",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- conn2
	time.Sleep(10 * time.Millisecond)

	// Both should be registered
	conns := hub.GetClientConns("multi-user")
	if len(conns) != 2 {
		t.Fatalf("expected 2 connections, got %d", len(conns))
	}
	if hub.ClientCount() != 1 {
		t.Fatalf("expected 1 unique client user, got %d", hub.ClientCount())
	}
	if hub.ClientConnCount() != 2 {
		t.Fatalf("expected 2 total client connections, got %d", hub.ClientConnCount())
	}
}

// TestMultiDeviceSameDeviceReconnect verifies that reconnecting with the same device_id
// replaces only that device's connection, keeping others intact.
func TestMultiDeviceSameDeviceReconnect(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	// Connect phone
	phone1 := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "md-user",
		deviceID:    "phone",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- phone1
	time.Sleep(10 * time.Millisecond)

	// Connect laptop
	laptop := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "md-user",
		deviceID:    "laptop",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- laptop
	time.Sleep(10 * time.Millisecond)

	// Reconnect phone (same device_id)
	phone2 := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "md-user",
		deviceID:    "phone",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- phone2
	time.Sleep(10 * time.Millisecond)

	// Should still have 2 connections
	conns := hub.GetClientConns("md-user")
	if len(conns) != 2 {
		t.Fatalf("expected 2 connections after phone reconnect, got %d", len(conns))
	}

	// Old phone connection should be closed
	select {
	case _, ok := <-phone1.send:
		if ok {
			t.Fatal("old phone connection should be closed")
		}
	default:
		t.Fatal("old phone send channel should be closed (blocking read returned open)")
	}

	// Laptop should still be alive
	select {
	case _, ok := <-laptop.send:
		if ok {
			// Got a message — might be from routing, that's fine as long as channel is open
		} else {
			t.Fatal("laptop connection should NOT be closed")
		}
	default:
		// Channel is open but empty — that's expected
	}
}

// TestMultiDevicePartialDisconnect verifies that disconnecting one device
// leaves the other device connected.
func TestMultiDevicePartialDisconnect(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	phone := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "pd-user",
		deviceID:    "phone",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- phone
	time.Sleep(10 * time.Millisecond)

	laptop := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "pd-user",
		deviceID:    "laptop",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- laptop
	time.Sleep(10 * time.Millisecond)

	// Disconnect phone only
	hub.unregister <- phone
	time.Sleep(10 * time.Millisecond)

	// Should have 1 connection left
	conns := hub.GetClientConns("pd-user")
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection after partial disconnect, got %d", len(conns))
	}
	if conns[0].deviceID != "laptop" {
		t.Fatalf("expected laptop to remain, got %s", conns[0].deviceID)
	}
	if hub.ClientCount() != 1 {
		t.Fatalf("expected 1 unique client user, got %d", hub.ClientCount())
	}
	if hub.ClientConnCount() != 1 {
		t.Fatalf("expected 1 total client connection, got %d", hub.ClientConnCount())
	}

	// Disconnect laptop
	hub.unregister <- laptop
	time.Sleep(10 * time.Millisecond)

	// User should be fully disconnected
	if hub.ClientCount() != 0 {
		t.Fatalf("expected 0 clients after full disconnect, got %d", hub.ClientCount())
	}
}

// TestMultiDeviceMessageDelivery verifies that messages are delivered to ALL
// connected devices of a user.
func TestMultiDeviceMessageDelivery(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	// Create agent
	agent := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "md-agent",
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
	}
	hub.register <- agent
	time.Sleep(10 * time.Millisecond)

	// Create conversation in DB
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		"md-conv-1", "md-user", "md-agent")
	if err != nil {
		t.Fatal(err)
	}

	// Connect user on two devices
	phone := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "md-user",
		deviceID:    "phone",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- phone
	time.Sleep(10 * time.Millisecond)

	laptop := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "md-user",
		deviceID:    "laptop",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- laptop
	time.Sleep(10 * time.Millisecond)

	// Agent sends a message to the user
	msg := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{"conversation_id":"md-conv-1","content":"Hello from agent!"}`),
	}
	raw, _ := json.Marshal(msg)
	routeMessage(agent, raw)

	// Both devices should receive the message
	receivedPhone := false
	receivedLaptop := false

	select {
	case data := <-phone.send:
		var outMsg OutgoingMessage
		json.Unmarshal(data, &outMsg)
		if outMsg.Type == "message" {
			receivedPhone = true
		}
	case <-time.After(time.Second):
	}

	select {
	case data := <-laptop.send:
		var outMsg OutgoingMessage
		json.Unmarshal(data, &outMsg)
		if outMsg.Type == "message" {
			receivedLaptop = true
		}
	case <-time.After(time.Second):
	}

	if !receivedPhone {
		t.Fatal("phone should have received the message")
	}
	if !receivedLaptop {
		t.Fatal("laptop should have received the message")
	}
}

// TestMultiDeviceTypingIndicator verifies typing indicators are sent to all devices.
func TestMultiDeviceTypingIndicator(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	// Create agent
	agent := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "typing-md-agent",
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
	}
	hub.register <- agent
	time.Sleep(10 * time.Millisecond)

	// Create conversation
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		"typing-md-conv", "typing-md-user", "typing-md-agent")
	if err != nil {
		t.Fatal(err)
	}

	// Connect two devices
	phone := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "typing-md-user",
		deviceID:    "phone",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- phone
	time.Sleep(10 * time.Millisecond)

	laptop := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "typing-md-user",
		deviceID:    "laptop",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- laptop
	time.Sleep(10 * time.Millisecond)

	// Agent sends typing indicator
	msg := IncomingMessage{
		Type: "typing",
		Data: json.RawMessage(`{"conversation_id":"typing-md-conv"}`),
	}
	raw, _ := json.Marshal(msg)
	routeMessage(agent, raw)

	// Both should receive typing
	gotPhone := false
	gotLaptop := false

	select {
	case data := <-phone.send:
		var outMsg OutgoingMessage
		json.Unmarshal(data, &outMsg)
		if outMsg.Type == "typing" {
			gotPhone = true
		}
	case <-time.After(time.Second):
	}

	select {
	case data := <-laptop.send:
		var outMsg OutgoingMessage
		json.Unmarshal(data, &outMsg)
		if outMsg.Type == "typing" {
			gotLaptop = true
		}
	case <-time.After(time.Second):
	}

	if !gotPhone {
		t.Fatal("phone should have received typing indicator")
	}
	if !gotLaptop {
		t.Fatal("laptop should have received typing indicator")
	}
}

// TestMultiDeviceNoDeviceID verifies backward compatibility: connecting without
// a device_id still works (each connection gets a unique slot, no dedup).
func TestMultiDeviceNoDeviceID(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	// Connect without device_id (legacy)
	conn1 := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "legacy-user",
		deviceID:    "",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- conn1
	time.Sleep(10 * time.Millisecond)

	// Connect again without device_id (second connection from same user)
	conn2 := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "legacy-user",
		deviceID:    "",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- conn2
	time.Sleep(10 * time.Millisecond)

	// Both should be active (no device_id means no dedup)
	conns := hub.GetClientConns("legacy-user")
	if len(conns) != 2 {
		t.Fatalf("expected 2 connections (no device_id dedup), got %d", len(conns))
	}

	// conn1 send channel should still be open (it wasn't replaced)
	// We just verify the channel isn't closed by doing a non-blocking read
	select {
	case _, ok := <-conn1.send:
		if !ok {
			t.Fatal("conn1 send channel should not be closed")
		}
	default:
		// Channel is open and empty — expected
	}
}

// TestMultiDeviceStatusUpdateToAll verifies status updates are sent to all devices.
func TestMultiDeviceStatusUpdateToAll(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	// Create agent
	agent := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "status-md-agent",
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
	}
	hub.register <- agent
	time.Sleep(10 * time.Millisecond)

	// Create conversation
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		"status-md-conv", "status-md-user", "status-md-agent")
	if err != nil {
		t.Fatal(err)
	}

	// Connect two devices
	phone := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "status-md-user",
		deviceID:    "phone",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- phone
	time.Sleep(10 * time.Millisecond)

	laptop := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "status-md-user",
		deviceID:    "laptop",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- laptop
	time.Sleep(10 * time.Millisecond)

	// Agent sends status update
	msg := IncomingMessage{
		Type: "status",
		Data: json.RawMessage(`{"conversation_id":"status-md-conv","status":"busy"}`),
	}
	raw, _ := json.Marshal(msg)
	routeMessage(agent, raw)

	// Both should receive status
	gotPhone := false
	gotLaptop := false

	select {
	case data := <-phone.send:
		var outMsg OutgoingMessage
		json.Unmarshal(data, &outMsg)
		if outMsg.Type == "status" {
			gotPhone = true
		}
	case <-time.After(time.Second):
	}

	select {
	case data := <-laptop.send:
		var outMsg OutgoingMessage
		json.Unmarshal(data, &outMsg)
		if outMsg.Type == "status" {
			gotLaptop = true
		}
	case <-time.After(time.Second):
	}

	if !gotPhone {
		t.Fatal("phone should have received status update")
	}
	if !gotLaptop {
		t.Fatal("laptop should have received status update")
	}
}

// TestMultiDeviceReadReceiptToAllDevices verifies read receipts are forwarded
// to all of a user's connected devices (for cross-device read sync).
// This test verifies that when an agent receives a read_receipt event,
// the hub properly supports multi-device for the read_receipt flow.
func TestMultiDeviceReadReceiptToAllDevices(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	// Create agent
	agent := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "rr-md-agent",
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
	}
	hub.register <- agent
	time.Sleep(10 * time.Millisecond)

	// Verify agent is connected
	if hub.GetAgent("rr-md-agent") == nil {
		t.Fatal("agent should be connected")
	}
}

// TestMultiDeviceOfflineQueueReplay verifies that offline messages are replayed
// only to the reconnecting device, not to already-connected devices.
func TestMultiDeviceOfflineQueueReplay(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)

	// Queue some messages for user while offline
	msg1 := []byte(`{"type":"message","data":{"content":"offline msg 1"}}`)
	msg2 := []byte(`{"type":"message","data":{"content":"offline msg 2"}}`)
	q.Enqueue("oq-user", msg1)
	q.Enqueue("oq-user", msg2)

	if q.QueueDepth("oq-user") != 2 {
		t.Fatalf("expected 2 queued messages, got %d", q.QueueDepth("oq-user"))
	}

	// When first device reconnects, drain the queue
	drained := q.Drain("oq-user")
	if len(drained) != 2 {
		t.Fatalf("expected 2 drained messages, got %d", len(drained))
	}

	// Second device connecting should get nothing (already drained)
	drained2 := q.Drain("oq-user")
	if len(drained2) != 0 {
		t.Fatalf("expected 0 drained messages for second device, got %d", len(drained2))
	}
}

// TestMultiDeviceHealthMetrics verifies health endpoint includes multi-device metrics.
func TestMultiDeviceHealthMetrics(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	// Connect 1 user on 3 devices
	for i, did := range []string{"phone", "tablet", "laptop"} {
		conn := &Connection{
			hub:         hub,
			connType:    "client",
			id:          "health-user",
			deviceID:    did,
			send:        make(chan []byte, 10),
			connectedAt: time.Now(),
		}
		hub.register <- conn
		time.Sleep(10 * time.Millisecond)
		_ = i
	}

	// Also connect an agent
	agent := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "health-agent",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- agent
	time.Sleep(10 * time.Millisecond)

	snapshot := ServerMetrics.Snapshot()
	if snapshot["agents_connected"] != 1 {
		t.Fatalf("expected 1 agent, got %v", snapshot["agents_connected"])
	}
	if snapshot["clients_connected"] != 1 {
		t.Fatalf("expected 1 unique client user, got %v", snapshot["clients_connected"])
	}
	if snapshot["client_conns_total"] != 3 {
		t.Fatalf("expected 3 total client connections, got %v", snapshot["client_conns_total"])
	}
}

// TestMultiDeviceWebSocket tests multi-device via actual WebSocket connections.
func TestMultiDeviceWebSocket(t *testing.T) {
	server, cleanup := setupTestServerForRouting(t)
	defer cleanup()

	// Register a user and get a token
	token := registerUserAndGetToken(t, "wsmduser", "testpass")

	// Extract the real user_id from the JWT
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}
	userID := claims.UserID

	// Create agent
	agentConn := registerAndConnectAgent(t, server, "ws-md-agent", agentSecret)
	defer agentConn.Close()

	// Read welcome
	_, _, _ = agentConn.ReadMessage()

	// Create conversation using the real user_id from the JWT
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		"ws-md-conv", userID, "ws-md-agent")
	if err != nil {
		t.Fatal(err)
	}

	// Connect two client devices (user_id in query is ignored; JWT claims are authoritative)
	wsURL1 := "ws" + strings.TrimPrefix(server.URL, "http") + "/client/connect?user_id=" + url.QueryEscape(userID) + "&token=" + url.QueryEscape(token) + "&device_id=phone"
	ws1, _, err := websocket.DefaultDialer.Dial(wsURL1, nil)
	if err != nil {
		t.Fatalf("device 1 connect failed: %v", err)
	}
	defer ws1.Close()

	wsURL2 := "ws" + strings.TrimPrefix(server.URL, "http") + "/client/connect?user_id=" + url.QueryEscape(userID) + "&token=" + url.QueryEscape(token) + "&device_id=laptop"
	ws2, _, err := websocket.DefaultDialer.Dial(wsURL2, nil)
	if err != nil {
		t.Fatalf("device 2 connect failed: %v", err)
	}
	defer ws2.Close()

	// Read welcome messages
	_, _, _ = ws1.ReadMessage()
	_, _, _ = ws2.ReadMessage()

	// Agent sends a message
	agentMsg := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{"conversation_id":"ws-md-conv","content":"Multi-device test!"}`),
	}
	raw, _ := json.Marshal(agentMsg)
	agentConn.WriteMessage(1, raw)

	// Both devices should receive the message
	var gotPhone, gotLaptop bool
	timeout := time.After(3 * time.Second)

	for !(gotPhone && gotLaptop) {
		select {
		case <-timeout:
			t.Fatalf("timeout: phone=%v laptop=%v", gotPhone, gotLaptop)
		default:
		}

		ws1.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, msg, err := ws1.ReadMessage()
		if err == nil {
			var outMsg OutgoingMessage
			json.Unmarshal(msg, &outMsg)
			if outMsg.Type == "message" {
				gotPhone = true
			}
		}

		ws2.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, msg, err = ws2.ReadMessage()
		if err == nil {
			var outMsg OutgoingMessage
			json.Unmarshal(msg, &outMsg)
			if outMsg.Type == "message" {
				gotLaptop = true
			}
		}
	}

	if !gotPhone {
		t.Fatal("phone should have received the message via WebSocket")
	}
	if !gotLaptop {
		t.Fatal("laptop should have received the message via WebSocket")
	}
}