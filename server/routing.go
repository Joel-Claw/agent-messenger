package main

import (
	"context"
	"encoding/json"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Message types
const (
	MsgTypeMessage   = "message"
	MsgTypeTyping    = "typing"
	MsgTypeStatus    = "status"
	MsgTypeError     = "error"
	MsgTypeHistReq   = "history_request"
	MsgTypeHistResp  = "history_response"
	MsgTypeHeartbeat = "heartbeat"
)

// RoutedMessage is the internal message structure for routing
type RoutedMessage struct {
	Type           string   `json:"type"`
	ConversationID string   `json:"conversation_id"`
	Content        string   `json:"content"`
	AttachmentIDs  []string `json:"attachment_ids,omitempty"`
	SenderType     string   `json:"sender_type"`
	SenderID       string   `json:"sender_id"`
	RecipientID    string   `json:"recipient_id"`
	Timestamp      string   `json:"timestamp,omitempty"`
}

// routeMessage handles incoming messages and routes them to the correct recipient
func routeMessage(sender *Connection, raw []byte) {
	// Start top-level routing span
	span := TraceRouteMessage(sender.connType, sender.id)
	defer span.End()

	// Rate limit check
	if !checkRateLimit(sender) {
		span.AddEvent("rate_limited", trace.WithAttributes(
			attribute.String(attrConnType, sender.connType),
			attribute.String(attrConnID, sender.id),
		))
		return
	}

	var msg IncomingMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		DefaultLogger.Warn("invalid_message", map[string]interface{}{"conn_type": sender.connType, "id": sender.id, "error": err.Error()})
		DefaultLogger.Warn("invalid_message", map[string]interface{}{"conn_type": sender.connType, "id": sender.id, "error": err.Error()})
		SpanError(span, err)
		sendError(sender, "invalid message format")
		return
	}

	span.SetAttributes(attribute.String(attrMessageType, msg.Type))

	switch msg.Type {
	case MsgTypeMessage:
		routeChatMessage(sender, msg.Data)
	case MsgTypeTyping:
		routeTypingIndicator(sender, msg.Data)
	case MsgTypeStatus:
		routeStatusUpdate(sender, msg.Data)
	case MsgTypeHeartbeat:
		routeHeartbeat(sender)
	default:
		DefaultLogger.Warn("unknown_message_type", map[string]interface{}{"type": msg.Type, "conn_type": sender.connType, "id": sender.id})
		DefaultLogger.Warn("unknown_message_type", map[string]interface{}{"type": msg.Type, "conn_type": sender.connType, "id": sender.id})
		sendError(sender, "unknown message type: "+msg.Type)
	}
}

// routeChatMessage handles a chat message: validate, persist, and deliver
func routeChatMessage(sender *Connection, data json.RawMessage) {
	_, span := TraceChatMessage(context.Background(), sender.connType, sender.id, "", "")
	defer span.End()

	var msg RoutedMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		DefaultLogger.Warn("invalid_chat_message", map[string]interface{}{"conn_type": sender.connType, "id": sender.id, "error": err.Error()})
		SpanError(span, err)
		sendError(sender, "invalid message data")
		return
	}

	span.SetAttributes(
		attribute.String(attrConversationID, msg.ConversationID),
		attribute.String(attrSenderType, sender.connType),
		attribute.String(attrSenderID, sender.id),
	)

	if msg.Content == "" {
		sendError(sender, "content is required")
		return
	}

	if msg.ConversationID == "" {
		sendError(sender, "conversation_id is required")
		return
	}

	msg.SenderType = sender.connType
	msg.SenderID = sender.id
	msg.Type = MsgTypeMessage

	// Verify conversation exists and sender is a participant
	conv, err := getConversation(msg.ConversationID)
	if err != nil {
		DefaultLogger.Error("conversation_fetch_error", map[string]interface{}{"conversation_id": msg.ConversationID, "error": err.Error()})
		SpanError(span, err)
		sendError(sender, "conversation not found")
		return
	}
	if conv == nil {
		sendError(sender, "conversation not found")
		return
	}

	// Validate sender is part of the conversation
	if sender.connType == "agent" && conv.AgentID != sender.id {
		sendError(sender, "not authorized for this conversation")
		return
	}
	if sender.connType == "client" && conv.UserID != sender.id {
		sendError(sender, "not authorized for this conversation")
		return
	}

	// Determine recipient
	var recipientID string
	if sender.connType == "agent" {
		msg.RecipientID = conv.UserID
		recipientID = conv.UserID
	} else {
		msg.RecipientID = conv.AgentID
		recipientID = conv.AgentID
	}

	span.SetAttributes(attribute.String(attrRecipientID, recipientID))

	// Persist message (child span)
	_, storeSpan := TraceStoreMessage(context.Background(), msg.ConversationID, sender.id)
	if err := storeMessage(msg); err != nil {
		DefaultLogger.Error("message_store_error", map[string]interface{}{"error": err.Error()})
		DefaultLogger.Error("message_store_error", map[string]interface{}{"error": err.Error()})
		SpanError(storeSpan, err)
		storeSpan.End()
		sendError(sender, "failed to store message")
		return
	}
	SpanOK(storeSpan)
	storeSpan.End()

	// Deliver to recipient if online
	outgoing, err := json.Marshal(OutgoingMessage{Type: MsgTypeMessage, Data: msg})
	if err != nil {
		DefaultLogger.Error("message_marshal_error", map[string]interface{}{"error": err.Error()})
		return
	}

	if sender.connType == "agent" {
		// Deliver to ALL of the user's connected devices (multi-device sync)
		conns := hub.GetClientConns(recipientID)
		_, deliverSpan := TraceDeliverMessage(context.Background(), recipientID, "client", len(conns) > 0)
		if len(conns) > 0 {
			delivered := 0
			for _, client := range conns {
				if client.SafeSend(outgoing) {
					delivered++
				} else {
					DefaultLogger.Warn("client_buffer_full", map[string]interface{}{"user_id": recipientID, "device_id": client.deviceID})
				}
			}
			deliverSpan.SetAttributes(
				attribute.Int("messenger.devices_delivered", delivered),
				attribute.Int("messenger.devices_total", len(conns)),
			)
			if delivered == 0 {
				// All buffers full, queue for later
				offlineSpan := TraceOfflineEnqueue(recipientID)
				offlineQueue.Enqueue(recipientID, outgoing)
				persistQueue(db, recipientID, outgoing)
				offlineSpan.SetAttributes(attribute.Bool(attrBuffered, true))
				SpanOK(offlineSpan)
				offlineSpan.End()
				go notifyUser(recipientID, "New Message", truncate(msg.Content, 100), msg.ConversationID)
			}
		} else {
			// Client is offline on all devices, queue message for later delivery
			offlineSpan := TraceOfflineEnqueue(recipientID)
			offlineQueue.Enqueue(recipientID, outgoing)
			persistQueue(db, recipientID, outgoing)
			offlineSpan.SetAttributes(attribute.Bool(attrOffline, true))
			SpanOK(offlineSpan)
			offlineSpan.End()
			// Also send push notification for immediate awareness
			pushSpan := TracePushNotify(recipientID, msg.ConversationID, true)
			go notifyUser(recipientID, "New Message", truncate(msg.Content, 100), msg.ConversationID)
			pushSpan.SetAttributes(attribute.Bool(attrPushSent, true))
			pushSpan.End()
		}
		SpanOK(deliverSpan)
		deliverSpan.End()
	} else {
		if agent := hub.GetAgent(recipientID); agent != nil {
			_, deliverSpan := TraceDeliverMessage(context.Background(), recipientID, "agent", true)
			if agent.SafeSend(outgoing) {
				deliverSpan.SetAttributes(attribute.Bool(attrDelivered, true))
			} else {
				DefaultLogger.Warn("agent_buffer_full", map[string]interface{}{"agent_id": recipientID})
				deliverSpan.SetAttributes(attribute.Bool(attrDelivered, false))
				offlineSpan := TraceOfflineEnqueue(recipientID)
				offlineQueue.Enqueue(recipientID, outgoing)
				persistQueue(db, recipientID, outgoing)
				offlineSpan.SetAttributes(attribute.Bool(attrOffline, true))
				SpanOK(offlineSpan)
				offlineSpan.End()
			}
			SpanOK(deliverSpan)
			deliverSpan.End()
		} else {
			_, deliverSpan := TraceDeliverMessage(context.Background(), recipientID, "agent", false)
			deliverSpan.SetAttributes(attribute.Bool(attrDelivered, false))
			deliverSpan.End()

			// Agent is offline, queue message for later delivery
			offlineSpan := TraceOfflineEnqueue(recipientID)
			offlineQueue.Enqueue(recipientID, outgoing)
			persistQueue(db, recipientID, outgoing)
			offlineSpan.SetAttributes(attribute.Bool(attrOffline, true))
			SpanOK(offlineSpan)
			offlineSpan.End()
		}
	}

	// Send acknowledgment back to sender
	ack := OutgoingMessage{
		Type: "message_sent",
		Data: map[string]string{
			"conversation_id": msg.ConversationID,
			"status":          "delivered",
		},
	}
	ackData, _ := json.Marshal(ack)
	sender.SafeSend(ackData)
}

// routeTypingIndicator forwards typing indicators to the other party
func routeTypingIndicator(sender *Connection, data json.RawMessage) {
	var payload struct {
		ConversationID string `json:"conversation_id"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return
	}

	if payload.ConversationID == "" {
		return
	}

	conv, err := getConversation(payload.ConversationID)
	if err != nil || conv == nil {
		return
	}

	// Validate sender is part of the conversation
	if sender.connType == "agent" && conv.AgentID != sender.id {
		return
	}
	if sender.connType == "client" && conv.UserID != sender.id {
		return
	}

	var recipientID string
	if sender.connType == "agent" {
		recipientID = conv.UserID
	} else {
		recipientID = conv.AgentID
	}

	outgoing := OutgoingMessage{
		Type: MsgTypeTyping,
		Data: map[string]string{
			"conversation_id": payload.ConversationID,
			"sender_type":     sender.connType,
			"sender_id":       sender.id,
		},
	}
	outData, _ := json.Marshal(outgoing)

	if sender.connType == "agent" {
		// Send typing indicator to ALL user's devices
		for _, client := range hub.GetClientConns(recipientID) {
			client.SafeSend(outData)
		}
	} else {
		if agent := hub.GetAgent(recipientID); agent != nil {
			agent.SafeSend(outData)
		}
	}
}

// routeStatusUpdate forwards status updates (e.g., agent goes idle/busy)
// and updates the agent's availability status in the hub.
func routeStatusUpdate(sender *Connection, data json.RawMessage) {
	var payload struct {
		ConversationID string `json:"conversation_id"`
		Status         string `json:"status"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return
	}

	// Update agent status in hub if this is an agent
	if sender.connType == "agent" && payload.Status != "" {
		hub.SetAgentStatus(sender.id, payload.Status)

		// Broadcast status change to all connected clients
		outgoing := OutgoingMessage{
			Type: MsgTypeStatus,
			Data: map[string]string{
				"sender_type": sender.connType,
				"sender_id":   sender.id,
				"status":      payload.Status,
			},
		}
		outData, _ := json.Marshal(outgoing)
		hub.BroadcastToAllClients(outData)
	}

	if payload.ConversationID == "" {
		return
	}

	conv, err := getConversation(payload.ConversationID)
	if err != nil || conv == nil {
		return
	}

	var recipientID string
	if sender.connType == "agent" {
		recipientID = conv.UserID
	} else {
		recipientID = conv.AgentID
	}

	outgoing := OutgoingMessage{
		Type: MsgTypeStatus,
		Data: map[string]string{
			"conversation_id": payload.ConversationID,
			"sender_type":     sender.connType,
			"sender_id":       sender.id,
			"status":          payload.Status,
		},
	}
	outData, _ := json.Marshal(outgoing)

	if sender.connType == "agent" {
		// Send status update to ALL user's devices
		for _, client := range hub.GetClientConns(recipientID) {
			client.SafeSend(outData)
		}
	} else {
		if agent := hub.GetAgent(recipientID); agent != nil {
			agent.SafeSend(outData)
		}
	}
}

// sendError sends an error message to a connection
func sendError(conn *Connection, message string) {
	errMsg := OutgoingMessage{
		Type: MsgTypeError,
		Data: map[string]string{"error": message},
	}
	data, _ := json.Marshal(errMsg)
	safeSendToConn(conn, data)
}

// truncate shortens a string to maxLen characters
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// routeHeartbeat handles a heartbeat message from an agent.
// It updates the agent's lastHeartbeat timestamp and sends an ack back.
// Clients can also send heartbeats (they are accepted but only agent
// heartbeats are monitored for stale disconnection).
func routeHeartbeat(sender *Connection) {
	sender.hub.TouchHeartbeat(sender)

	// Send heartbeat acknowledgment
	ack := OutgoingMessage{
		Type: "heartbeat_ack",
		Data: map[string]interface{}{
			"server_time": time.Now().UTC().Format(time.RFC3339Nano),
			"interval_s":  int(agentPresenceInterval.Seconds()),
			"timeout_s":   int(agentPresenceTimeout.Seconds()),
			"monitoring":  agentPresenceEnabled,
		},
	}
	ackData, _ := json.Marshal(ack)
	sender.SafeSend(ackData)
}
