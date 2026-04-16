package main

import (
	"encoding/json"
	"log"
)

// Message types
const (
	MsgTypeMessage  = "message"
	MsgTypeTyping   = "typing"
	MsgTypeStatus   = "status"
	MsgTypeError    = "error"
	MsgTypeHistReq  = "history_request"
	MsgTypeHistResp = "history_response"
)

// RoutedMessage is the internal message structure for routing
type RoutedMessage struct {
	Type           string `json:"type"`
	ConversationID string `json:"conversation_id"`
	Content        string `json:"content"`
	SenderType     string `json:"sender_type"`
	SenderID       string `json:"sender_id"`
	RecipientID    string `json:"recipient_id"`
	Timestamp      string `json:"timestamp,omitempty"`
}

// routeMessage handles incoming messages and routes them to the correct recipient
func routeMessage(sender *Connection, raw []byte) {
	// Rate limit check
	if !checkRateLimit(sender) {
		return
	}

	var msg IncomingMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		log.Printf("Invalid message from %s %s: %v", sender.connType, sender.id, err)
		sendError(sender, "invalid message format")
		return
	}

	switch msg.Type {
	case MsgTypeMessage:
		routeChatMessage(sender, msg.Data)
	case MsgTypeTyping:
		routeTypingIndicator(sender, msg.Data)
	case MsgTypeStatus:
		routeStatusUpdate(sender, msg.Data)
	default:
		log.Printf("Unknown message type %q from %s %s", msg.Type, sender.connType, sender.id)
		sendError(sender, "unknown message type: "+msg.Type)
	}
}

// routeChatMessage handles a chat message: validate, persist, and deliver
func routeChatMessage(sender *Connection, data json.RawMessage) {
	var msg RoutedMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Printf("Invalid chat message from %s %s: %v", sender.connType, sender.id, err)
		sendError(sender, "invalid message data")
		return
	}

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
		log.Printf("Error fetching conversation %s: %v", msg.ConversationID, err)
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

	// Persist message
	if err := storeMessage(msg); err != nil {
		log.Printf("Error storing message: %v", err)
		sendError(sender, "failed to store message")
		return
	}

	// Deliver to recipient if online
	outgoing, err := json.Marshal(OutgoingMessage{Type: MsgTypeMessage, Data: msg})
	if err != nil {
		log.Printf("Error marshaling outgoing message: %v", err)
		return
	}

	if sender.connType == "agent" {
		if client := hub.GetClient(recipientID); client != nil {
			select {
			case client.send <- outgoing:
			default:
				log.Printf("Client %s send buffer full, dropping message", recipientID)
			}
		}
	} else {
		if agent := hub.GetAgent(recipientID); agent != nil {
			select {
			case agent.send <- outgoing:
			default:
				log.Printf("Agent %s send buffer full, dropping message", recipientID)
			}
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
	select {
	case sender.send <- ackData:
	default:
	}
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
			"sender_id":        sender.id,
		},
	}
	outData, _ := json.Marshal(outgoing)

	if sender.connType == "agent" {
		if client := hub.GetClient(recipientID); client != nil {
			select {
			case client.send <- outData:
			default:
			}
		}
	} else {
		if agent := hub.GetAgent(recipientID); agent != nil {
			select {
			case agent.send <- outData:
			default:
			}
		}
	}
}

// routeStatusUpdate forwards status updates (e.g., agent goes idle/busy)
func routeStatusUpdate(sender *Connection, data json.RawMessage) {
	var payload struct {
		ConversationID string `json:"conversation_id"`
		Status         string `json:"status"`
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
			"sender_type":      sender.connType,
			"sender_id":         sender.id,
			"status":           payload.Status,
		},
	}
	outData, _ := json.Marshal(outgoing)

	if sender.connType == "agent" {
		if client := hub.GetClient(recipientID); client != nil {
			select {
			case client.send <- outData:
			default:
			}
		}
	} else {
		if agent := hub.GetAgent(recipientID); agent != nil {
			select {
			case agent.send <- outData:
			default:
			}
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
	select {
	case conn.send <- data:
	default:
	}
}