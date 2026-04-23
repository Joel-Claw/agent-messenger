package main

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// OfflineQueue buffers messages for disconnected clients/agents.
// When a user or agent goes offline, messages destined for them are
// queued and replayed when they reconnect.
type OfflineQueue struct {
	mu      sync.Mutex
	buffers map[string][]queuedMessage // key = user_id or agent_id
	maxLen  int                        // max messages per recipient
	ttl     time.Duration              // how long to keep stale messages
}

type queuedMessage struct {
	data      []byte
	queuedAt  time.Time
	sentCount int // how many times we've tried to deliver
}

// newOfflineQueue creates a new message queue.
// maxLen is the maximum queued messages per recipient (0 = unlimited).
// ttl is how long to keep undelivered messages before discarding them.
func newOfflineQueue(maxLen int, ttl time.Duration) *OfflineQueue {
	if maxLen <= 0 {
		maxLen = 100
	}
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour // default: 7 days
	}
	return &OfflineQueue{
		buffers: make(map[string][]queuedMessage),
		maxLen:  maxLen,
		ttl:     ttl,
	}
}

// Enqueue adds a message to the recipient's offline queue.
// Called when the recipient is not currently connected.
func (q *OfflineQueue) Enqueue(recipientID string, data []byte) {
	q.mu.Lock()
	defer q.mu.Unlock()

	msg := queuedMessage{
		data:      data,
		queuedAt:  time.Now(),
		sentCount: 0,
	}

	buf := q.buffers[recipientID]
	buf = append(buf, msg)

	// Trim oldest if over max
	if len(buf) > q.maxLen {
		buf = buf[len(buf)-q.maxLen:]
	}

	q.buffers[recipientID] = buf
	log.Printf("Queued offline message for %s (queue depth: %d)", recipientID, len(buf))
}

// Drain removes all queued messages for a recipient, returning them in order.
// Called when a recipient reconnects. Returns nil if no messages are queued.
func (q *OfflineQueue) Drain(recipientID string) [][]byte {
	q.mu.Lock()
	defer q.mu.Unlock()

	buf, ok := q.buffers[recipientID]
	if !ok || len(buf) == 0 {
		return nil
	}

	// Filter out expired messages and collect valid ones
	now := time.Now()
	var result [][]byte
	var remaining []queuedMessage

	for _, msg := range buf {
		if now.Sub(msg.queuedAt) > q.ttl {
			log.Printf("Discarding expired offline message for %s (aged %v)", recipientID, now.Sub(msg.queuedAt))
			continue
		}
		result = append(result, msg.data)
	}

	delete(q.buffers, recipientID)

	if len(remaining) > 0 {
		q.buffers[recipientID] = remaining
	}

	log.Printf("Drained %d offline messages for %s", len(result), recipientID)
	return result
}

// Purge removes all queued messages for a recipient.
func (q *OfflineQueue) Purge(recipientID string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.buffers, recipientID)
}

// QueueDepth returns the number of queued messages for a recipient.
func (q *OfflineQueue) QueueDepth(recipientID string) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.buffers[recipientID])
}

// TotalDepth returns the total number of queued messages across all recipients.
func (q *OfflineQueue) TotalDepth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	total := 0
	for _, buf := range q.buffers {
		total += len(buf)
	}
	return total
}

// replayOfflineMessages sends all queued messages to a newly connected
// client or agent. Called after a successful WebSocket connection.
func replayOfflineMessages(conn *Connection) {
	if offlineQueue == nil {
		return
	}

	messages := offlineQueue.Drain(conn.id)
	if len(messages) == 0 {
		return
	}

	log.Printf("Replaying %d offline messages to %s %s", len(messages), conn.connType, conn.id)

	for _, data := range messages {
		// Parse to check if it's a chat message (skip typing/status)
		var outMsg OutgoingMessage
		if err := json.Unmarshal(data, &outMsg); err == nil {
			// Only replay actual messages, not transient events
			if outMsg.Type == MsgTypeMessage || outMsg.Type == "read_receipt" {
				select {
				case conn.send <- data:
				default:
					log.Printf("Send buffer full while replaying offline messages to %s %s, stopping replay", conn.connType, conn.id)
					return
				}
			}
		}
	}
}