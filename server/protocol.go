package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

const (
	// ProtocolVersion is the current WebSocket sub-protocol version
	ProtocolVersion = "v1"

	// SupportedVersions lists all supported protocol versions
	SupportedVersions = "v1"
)

// negotiateProtocol selects the best protocol version from the client's request.
// If the client sends Sec-WebSocket-Protocol, we pick the first matching version.
// Otherwise, we default to the latest (ProtocolVersion).
func negotiateProtocol(r *http.Request) string {
	// Check Sec-WebSocket-Protocol header
	protocols := strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",")
	for _, p := range protocols {
		p = strings.TrimSpace(p)
		if isSupportedVersion(p) {
			return p
		}
	}

	// Check query param fallback
	if v := r.URL.Query().Get("protocol_version"); v != "" {
		if isSupportedVersion(v) {
			return v
		}
	}

	// Default to latest
	return ProtocolVersion
}

func isSupportedVersion(v string) bool {
	for _, sv := range strings.Split(SupportedVersions, ",") {
		if strings.TrimSpace(sv) == v {
			return true
		}
	}
	return false
}

// upgradeWithProtocol performs a WebSocket upgrade with sub-protocol negotiation.
// It sets the Sec-WebSocket-Protocol response header to the negotiated version.
func upgradeWithProtocol(w http.ResponseWriter, r *http.Request, negotiated string) {
	// Set the response header for the negotiated sub-protocol
	// This must be done before the upgrade
	if negotiated != "" && isSupportedVersion(negotiated) {
		w.Header().Set("Sec-WebSocket-Protocol", negotiated)
	}
}

// sendWelcomeMessage sends the initial welcome message with protocol version info
func sendWelcomeMessage(connType, id, deviceID, protocolVersion string, send chan []byte) {
	welcomeData := map[string]interface{}{
		"id":               id,
		"status":           "connected",
		"protocol_version": protocolVersion,
		"supported_versions": strings.Split(SupportedVersions, ","),
	}
	if deviceID != "" {
		welcomeData["device_id"] = deviceID
	}

	welcome := OutgoingMessage{
		Type: "connected",
		Data: welcomeData,
	}
	data, err := json.Marshal(welcome)
	if err != nil {
		log.Printf("Failed to marshal welcome message: %v", err)
		return
	}
	select {
	case send <- data:
	default:
		log.Printf("Send buffer full, dropping welcome message for %s", id)
	}
}