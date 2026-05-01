package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// LogLevel represents the severity of a log message.
type LogLevel int

const (
	LogDebug LogLevel = iota
	LogInfo
	LogWarn
	LogError
)

// String returns the string representation of a LogLevel.
func (l LogLevel) String() string {
	switch l {
	case LogDebug:
		return "debug"
	case LogInfo:
		return "info"
	case LogWarn:
		return "warn"
	case LogError:
		return "error"
	default:
		return "unknown"
	}
}

// Logger provides structured JSON logging with log levels.
// It is safe for concurrent use.
type Logger struct {
	mu     sync.Mutex
	output io.Writer
	level  LogLevel
	fields map[string]interface{}
}

// DefaultLogger is the global structured logger instance.
var DefaultLogger = NewLogger(LogInfo)

// NewLogger creates a new Logger that writes to stdout with the given minimum level.
func NewLogger(level LogLevel) *Logger {
	return &Logger{
		output: os.Stdout,
		level:  level,
		fields: make(map[string]interface{}),
	}
}

// SetLevel changes the minimum log level.
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetOutput changes the output destination.
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

// WithFields returns a new Logger with the given fields attached to all log entries.
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	merged := make(map[string]interface{}, len(l.fields)+len(fields))
	for k, v := range l.fields {
		merged[k] = v
	}
	for k, v := range fields {
		merged[k] = v
	}
	return &Logger{
		output: l.output,
		level:  l.level,
		fields: merged,
	}
}

// logEntry writes a structured log entry.
func (l *Logger) logEntry(level LogLevel, msg string, fields map[string]interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry := make(map[string]interface{}, len(l.fields)+len(fields)+3)
	entry["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	entry["level"] = level.String()
	entry["msg"] = msg

	for k, v := range l.fields {
		entry[k] = v
	}
	for k, v := range fields {
		entry[k] = v
	}

	data, err := json.Marshal(entry)
	if err != nil {
		// Fallback: just write the message
		log.Printf("logger marshal error: %v, original msg: %s", err, msg)
		return
	}

	l.output.Write(append(data, '\n'))
}

// Debug logs a debug-level message with optional fields.
func (l *Logger) Debug(msg string, fields ...map[string]interface{}) {
	f := mergeOpt(fields)
	l.logEntry(LogDebug, msg, f)
}

// Info logs an info-level message with optional fields.
func (l *Logger) Info(msg string, fields ...map[string]interface{}) {
	f := mergeOpt(fields)
	l.logEntry(LogInfo, msg, f)
}

// Warn logs a warning-level message with optional fields.
func (l *Logger) Warn(msg string, fields ...map[string]interface{}) {
	f := mergeOpt(fields)
	l.logEntry(LogWarn, msg, f)
}

// Error logs an error-level message with optional fields.
func (l *Logger) Error(msg string, fields ...map[string]interface{}) {
	f := mergeOpt(fields)
	l.logEntry(LogError, msg, f)
}

// mergeOpt merges optional field maps into one.
func mergeOpt(fields []map[string]interface{}) map[string]interface{} {
	if len(fields) == 0 {
		return nil
	}
	result := make(map[string]interface{})
	for _, m := range fields {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}