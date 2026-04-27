package main

import (
	"testing"
)

func TestParseSize(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		wantErr  bool
	}{
		{"50MB", 50 << 20, false},
		{"50MB", 50 * 1024 * 1024, false},
		{"100MB", 100 << 20, false},
		{"1GB", 1 << 30, false},
		{"500KB", 500 << 10, false},
		{"1TB", 1 << 40, false},
		{"1024B", 1024, false},
		{"1024", 1024, false},
		{"50mb", 50 << 20, false}, // case insensitive
		{"50 Mb", 50 << 20, false}, // space ok
		{"0", 0, false},
		{"", 0, true},           // empty
		{"abc", 0, true},        // invalid
		{"10XB", 0, true},       // unknown suffix
	}

	for _, tt := range tests {
		got, err := parseSize(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseSize(%q): expected error, got %d", tt.input, got)
			}
		} else {
			if err != nil {
				t.Errorf("parseSize(%q): unexpected error: %v", tt.input, err)
			}
			if got != tt.expected {
				t.Errorf("parseSize(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		}
	}
}

func TestGetMaxUploadSize(t *testing.T) {
	// Default should be 50MB
	orig := maxUploadSize
	maxUploadSize = MaxUploadSize
	if got := getMaxUploadSize(); got != 50<<20 {
		t.Errorf("Default getMaxUploadSize() = %d, want %d", got, 50<<20)
	}

	// Set to 100MB
	maxUploadSize = 100 << 20
	if got := getMaxUploadSize(); got != 100<<20 {
		t.Errorf("Custom getMaxUploadSize() = %d, want %d", got, 100<<20)
	}

	maxUploadSize = orig
}