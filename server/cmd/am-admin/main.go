package main

import (
	"bufio"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	dbPath := flag.String("db", "./data/agent-messenger.db", "SQLite database path")
	flag.Parse()

	if flag.NArg() == 0 {
		printUsage()
		os.Exit(1)
	}

	switch flag.Arg(0) {
	case "create-agent":
		createAgent(*dbPath)
	case "create-user":
		createUser(*dbPath)
	case "list-agents":
		listAgents(*dbPath)
	case "list-users":
		listUsers(*dbPath)
	case "reset-apikey":
		resetAPIKey(*dbPath)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", flag.Arg(0))
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Agent Messenger Admin CLI

Usage: am-admin [flags] <command> [args]

Commands:
  create-agent    Register a new agent (generates API key)
  create-user     Register a new user
  list-agents     List all registered agents
  list-users      List all registered users
  reset-apikey    Generate a new API key for an agent

Flags:
  -db string    SQLite database path (default "./data/agent-messenger.db")

Examples:
  am-admin -db ./data/agent-messenger.db create-agent
  am-admin -db ./data/agent-messenger.db list-agents
  am-admin -db ./data/agent-messenger.db reset-apikey`)
}

func createAgent(dbPath string) {
	reader := bufio.NewReader(os.Stdin)

	agentID := prompt(reader, "Agent ID", "")
	if agentID == "" {
		fmt.Fprintln(os.Stderr, "Agent ID is required")
		os.Exit(1)
	}

	name := prompt(reader, "Agent Name", agentID)
	model := prompt(reader, "Model (optional)", "")
	personality := prompt(reader, "Personality (optional)", "")
	specialty := prompt(reader, "Specialty (optional)", "")

	// Generate API key
	apiKey := generateAPIKey()
	hash, err := bcrypt.GenerateFromPassword([]byte(apiKey), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error hashing API key: %v\n", err)
		os.Exit(1)
	}

	db := openDB(dbPath)
	defer db.Close()

	_, err = db.Exec(`INSERT INTO agents (id, api_key_hash, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?, ?)`,
		agentID, string(hash), name, model, personality, specialty)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating agent: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n✅ Agent created successfully!")
	fmt.Printf("   ID:         %s\n", agentID)
	fmt.Printf("   Name:       %s\n", name)
	if model != "" {
		fmt.Printf("   Model:      %s\n", model)
	}
	if personality != "" {
		fmt.Printf("   Personality: %s\n", personality)
	}
	if specialty != "" {
		fmt.Printf("   Specialty:  %s\n", specialty)
	}
	fmt.Println()
	fmt.Println("⚠️  API Key (save this — it won't be shown again):")
	fmt.Printf("   %s\n", apiKey)
}

func createUser(dbPath string) {
	reader := bufio.NewReader(os.Stdin)

	username := prompt(reader, "Username", "")
	if username == "" {
		fmt.Fprintln(os.Stderr, "Username is required")
		os.Exit(1)
	}

	password := prompt(reader, "Password", "")
	if password == "" {
		fmt.Fprintln(os.Stderr, "Password is required")
		os.Exit(1)
	}

	userID := generateID("user")
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error hashing password: %v\n", err)
		os.Exit(1)
	}

	db := openDB(dbPath)
	defer db.Close()

	_, err = db.Exec(`INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)`,
		userID, username, string(hash))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating user: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n✅ User created successfully!")
	fmt.Printf("   ID:       %s\n", userID)
	fmt.Printf("   Username: %s\n", username)
}

func listAgents(dbPath string) {
	db := openDB(dbPath)
	defer db.Close()

	rows, err := db.Query(`SELECT id, name, model, personality, specialty, created_at FROM agents ORDER BY created_at`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying agents: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	fmt.Println("\nRegistered Agents:")
	fmt.Println(strings.Repeat("-", 60))

	count := 0
	for rows.Next() {
		var id, name, model, personality, specialty, createdAt string
		if err := rows.Scan(&id, &name, &model, &personality, &specialty, &createdAt); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading row: %v\n", err)
			continue
		}
		count++
		fmt.Printf("  %-15s  %s", id, name)
		if model != "" {
			fmt.Printf("  [%s]", model)
		}
		fmt.Println()
		if personality != "" {
			fmt.Printf("    Personality: %s\n", personality)
		}
		if specialty != "" {
			fmt.Printf("    Specialty:  %s\n", specialty)
		}
		fmt.Printf("    Created:    %s\n", createdAt)
	}

	if count == 0 {
		fmt.Println("  (no agents registered)")
	}
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Total: %d\n", count)
}

func listUsers(dbPath string) {
	db := openDB(dbPath)
	defer db.Close()

	rows, err := db.Query(`SELECT id, username, created_at FROM users ORDER BY created_at`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying users: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	fmt.Println("\nRegistered Users:")
	fmt.Println(strings.Repeat("-", 60))

	count := 0
	for rows.Next() {
		var id, username, createdAt string
		if err := rows.Scan(&id, &username, &createdAt); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading row: %v\n", err)
			continue
		}
		count++
		fmt.Printf("  %-15s  %s  (%s)\n", username, id, createdAt)
	}

	if count == 0 {
		fmt.Println("  (no users registered)")
	}
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Total: %d\n", count)
}

func resetAPIKey(dbPath string) {
	reader := bufio.NewReader(os.Stdin)

	agentID := prompt(reader, "Agent ID", "")
	if agentID == "" {
		fmt.Fprintln(os.Stderr, "Agent ID is required")
		os.Exit(1)
	}

	apiKey := generateAPIKey()
	hash, err := bcrypt.GenerateFromPassword([]byte(apiKey), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error hashing API key: %v\n", err)
		os.Exit(1)
	}

	db := openDB(dbPath)
	defer db.Close()

	result, err := db.Exec(`UPDATE agents SET api_key_hash = ? WHERE id = ?`, string(hash), agentID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resetting API key: %v\n", err)
		os.Exit(1)
	}

	if n, _ := result.RowsAffected(); n == 0 {
		fmt.Fprintf(os.Stderr, "Agent %s not found\n", agentID)
		os.Exit(1)
	}

	fmt.Println("\n✅ API key reset successfully!")
	fmt.Println()
	fmt.Println("⚠️  New API Key (save this — it won't be shown again):")
	fmt.Printf("   %s\n", apiKey)
}

func prompt(reader *bufio.Reader, label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("%s: ", label)
	}
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return defaultVal
	}
	return text
}

func generateAPIKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "am_" + hex.EncodeToString(b)
}

func generateID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b)
}

func openDB(dbPath string) *sql.DB {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	return db
}