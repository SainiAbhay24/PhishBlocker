// PhishBlocker - PC Endpoint Telemetry Agent (prototype)
//
// This is a SYNTHETIC telemetry generator, matching Phase 3 of the
// project roadmap: "For the college project it should use synthetic
// or authorized local telemetry." It does NOT hook real OS APIs,
// inspect other processes, or capture keystrokes. It simulates a
// small, realistic sequence of endpoint events and POSTs them to the
// PhishBlocker backend for correlation.
//
// Run with:  go run main.go
// Or build:  go build -o phishblocker-agent && ./phishblocker-agent

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const apiBase = "http://localhost:8000"

// TelemetryEvent mirrors backend/models.py::TelemetryEvent
type TelemetryEvent struct {
	DeviceID    string `json:"device_id"`
	EventType   string `json:"event_type"`
	Description string `json:"description"`
	ProcessName string `json:"process_name,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	Severity    string `json:"severity"`
}

type TelemetryAck struct {
	Received            bool   `json:"received"`
	EventID             string `json:"event_id"`
	CorrelatedIncident  string `json:"correlated_incident"`
}

func sendEvent(event TelemetryEvent) (*TelemetryAck, error) {
	body, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(apiBase+"/telemetry", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("could not reach PhishBlocker backend: %w", err)
	}
	defer resp.Body.Close()

	var ack TelemetryAck
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		return nil, err
	}
	return &ack, nil
}

func main() {
	deviceID := "LAB-PC-01"
	if len(os.Args) > 1 {
		deviceID = os.Args[1]
	}

	fmt.Printf("PhishBlocker Endpoint Agent starting on device=%s\n", deviceID)
	fmt.Println("Simulating a synthetic suspicious activity chain (authorized lab data only)...")
	fmt.Println()

	// A synthetic event chain modeled on section 6 of the roadmap:
	// document process -> PowerShell -> suspicious command -> credential-access -> lateral movement
	events := []TelemetryEvent{
		{
			DeviceID:    deviceID,
			EventType:   "process_start",
			Description: "Office document spawned a child process",
			ProcessName: "WINWORD.EXE -> powershell.exe",
			Severity:    "MEDIUM",
		},
		{
			DeviceID:    deviceID,
			EventType:   "powershell_command",
			Description: "Encoded PowerShell command executed",
			ProcessName: "powershell.exe",
			CommandLine: "powershell -enc SQBFAFgA...(synthetic/truncated)",
			Severity:    "HIGH",
		},
		{
			DeviceID:    deviceID,
			EventType:   "credential_access_indicator",
			Description: "Process attempted to access stored credential vault (synthetic)",
			ProcessName: "powershell.exe",
			Severity:    "HIGH",
		},
		{
			DeviceID:    deviceID,
			EventType:   "lateral_movement_indicator",
			Description: "Outbound SMB connection attempt to internal host (synthetic/lab)",
			ProcessName: "powershell.exe",
			Severity:    "CRITICAL",
		},
	}

	for i, ev := range events {
		fmt.Printf("[%s] Sending event %d/%d: %s (%s)\n",
			time.Now().Format("15:04:05"), i+1, len(events), ev.EventType, ev.Severity)

		ack, err := sendEvent(ev)
		if err != nil {
			fmt.Println("  ERROR:", err)
			fmt.Println("  (Is the backend running? -> uvicorn main:app --reload --port 8000)")
			os.Exit(1)
		}

		fmt.Printf("  -> acknowledged, event_id=%s\n", ack.EventID)
		if ack.CorrelatedIncident != "" {
			fmt.Printf("  !! CORRELATION TRIGGERED -> incident %s\n", ack.CorrelatedIncident)
		}

		time.Sleep(1 * time.Second)
	}

	fmt.Println()
	fmt.Println("Synthetic telemetry sequence complete.")
}
