// Package a2a implements the A2A Agent-to-Agent Task Protocol.
//
// It provides JSON-RPC 2.0 task lifecycle management with a 6-state
// state machine: submitted → working → (completed | failed | canceled),
// with input-required as a pause state.
package a2a

import "fmt"

// TaskState represents the lifecycle state of an A2A task.
type TaskState string

const (
	TaskStateSubmitted    TaskState = "submitted"
	TaskStateWorking      TaskState = "working"
	TaskStateInputRequired TaskState = "input-required"
	TaskStateCompleted    TaskState = "completed"
	TaskStateFailed       TaskState = "failed"
	TaskStateCanceled     TaskState = "canceled"
)

// ValidTransitions defines the allowed state transitions.
var ValidTransitions = map[TaskState][]TaskState{
	TaskStateSubmitted:     {TaskStateWorking, TaskStateFailed, TaskStateCanceled},
	TaskStateWorking:       {TaskStateInputRequired, TaskStateCompleted, TaskStateFailed, TaskStateCanceled},
	TaskStateInputRequired: {TaskStateWorking, TaskStateCanceled},
	TaskStateCompleted:     {},
	TaskStateFailed:        {},
	TaskStateCanceled:      {},
}

// IsValidTransition checks if moving from current to next is allowed.
func IsValidTransition(current, next TaskState) bool {
	for _, allowed := range ValidTransitions[current] {
		if allowed == next {
			return true
		}
	}
	return false
}

// PartType identifies the content type of a message part.
type PartType string

const (
	PartTypeText            PartType = "text"
	PartTypeFile            PartType = "file"
	PartTypeFunctionCall    PartType = "function_call"
	PartTypeFunctionResponse PartType = "function_response"
)

// Part is a single piece of content within a task message.
type Part struct {
	Type PartType `json:"type"`
	Text string   `json:"text,omitempty"`

	// File fields
	FileURI     string `json:"fileUri,omitempty"`
	FileMimeType string `json:"fileMimeType,omitempty"`

	// Function call/response fields
	FunctionName string                 `json:"functionName,omitempty"`
	Arguments    map[string]interface{} `json:"arguments,omitempty"`
	FunctionResponse interface{}        `json:"functionResponse,omitempty"`
}

// TaskMessage is a message exchanged within a task.
type TaskMessage struct {
	Role  string `json:"role"` // "user" or "agent"
	Parts []Part `json:"parts"`
}

// TaskStatus represents the current status of a task.
type TaskStatus struct {
	State   TaskState     `json:"state"`
	Message *TaskMessage `json:"message,omitempty"`
}

// Task represents an A2A task with its full lifecycle.
type Task struct {
	ID        string                 `json:"id"`
	SessionID string                 `json:"sessionId"`
	Status    TaskStatus             `json:"status"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// JSON-RPC 2.0 structures

// JSONRPCRequest is a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

// JSONRPCResponse is a JSON-RPC 2.0 success response.
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Result  interface{} `json:"result"`
}

// JSONRPCError is a JSON-RPC 2.0 error response.
type JSONRPCError struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Error   struct {
		Code    int         `json:"code"`
		Message string      `json:"message"`
		Data    interface{} `json:"data,omitempty"`
	} `json:"error"`
}

// NewJSONRPCError creates a JSON-RPC error response.
func NewJSONRPCError(id int, code int, msg string) *JSONRPCError {
	err := &JSONRPCError{JSONRPC: "2.0", ID: id}
	err.Error.Code = code
	err.Error.Message = msg
	return err
}

// TaskSendParams are the parameters for tasks/send.
type TaskSendParams struct {
	ID        string                 `json:"id"`
	SessionID string                 `json:"sessionId"`
	Message   TaskMessage            `json:"message"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// TaskGetParams are the parameters for tasks/get.
type TaskGetParams struct {
	ID string `json:"id"`
}

// TaskCancelParams are the parameters for tasks/cancel.
type TaskCancelParams struct {
	ID string `json:"id"`
}

// Validate checks if the task state transition is valid and returns an error if not.
func (t *Task) Transition(nextState TaskState) error {
	if !IsValidTransition(t.Status.State, nextState) {
		return fmt.Errorf("invalid transition from %s to %s", t.Status.State, nextState)
	}
	t.Status.State = nextState
	return nil
}
