package a2a

import (
	"fmt"
	"sync"
)

// TaskStore is an in-memory store for A2A tasks.
// It is safe for concurrent access via mutex.
// Supports SSE streaming via subscriber channels.
type TaskStore struct {
	mu          sync.RWMutex
	tasks       map[string]*Task
	subscribers map[string][]chan Task
}

// NewTaskStore creates a new empty task store.
func NewTaskStore() *TaskStore {
	return &TaskStore{
		tasks:       make(map[string]*Task),
		subscribers: make(map[string][]chan Task),
	}
}

// Create adds a new task to the store and notifies subscribers.
func (ts *TaskStore) Create(task *Task) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if _, exists := ts.tasks[task.ID]; exists {
		return fmt.Errorf("task %s already exists", task.ID)
	}

	ts.tasks[task.ID] = task
	ts.notify(task.ID)
	return nil
}

// Get retrieves a task by ID.
func (ts *TaskStore) Get(id string) (*Task, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	task, exists := ts.tasks[id]
	if !exists {
		return nil, fmt.Errorf("task %s not found", id)
	}
	return task, nil
}

// Update applies a mutation function to a task and notifies subscribers.
func (ts *TaskStore) Update(id string, fn func(*Task) error) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	task, exists := ts.tasks[id]
	if !exists {
		return fmt.Errorf("task %s not found", id)
	}

	if err := fn(task); err != nil {
		return err
	}

	ts.notify(id)
	return nil
}

// Subscribe returns a buffered channel that receives a copy of the task
// on every state change. The caller MUST call Unsubscribe to avoid leaks.
func (ts *TaskStore) Subscribe(taskID string) chan Task {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ch := make(chan Task, 32)
	ts.subscribers[taskID] = append(ts.subscribers[taskID], ch)
	return ch
}

// Unsubscribe removes a subscriber channel and closes it.
func (ts *TaskStore) Unsubscribe(taskID string, ch chan Task) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	subs := ts.subscribers[taskID]
	for i, sub := range subs {
		if sub == ch {
			ts.subscribers[taskID] = append(subs[:i], subs[i+1:]...)
			close(ch)
			return
		}
	}
}

// notify sends the current task state to all subscribers.
// Must be called with ts.mu held (write lock).
func (ts *TaskStore) notify(taskID string) {
	task, exists := ts.tasks[taskID]
	if !exists {
		return
	}
	for _, ch := range ts.subscribers[taskID] {
		select {
		case ch <- *task:
		default:
			// Drop notification if subscriber is slow
		}
	}
}

// Delete removes a task from the store.
func (ts *TaskStore) Delete(id string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.tasks, id)
}

// List returns all tasks in the store.
func (ts *TaskStore) List() []*Task {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	result := make([]*Task, 0, len(ts.tasks))
	for _, task := range ts.tasks {
		result = append(result, task)
	}
	return result
}
