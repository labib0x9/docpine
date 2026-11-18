package sse

import "sync"

const (
	DefaultHistorySize = 512
	DefaultMaxRuns     = 256
)

type Event struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

type runStream struct {
	history  []Event
	finished bool
	subs     map[chan Event]struct{}
}

type Hub struct {
	mu          sync.Mutex
	historySize int
	maxRuns     int
	runs        map[int64]*runStream
	order       []int64
	closed      bool
}

func NewHub() *Hub {
	return NewHubWithOptions(DefaultHistorySize, DefaultMaxRuns)
}

func NewHubWithOptions(historySize, maxRuns int) *Hub {
	if historySize < 1 {
		historySize = 1
	}
	if maxRuns < 1 {
		maxRuns = 1
	}
	return &Hub{
		historySize: historySize,
		maxRuns:     maxRuns,
		runs:        make(map[int64]*runStream),
	}
}

func (h *Hub) Subscribe(runID int64) (<-chan Event, func()) {
	events := make(chan Event, h.historySize+2)
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		close(events)
		return events, func() {}
	}
	stream := h.streamLocked(runID)
	for _, event := range stream.history {
		events <- event
	}
	if stream.finished {
		close(events)
		return events, func() {}
	}
	stream.subs[events] = struct{}{}

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			h.mu.Lock()
			if current := h.runs[runID]; current != nil {
				delete(current.subs, events)
			}
			h.mu.Unlock()
		})
	}
	return events, unsubscribe
}

func (h *Hub) Publish(runID int64, event Event) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	stream := h.streamLocked(runID)
	if stream.finished {
		return false
	}
	h.appendLocked(stream, event)
	for events := range stream.subs {
		push(events, event)
	}
	return true
}

func (h *Hub) Finish(runID int64, event Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	stream := h.streamLocked(runID)
	if stream.finished {
		return
	}
	h.appendLocked(stream, event)
	stream.finished = true
	for events := range stream.subs {
		push(events, event)
		close(events)
	}
	stream.subs = make(map[chan Event]struct{})
}

func (h *Hub) History(runID int64) []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	stream := h.runs[runID]
	if stream == nil {
		return nil
	}
	history := make([]Event, len(stream.history))
	copy(history, stream.history)
	return history
}

func (h *Hub) Subscribers(runID int64) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	stream := h.runs[runID]
	if stream == nil {
		return 0
	}
	return len(stream.subs)
}

func (h *Hub) Shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	event := Event{Type: "shutdown", Data: "server shutting down"}
	for _, stream := range h.runs {
		if !stream.finished {
			h.appendLocked(stream, event)
			stream.finished = true
		}
		for events := range stream.subs {
			push(events, event)
			close(events)
		}
		stream.subs = nil
	}
}

func (h *Hub) streamLocked(runID int64) *runStream {
	if stream := h.runs[runID]; stream != nil {
		return stream
	}
	stream := &runStream{subs: make(map[chan Event]struct{})}
	h.runs[runID] = stream
	h.order = append(h.order, runID)
	for len(h.order) > h.maxRuns {
		evicted := false
		for index, id := range h.order {
			candidate := h.runs[id]
			if candidate != nil && candidate.finished && len(candidate.subs) == 0 {
				delete(h.runs, id)
				h.order = append(h.order[:index], h.order[index+1:]...)
				evicted = true
				break
			}
		}
		if !evicted {
			break
		}
	}
	return stream
}

func (h *Hub) appendLocked(stream *runStream, event Event) {
	stream.history = append(stream.history, event)
	if len(stream.history) > h.historySize {
		stream.history = append([]Event(nil), stream.history[len(stream.history)-h.historySize:]...)
	}
}

func push(events chan Event, event Event) {
	select {
	case events <- event:
		return
	default:
	}
	select {
	case <-events:
	default:
	}
	select {
	case events <- event:
	default:
	}
}
