package sse

import (
	"fmt"
	"testing"
	"time"
)

func TestHubPublishAndFinish(t *testing.T) {
	hub := NewHub()
	events, unsubscribe := hub.Subscribe(7)
	defer unsubscribe()

	if got := hub.Subscribers(7); got != 1 {
		t.Fatalf("subscribers = %d; want 1", got)
	}
	if !hub.Publish(7, Event{Type: "output", Data: "hello"}) {
		t.Fatal("publish failed")
	}
	assertEvent(t, events, Event{Type: "output", Data: "hello"})

	hub.Finish(7, Event{Type: "result", Data: "done"})
	assertEvent(t, events, Event{Type: "result", Data: "done"})
	assertClosed(t, events)
	if got := hub.Subscribers(7); got != 0 {
		t.Fatalf("subscribers after finish = %d; want 0", got)
	}
	if hub.Publish(7, Event{Type: "output", Data: "late"}) {
		t.Fatal("publish after finish should fail")
	}
}

func TestHubReplaysHistoryToLateSubscriber(t *testing.T) {
	hub := NewHub()
	hub.Publish(11, Event{Type: "status", Data: "running"})
	hub.Publish(11, Event{Type: "output", Data: "first"})

	events, unsubscribe := hub.Subscribe(11)
	defer unsubscribe()
	assertEvent(t, events, Event{Type: "status", Data: "running"})
	assertEvent(t, events, Event{Type: "output", Data: "first"})

	hub.Finish(11, Event{Type: "result", Data: "ok"})
	assertEvent(t, events, Event{Type: "result", Data: "ok"})
	assertClosed(t, events)
}

func TestHubLateSubscriberAfterFinish(t *testing.T) {
	hub := NewHub()
	hub.Finish(13, Event{Type: "result", Data: "finished"})

	events, unsubscribe := hub.Subscribe(13)
	defer unsubscribe()
	assertEvent(t, events, Event{Type: "result", Data: "finished"})
	assertClosed(t, events)
}

func TestHubKeepsLatestEventsForSlowSubscriber(t *testing.T) {
	hub := NewHubWithOptions(4, 2)
	events, unsubscribe := hub.Subscribe(17)
	defer unsubscribe()

	for i := 0; i < 20; i++ {
		hub.Publish(17, Event{Type: "output", Data: fmt.Sprintf("event-%d", i)})
	}
	hub.Finish(17, Event{Type: "result", Data: "done"})
	last := Event{}
	for {
		select {
		case event, open := <-events:
			if !open {
				if last.Data != "event-19" {
					t.Fatalf("last event = %q; want event-19", last.Data)
				}
				return
			}
			if event.Type != "result" {
				last = event
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out; last event = %+v", last)
		}
	}
}

func TestHubEvictsOldFinishedRuns(t *testing.T) {
	hub := NewHubWithOptions(8, 2)
	for _, runID := range []int64{21, 22, 23} {
		hub.Publish(runID, Event{Type: "output", Data: "value"})
		hub.Finish(runID, Event{Type: "result", Data: "done"})
	}
	if history := hub.History(21); len(history) != 0 {
		t.Fatalf("old run history = %+v; want empty", history)
	}
	if history := hub.History(23); len(history) != 2 {
		t.Fatalf("recent run history = %+v; want 2 events", history)
	}
}

func TestHubShutdown(t *testing.T) {
	hub := NewHub()
	events, unsubscribe := hub.Subscribe(31)
	defer unsubscribe()

	hub.Shutdown()
	assertEvent(t, events, Event{Type: "shutdown", Data: "server shutting down"})
	assertClosed(t, events)
	if hub.Publish(31, Event{Type: "output", Data: "ignored"}) {
		t.Fatal("publish after shutdown should fail")
	}
	after, afterUnsubscribe := hub.Subscribe(32)
	defer afterUnsubscribe()
	assertClosed(t, after)
}

func TestHubUnsubscribe(t *testing.T) {
	hub := NewHub()
	events, unsubscribe := hub.Subscribe(9)
	unsubscribe()
	unsubscribe()
	hub.Publish(9, Event{Type: "output", Data: "ignored"})
	select {
	case event := <-events:
		t.Fatalf("unexpected event after unsubscribe: %+v", event)
	case <-time.After(20 * time.Millisecond):
	}
	if got := hub.Subscribers(9); got != 0 {
		t.Fatalf("subscribers = %d; want 0", got)
	}
}

func assertEvent(t *testing.T, events <-chan Event, want Event) {
	t.Helper()
	select {
	case got, open := <-events:
		if !open {
			t.Fatalf("channel closed before event %+v", want)
		}
		if got != want {
			t.Fatalf("event = %+v; want %+v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for event %+v", want)
	}
}

func assertClosed(t *testing.T, events <-chan Event) {
	t.Helper()
	select {
	case event, open := <-events:
		if open {
			t.Fatalf("channel still open with event %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel close")
	}
}
