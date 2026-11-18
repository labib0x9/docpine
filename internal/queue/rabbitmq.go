package queue

import (
	"context"
	"encoding/json"
	"sync"

	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	DefaultQueue          = "docpine.lab.runs"
	DefaultEventsExchange = "docpine.lab.events"
)

type Job struct {
	RunID int64 `json:"run_id"`
}

type LabEvent struct {
	RunID int64  `json:"run_id"`
	Type  string `json:"type"`
	Data  string `json:"data"`
}

type Handler func(context.Context, int64) error

type EventHandler func(context.Context, LabEvent) error

type Client struct {
	queueName      string
	eventsExchange string
	conn           *amqp.Connection
	publishCh      *amqp.Channel
	jobsCh         *amqp.Channel
	eventsCh       *amqp.Channel
	mu             sync.Mutex
}

func New(url, queueName, eventsExchange string) (*Client, error) {
	if url == "" {
		url = "amqp://docpine:docpine@localhost:5672/"
	}
	if queueName == "" {
		queueName = DefaultQueue
	}
	if eventsExchange == "" {
		eventsExchange = DefaultEventsExchange
	}

	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, err
	}

	channels := []*amqp.Channel{}
	closeChannels := func() {
		for _, ch := range channels {
			_ = ch.Close()
		}
		_ = conn.Close()
	}

	publishCh, err := conn.Channel()
	if err != nil {
		closeChannels()
		return nil, err
	}
	channels = append(channels, publishCh)

	jobsCh, err := conn.Channel()
	if err != nil {
		closeChannels()
		return nil, err
	}
	channels = append(channels, jobsCh)

	eventsCh, err := conn.Channel()
	if err != nil {
		closeChannels()
		return nil, err
	}
	channels = append(channels, eventsCh)

	if _, err := jobsCh.QueueDeclare(queueName, true, false, false, false, nil); err != nil {
		closeChannels()
		return nil, err
	}
	if err := jobsCh.Qos(1, 0, false); err != nil {
		closeChannels()
		return nil, err
	}
	if err := publishCh.ExchangeDeclare(eventsExchange, "fanout", true, false, false, false, nil); err != nil {
		closeChannels()
		return nil, err
	}

	return &Client{
		queueName:      queueName,
		eventsExchange: eventsExchange,
		conn:           conn,
		publishCh:      publishCh,
		jobsCh:         jobsCh,
		eventsCh:       eventsCh,
	}, nil
}

func (c *Client) Publish(ctx context.Context, runID int64) error {
	body, err := json.Marshal(Job{RunID: runID})
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.publishCh.PublishWithContext(ctx, "", c.queueName, false, false, amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
		Body:         body,
	})
}

func (c *Client) PublishEvent(ctx context.Context, event LabEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.publishCh.PublishWithContext(ctx, c.eventsExchange, "", false, false, amqp.Publishing{
		ContentType: "application/json",
		Body:        body,
	})
}

func (c *Client) Consume(ctx context.Context, handle Handler) error {
	deliveries, err := c.jobsCh.Consume(c.queueName, "docpine-lab-worker", false, false, false, false, nil)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case delivery, ok := <-deliveries:
			if !ok {
				return nil
			}
			var job Job
			if err := json.Unmarshal(delivery.Body, &job); err != nil {
				_ = delivery.Nack(false, false)
				continue
			}
			if err := handle(ctx, job.RunID); err != nil {
				_ = delivery.Nack(false, true)
				continue
			}
			_ = delivery.Ack(false)
		}
	}
}

func (c *Client) ConsumeEvents(ctx context.Context, handle EventHandler) error {
	queue, err := c.eventsCh.QueueDeclare("", false, true, true, false, nil)
	if err != nil {
		return err
	}
	if err := c.eventsCh.QueueBind(queue.Name, c.eventsExchange, "", false, nil); err != nil {
		return err
	}
	deliveries, err := c.eventsCh.Consume(queue.Name, "", true, false, false, false, nil)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case delivery, ok := <-deliveries:
			if !ok {
				return nil
			}
			var event LabEvent
			if err := json.Unmarshal(delivery.Body, &event); err != nil {
				continue
			}
			if err := handle(ctx, event); err != nil {
				return err
			}
		}
	}
}

func (c *Client) Close() error {
	_ = c.jobsCh.Close()
	_ = c.eventsCh.Close()
	_ = c.publishCh.Close()
	return c.conn.Close()
}
