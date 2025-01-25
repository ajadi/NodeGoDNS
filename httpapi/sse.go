package httpapi

import (
    "fmt"
    "net/http"

    "github.com/sirupsen/logrus"
)

// SSEClient holds the channels for SSE streaming.
type SSEClient struct {
    channel chan string
    done    chan struct{}
}

// SSEHub manages SSE clients: register/unregister, broadcast.
type SSEHub struct {
    clients    map[*SSEClient]struct{}
    register   chan *SSEClient
    unregister chan *SSEClient
    broadcast  chan string
}

// NewSSEHub creates an SSEHub with internal channels.
func NewSSEHub() *SSEHub {
    return &SSEHub{
        clients:    make(map[*SSEClient]struct{}),
        register:   make(chan *SSEClient),
        unregister: make(chan *SSEClient),
        broadcast:  make(chan string),
    }
}

// Run listens for SSE events: register/unregister/broadcast.
func (hub *SSEHub) Run() {
    for {
        select {
        case client := <-hub.register:
            hub.clients[client] = struct{}{}
            logrus.Info("New SSE client registered")
        case client := <-hub.unregister:
            if _, ok := hub.clients[client]; ok {
                delete(hub.clients, client)
                close(client.channel)
                close(client.done)
                logrus.Info("SSE client unregistered")
            }
        case message := <-hub.broadcast:
            for client := range hub.clients {
                select {
                case client.channel <- message:
                default:
                    close(client.channel)
                    delete(hub.clients, client)
                }
            }
        }
    }
}

// Broadcast sends a message to all SSE clients.
func (hub *SSEHub) Broadcast(message string) {
    hub.broadcast <- message
}

// AddClient registers an SSEClient.
func (hub *SSEHub) AddClient(client *SSEClient) {
    hub.register <- client
}

// RemoveClient unregisters an SSEClient.
func (hub *SSEHub) RemoveClient(client *SSEClient) {
    hub.unregister <- client
}

// HandleSubscribeSSE upgrades HTTP connection to SSE for real-time notifications.
func (api *HTTPAPI) HandleSubscribeSSE(w http.ResponseWriter, r *http.Request, hub *SSEHub) {
    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
        return
    }

    client := &SSEClient{
        channel: make(chan string, 10),
        done:    make(chan struct{}),
    }

    hub.AddClient(client)
    defer hub.RemoveClient(client)

    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")

    notify := w.(http.CloseNotifier).CloseNotify()

    go func() {
        <-notify
        close(client.done)
    }()

    for {
        select {
        case msg := <-client.channel:
            _, _ = fmt.Fprintf(w, "data: %s\n\n", msg)
            flusher.Flush()
        case <-client.done:
            return
        }
    }
}
