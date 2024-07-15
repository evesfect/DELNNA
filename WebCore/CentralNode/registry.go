package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

type NodeInfo struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}

type Registry struct {
	Nodes map[string]NodeInfo
	mu    sync.RWMutex
}

func NewRegistry() *Registry {
	return &Registry{
		Nodes: make(map[string]NodeInfo),
	}
}

func (r *Registry) RegisterNode(w http.ResponseWriter, req *http.Request) {
	var node NodeInfo
	if err := json.NewDecoder(req.Body).Decode(&node); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	r.Nodes[node.ID] = node
	r.mu.Unlock()

	log.Printf("Node registered: %s at %s", node.ID, node.Address)
	w.WriteHeader(http.StatusOK)
}

func (r *Registry) GetNodes(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	json.NewEncoder(w).Encode(r.Nodes)
}

func main() {
	registry := NewRegistry()

	http.HandleFunc("/register", registry.RegisterNode)
	http.HandleFunc("/nodes", registry.GetNodes)

	log.Println("Registry starting on :8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
