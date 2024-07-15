package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
)

type Node struct {
	ID      string
	Address string
	Data    map[string]interface{}
	mu      sync.RWMutex
}

func NewNode(id, address string) *Node {
	return &Node{
		ID:      id,
		Address: address,
		Data:    make(map[string]interface{}),
	}
}

func (n *Node) HandleGetData(w http.ResponseWriter, r *http.Request) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	json.NewEncoder(w).Encode(n.Data)
}

func (n *Node) HandleSetData(w http.ResponseWriter, r *http.Request) {
	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	n.mu.Lock()
	for k, v := range data {
		n.Data[k] = v
	}
	n.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func (n *Node) RegisterWithRegistry(registryAddress string) error {
	data, _ := json.Marshal(map[string]string{"id": n.ID, "address": n.Address})
	_, err := http.Post(fmt.Sprintf("http://%s/register", registryAddress), "application/json", bytes.NewBuffer(data))
	return err
}

func main() {
	var (
		id              = flag.String("id", "", "Node ID")
		address         = flag.String("address", "", "Node address (host:port)")
		registryAddress = flag.String("registry", "", "Registry address (host:port)")
	)
	flag.Parse()

	if *id == "" || *address == "" || *registryAddress == "" {
		log.Fatal("Node ID, address, and registry address are required")
	}

	node := NewNode(*id, *address)

	if err := node.RegisterWithRegistry(*registryAddress); err != nil {
		log.Fatalf("Failed to register with registry: %v", err)
	}

	http.HandleFunc("/getData", node.HandleGetData)
	http.HandleFunc("/setData", node.HandleSetData)

	log.Printf("Node %s starting on %s", node.ID, node.Address)
	log.Fatal(http.ListenAndServe(node.Address, nil))
}
