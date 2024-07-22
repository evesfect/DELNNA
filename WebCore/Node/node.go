package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
)

type Node struct {
	ID              string
	Address         string
	Data            map[string]interface{}
	RegistryAddress string
	Token           string
	mu              sync.RWMutex
}

type NodeInfo struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}

func NewNode(id, address, registryAddress string) *Node {
	return &Node{
		ID:              id,
		Address:         address,
		Data:            make(map[string]interface{}),
		RegistryAddress: registryAddress,
	}
}

func (n *Node) RegisterWithRegistry(registryAddress string) error {
	data, _ := json.Marshal(map[string]string{"id": n.ID, "address": n.Address})
	resp, err := http.Post(fmt.Sprintf("http://%s/register", registryAddress), "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	n.Token = result["token"]
	return nil
}

func (n *Node) makeAuthenticatedRequest(method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", n.Token)
	return http.DefaultClient.Do(req)
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

func (n *Node) GetNodesFromRegistry() (map[string]NodeInfo, error) {
	resp, err := n.makeAuthenticatedRequest("GET", fmt.Sprintf("http://%s/nodes", n.RegistryAddress), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var nodes map[string]NodeInfo
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		return nil, err
	}

	return nodes, nil
}

func (n *Node) RequestDataFromNode(nodeAddress string) (map[string]interface{}, error) {
	resp, err := n.makeAuthenticatedRequest("GET", fmt.Sprintf("http://%s/getData", nodeAddress), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return data, nil
}

func (n *Node) HandleRequestData(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("nodeID")

	if nodeID == "" {
		http.Error(w, "Missing nodeID", http.StatusBadRequest)
		return
	}

	nodes, err := n.GetNodesFromRegistry()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get nodes from registry: %v", err), http.StatusInternalServerError)
		return
	}

	targetNode, ok := nodes[nodeID]
	if !ok {
		http.Error(w, fmt.Sprintf("Node %s not found", nodeID), http.StatusNotFound)
		return
	}

	data, err := n.RequestDataFromNode(targetNode.Address)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get data from node: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(data)
}

func (n *Node) SetDataOnRegistry(data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	_, err = n.makeAuthenticatedRequest("POST", fmt.Sprintf("http://%s/setData", n.RegistryAddress), bytes.NewBuffer(jsonData))
	return err
}

func (n *Node) GetDataFromRegistry() (map[string]interface{}, error) {
	resp, err := n.makeAuthenticatedRequest("GET", fmt.Sprintf("http://%s/getData", n.RegistryAddress), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return data, nil
}

func (n *Node) HandleSetRegistryData(w http.ResponseWriter, r *http.Request) {
	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := n.SetDataOnRegistry(data); err != nil {
		http.Error(w, fmt.Sprintf("Failed to set data on registry: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (n *Node) HandleGetRegistryData(w http.ResponseWriter, r *http.Request) {
	data, err := n.GetDataFromRegistry()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get data from registry: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(data)
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

	node := NewNode(*id, *address, *registryAddress)

	if err := node.RegisterWithRegistry(*registryAddress); err != nil {
		log.Fatalf("Failed to register with registry: %v", err)
	}

	http.HandleFunc("/getData", node.HandleGetData)
	http.HandleFunc("/setData", node.HandleSetData)
	http.HandleFunc("/requestData", node.HandleRequestData)
	http.HandleFunc("/setRegistryData", node.HandleSetRegistryData)
	http.HandleFunc("/getRegistryData", node.HandleGetRegistryData)

	log.Printf("Node %s starting on %s", node.ID, node.Address)
	log.Fatal(http.ListenAndServe(node.Address, nil))
}
