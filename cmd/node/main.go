package main

import (
	"WebCore/internal/logging"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sync"
)

type Node struct {
	ID              string
	Address         string
	Password        string
	Data            map[string]interface{}
	RegistryAddress string
	Token           string
	RefreshToken    string
	mu              sync.RWMutex
}

type NodeInfo struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}

func NewNode(id, address, registryAddress string, password string) *Node {
	return &Node{
		ID:              id,
		Address:         address,
		Password:        password,
		Data:            make(map[string]interface{}),
		RegistryAddress: registryAddress,
	}
}

func (n *Node) RegisterWithRegistry(registryAddress string) error {
	data, _ := json.Marshal(map[string]string{"id": n.ID, "address": n.Address, "password": n.Password})
	resp, err := http.Post(fmt.Sprintf("http://%s/register", registryAddress), "application/json", bytes.NewBuffer(data))
	if err != nil {
		logging.Error("Failed to register with registry", "error", err, "node_id", n.ID)
		return err
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logging.Error("Failed to decode registration response", "error", err, "node_id", n.ID)
		return err
	}
	n.Token = result["access_token"]
	n.RefreshToken = result["refresh_token"]

	logging.Info("Node registered successfully", "node_id", n.ID, "registry", registryAddress)
	return nil
}

func (n *Node) Authenticate() error {
	data, _ := json.Marshal(map[string]string{"id": n.ID, "password": n.Password})
	resp, err := http.Post(fmt.Sprintf("http://%s/authenticate", n.RegistryAddress), "application/json", bytes.NewBuffer(data))
	if err != nil {
		logging.Error("Authentication failed", "error", err, "node_id", n.ID)
		return err
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logging.Error("Failed to decode authentication response", "error", err, "node_id", n.ID)
		return err
	}
	n.Token = result["access_token"]
	n.RefreshToken = result["refresh_token"]

	logging.Info("Node authenticated successfully", "node_id", n.ID)
	return nil
}

func (n *Node) RefreshTokens() error {
	data, _ := json.Marshal(map[string]string{"refresh_token": n.RefreshToken})
	resp, err := http.Post(fmt.Sprintf("http://%s/refresh", n.RegistryAddress), "application/json", bytes.NewBuffer(data))
	if err != nil {
		logging.Error("Token refresh failed", "error", err, "node_id", n.ID)
		return err
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logging.Error("Failed to decode token refresh response", "error", err, "node_id", n.ID)
		return err
	}
	n.Token = result["access_token"]
	n.RefreshToken = result["refresh_token"]

	logging.Info("Tokens refreshed successfully", "node_id", n.ID)
	return nil
}

func (n *Node) makeAuthenticatedRequest(method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		logging.Error("Failed to create request", "error", err, "method", method, "url", url)
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logging.Error("Request failed", "error", err, "method", method, "url", url)
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		logging.Warn("Token expired, attempting refresh", "node_id", n.ID)
		if err := n.RefreshTokens(); err != nil {
			logging.Error("Failed to refresh tokens", "error", err, "node_id", n.ID)
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+n.Token)
		return http.DefaultClient.Do(req)
	}
	return resp, nil
}

func (n *Node) HandleGetData(w http.ResponseWriter, r *http.Request) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	json.NewEncoder(w).Encode(n.Data)
	logging.Info("Data requested from node", "node_id", n.ID, "requester", r.RemoteAddr)
}

func (n *Node) HandleSetData(w http.ResponseWriter, r *http.Request) {
	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		logging.Error("Failed to decode set data request", "error", err, "node_id", n.ID)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	n.mu.Lock()
	for k, v := range data {
		n.Data[k] = v
	}
	n.mu.Unlock()

	logging.Info("Data updated on node", "node_id", n.ID, "requester", r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
}

func (n *Node) GetNodesFromRegistry() (map[string]NodeInfo, error) {
	resp, err := n.makeAuthenticatedRequest("GET", fmt.Sprintf("http://%s/nodes", n.RegistryAddress), nil)
	if err != nil {
		logging.Error("Failed to get nodes from registry", "error", err, "node_id", n.ID)
		return nil, err
	}
	defer resp.Body.Close()

	var nodes map[string]NodeInfo
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		logging.Error("Failed to decode nodes response", "error", err, "node_id", n.ID)
		return nil, err
	}

	logging.Info("Retrieved nodes from registry", "node_id", n.ID, "node_count", len(nodes))
	return nodes, nil
}

func (n *Node) RequestDataFromNode(nodeAddress string) (map[string]interface{}, error) {
	resp, err := n.makeAuthenticatedRequest("GET", fmt.Sprintf("http://%s/getData", nodeAddress), nil)
	if err != nil {
		logging.Error("Failed to request data from node", "error", err, "node_id", n.ID, "target_address", nodeAddress)
		return nil, err
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		logging.Error("Failed to decode data response", "error", err, "node_id", n.ID, "target_address", nodeAddress)
		return nil, err
	}

	logging.Info("Retrieved data from node", "node_id", n.ID, "target_address", nodeAddress)
	return data, nil
}

func (n *Node) HandleRequestData(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("nodeID")

	if nodeID == "" {
		logging.Warn("Missing nodeID in request", "node_id", n.ID, "requester", r.RemoteAddr)
		http.Error(w, "Missing nodeID", http.StatusBadRequest)
		return
	}

	nodes, err := n.GetNodesFromRegistry()
	if err != nil {
		logging.Error("Failed to get nodes from registry", "error", err, "node_id", n.ID)
		http.Error(w, fmt.Sprintf("Failed to get nodes from registry: %v", err), http.StatusInternalServerError)
		return
	}

	targetNode, ok := nodes[nodeID]
	if !ok {
		logging.Warn("Requested node not found", "node_id", n.ID, "target_node_id", nodeID)
		http.Error(w, fmt.Sprintf("Node %s not found", nodeID), http.StatusNotFound)
		return
	}

	data, err := n.RequestDataFromNode(targetNode.Address)
	if err != nil {
		logging.Error("Failed to get data from node", "error", err, "node_id", n.ID, "target_node_id", nodeID)
		http.Error(w, fmt.Sprintf("Failed to get data from node: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(data)
	logging.Info("Data request handled successfully", "node_id", n.ID, "target_node_id", nodeID)
}

func (n *Node) SetDataOnRegistry(data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		logging.Error("Failed to marshal data for registry", "error", err, "node_id", n.ID)
		return err
	}

	_, err = n.makeAuthenticatedRequest("POST", fmt.Sprintf("http://%s/setData", n.RegistryAddress), bytes.NewBuffer(jsonData))
	if err != nil {
		logging.Error("Failed to set data on registry", "error", err, "node_id", n.ID)
		return err
	}

	logging.Info("Data set on registry successfully", "node_id", n.ID)
	return nil
}

func (n *Node) GetDataFromRegistry() (map[string]interface{}, error) {
	resp, err := n.makeAuthenticatedRequest("GET", fmt.Sprintf("http://%s/getData", n.RegistryAddress), nil)
	if err != nil {
		logging.Error("Failed to get data from registry", "error", err, "node_id", n.ID)
		return nil, err
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		logging.Error("Failed to decode data from registry", "error", err, "node_id", n.ID)
		return nil, err
	}

	logging.Info("Retrieved data from registry", "node_id", n.ID)
	return data, nil
}

func (n *Node) HandleSetRegistryData(w http.ResponseWriter, r *http.Request) {
	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		logging.Error("Failed to decode set registry data request", "error", err, "node_id", n.ID)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := n.SetDataOnRegistry(data); err != nil {
		logging.Error("Failed to set data on registry", "error", err, "node_id", n.ID)
		http.Error(w, fmt.Sprintf("Failed to set data on registry: %v", err), http.StatusInternalServerError)
		return
	}

	logging.Info("Data set on registry handled successfully", "node_id", n.ID)
	w.WriteHeader(http.StatusOK)
}

func (n *Node) HandleGetRegistryData(w http.ResponseWriter, r *http.Request) {
	data, err := n.GetDataFromRegistry()
	if err != nil {
		logging.Error("Failed to get data from registry", "error", err, "node_id", n.ID)
		http.Error(w, fmt.Sprintf("Failed to get data from registry: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(data)
	logging.Info("Registry data retrieved successfully", "node_id", n.ID)
}

func main() {
	var (
		id              = flag.String("id", "", "Node ID")
		address         = flag.String("address", "", "Node address (host:port)")
		registryAddress = flag.String("registry", "", "Registry address (host:port)")
		password        = flag.String("password", "", "Node password")
	)
	flag.Parse()

	logging.InitLogger(fmt.Sprintf("node_%s.log", *id), true)

	if *id == "" || *address == "" || *registryAddress == "" || *password == "" {
		logging.Fatal("Missing required parameters", "id", *id, "address", *address, "registry", *registryAddress)
	}

	logging.Info("Node starting up", "node_id", *id, "address", *address)

	node := NewNode(*id, *address, *registryAddress, *password)

	if err := node.RegisterWithRegistry(*registryAddress); err != nil {
		logging.Fatal("Failed to register with registry", "error", err)
	}

	http.HandleFunc("/getData", node.HandleGetData)
	http.HandleFunc("/setData", node.HandleSetData)
	http.HandleFunc("/requestData", node.HandleRequestData)
	http.HandleFunc("/setRegistryData", node.HandleSetRegistryData)
	http.HandleFunc("/getRegistryData", node.HandleGetRegistryData)

	logging.Info("Node started", "node_id", node.ID, "address", node.Address)
	if err := http.ListenAndServe(node.Address, nil); err != nil {
		logging.Fatal("Node failed to start", "error", err)
	}
}
