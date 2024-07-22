package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

var jwtKey = []byte("your_secret_key")

type Claims struct {
	NodeID string `json:"node_id"`
	jwt.StandardClaims
}

type NodeInfo struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}

type Registry struct {
	Nodes map[string]NodeInfo
	Data  map[string]interface{}
	mu    sync.RWMutex
}

func NewRegistry() *Registry {
	return &Registry{
		Nodes: make(map[string]NodeInfo),
		Data:  make(map[string]interface{}),
	}
}

func generateToken(nodeID string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		NodeID: nodeID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func validateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims, err := validateToken(tokenString)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		r.Header.Set("X-Node-ID", claims.NodeID)
		next.ServeHTTP(w, r)
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

	token, err := generateToken(node.ID)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})

	log.Printf("Node registered: %s at %s", node.ID, node.Address)
}

func (r *Registry) GetNodes(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	json.NewEncoder(w).Encode(r.Nodes)
}

func (r *Registry) HandleGetData(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	json.NewEncoder(w).Encode(r.Data)
}

func (r *Registry) HandleSetData(w http.ResponseWriter, req *http.Request) {
	var data map[string]interface{}
	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	for k, v := range data {
		r.Data[k] = v
	}
	r.mu.Unlock()

	log.Printf("Data received and stored in registry")
	w.WriteHeader(http.StatusOK)
}

func main() {
	registry := NewRegistry()
	r := mux.NewRouter()

	r.HandleFunc("/register", registry.RegisterNode).Methods("POST")
	r.HandleFunc("/nodes", authMiddleware(registry.GetNodes)).Methods("GET")
	r.HandleFunc("/getData", authMiddleware(registry.HandleGetData)).Methods("GET")
	r.HandleFunc("/setData", authMiddleware(registry.HandleSetData)).Methods("POST")

	log.Println("Registry starting on :8000")
	log.Fatal(http.ListenAndServe(":8000", r))
}
