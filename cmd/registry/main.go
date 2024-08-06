package main

import (
	"WebCore/internal/logging"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("your_secret_key")

type Claims struct {
	NodeID         string `json:"node_id"`
	RefreshTokenID string `json:"refresh_token_id"`
	jwt.StandardClaims
}

type RefreshToken struct {
	ID        string
	NodeID    string
	ExpiresAt time.Time
}

type NodeInfo struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Password string `json:"password"`
}

type Registry struct {
	Nodes         map[string]NodeInfo
	Data          map[string]interface{}
	RefreshTokens map[string]RefreshToken

	mu        sync.RWMutex
	refreshMu sync.RWMutex
}

func NewRegistry() *Registry {
	return &Registry{
		Nodes:         make(map[string]NodeInfo),
		Data:          make(map[string]interface{}),
		RefreshTokens: make(map[string]RefreshToken),
	}
}

func (r *Registry) generateTokens(nodeID string) (string, string, error) {
	// Access token
	accessTokenExpirationTime := time.Now().Add(15 * time.Minute)
	refreshTokenID := uuid.New().String()
	accessClaims := &Claims{
		NodeID:         nodeID,
		RefreshTokenID: refreshTokenID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: accessTokenExpirationTime.Unix(),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(jwtKey)
	if err != nil {
		logging.Error("Failed to generate access token", "error", err, "node_id", nodeID)
		return "", "", err
	}

	// Refresh token
	refreshTokenExpirationTime := time.Now().Add(7 * 24 * time.Hour)
	r.refreshMu.Lock()
	r.RefreshTokens[refreshTokenID] = RefreshToken{
		ID:        refreshTokenID,
		NodeID:    nodeID,
		ExpiresAt: refreshTokenExpirationTime,
	}
	r.refreshMu.Unlock()

	logging.Info("Tokens generated successfully", "node_id", nodeID)
	return accessTokenString, refreshTokenID, nil
}

func validateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		logging.Error("Token validation failed", "error", err)
		return nil, err
	}

	if !token.Valid {
		logging.Warn("Invalid token", "token", tokenString)
		return nil, fmt.Errorf("invalid token")
	}

	logging.Debug("Token validated successfully", "node_id", claims.NodeID)
	return claims, nil
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		tokenString := r.Header.Get("Authorization")

		if tokenString == "" {
			logging.Warn("No token provided", "remote_addr", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// "Bearer" prefix needs to be trimmed
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		claims, err := validateToken(tokenString)
		if err != nil {
			logging.Error("Token validation error", "error", err, "remote_addr", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		r.Header.Set("X-Node-ID", claims.NodeID)
		next.ServeHTTP(w, r)

		duration := time.Since(start)
		logging.LogHTTPRequest(r.Method, r.URL.Path, r.RemoteAddr, http.StatusOK, duration)
	}
}

func (r *Registry) RegisterNode(w http.ResponseWriter, req *http.Request) {
	var node NodeInfo
	if err := json.NewDecoder(req.Body).Decode(&node); err != nil {
		logging.Error("Failed to decode node registration request", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if the node ID already exists
	if _, exists := r.Nodes[node.ID]; exists {
		logging.Warn("Attempted to register node with existing ID", "node_id", node.ID)
		http.Error(w, "Node ID already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(node.Password), bcrypt.DefaultCost)
	if err != nil {
		logging.Error("Failed to hash password", "error", err)
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	node.Password = string(hashedPassword)
	r.Nodes[node.ID] = node

	accessToken, refreshToken, err := r.generateTokens(node.ID)
	if err != nil {
		logging.Error("Failed to generate tokens", "error", err, "node_id", node.ID)
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})

	logging.LogNodeRegistration(node.ID, node.Address, true)
}

func (r *Registry) AuthenticateNode(w http.ResponseWriter, req *http.Request) {
	var credentials struct {
		ID       string `json:"id"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(req.Body).Decode(&credentials); err != nil {
		logging.Error("Failed to decode authentication request", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	r.mu.RLock()
	node, exists := r.Nodes[credentials.ID]
	r.mu.RUnlock()

	if !exists {
		logging.Warn("Authentication attempt for non-existent node", "node_id", credentials.ID)
		http.Error(w, "Node not found", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(node.Password), []byte(credentials.Password)); err != nil {
		logging.Warn("Invalid password during authentication", "node_id", credentials.ID)
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	accessToken, refreshToken, err := r.generateTokens(credentials.ID)
	if err != nil {
		logging.Error("Failed to generate tokens", "error", err, "node_id", credentials.ID)
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})

	logging.LogNodeAuthentication(credentials.ID, true)
}

func (r *Registry) RefreshToken(w http.ResponseWriter, req *http.Request) {
	var refreshReq struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(req.Body).Decode(&refreshReq); err != nil {
		logging.Error("Failed to decode refresh token request", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	r.refreshMu.RLock()
	refreshToken, exists := r.RefreshTokens[refreshReq.RefreshToken]
	r.refreshMu.RUnlock()

	if !exists || time.Now().After(refreshToken.ExpiresAt) {
		logging.Warn("Invalid or expired refresh token", "refresh_token", refreshReq.RefreshToken)
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	accessToken, newRefreshToken, err := r.generateTokens(refreshToken.NodeID)
	if err != nil {
		logging.Error("Failed to generate new tokens", "error", err, "node_id", refreshToken.NodeID)
		http.Error(w, "Failed to generate new tokens", http.StatusInternalServerError)
		return
	}

	r.refreshMu.Lock()
	delete(r.RefreshTokens, refreshReq.RefreshToken)
	r.refreshMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	})

	logging.LogTokenRefresh(refreshToken.NodeID, true)
}

func (r *Registry) GetNodes(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	json.NewEncoder(w).Encode(r.Nodes)
	logging.Info("Nodes list requested", "requester", req.Header.Get("X-Node-ID"))
}

func (r *Registry) HandleGetData(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	json.NewEncoder(w).Encode(r.Data)
	logging.Info("Registry data requested", "requester", req.Header.Get("X-Node-ID"))
}

func (r *Registry) HandleSetData(w http.ResponseWriter, req *http.Request) {
	var data map[string]interface{}
	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		logging.Error("Failed to decode set data request", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	for k, v := range data {
		r.Data[k] = v
	}
	r.mu.Unlock()

	logging.Info("Data updated in registry", "requester", req.Header.Get("X-Node-ID"))
	w.WriteHeader(http.StatusOK)
}

func main() {
	logging.InitLogger("registry.log", true)
	logging.Info("Registry starting up")

	registry := NewRegistry()
	r := mux.NewRouter()

	r.HandleFunc("/register", registry.RegisterNode).Methods("POST")
	r.HandleFunc("/authenticate", registry.AuthenticateNode).Methods("POST")
	r.HandleFunc("/nodes", authMiddleware(registry.GetNodes)).Methods("GET")
	r.HandleFunc("/getData", authMiddleware(registry.HandleGetData)).Methods("GET")
	r.HandleFunc("/setData", authMiddleware(registry.HandleSetData)).Methods("POST")
	r.HandleFunc("/refresh", registry.RefreshToken).Methods("POST")

	logging.Info("Registry starting on :8000")
	logging.Fatal("Server failed to start", "error", http.ListenAndServe(":8000", r))
}
