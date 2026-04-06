package httpx

import (
	"encoding/json"
	"net/http"
)

type ErrorResponse struct {
	RequestID string `json:"request_id"`
	Action    string `json:"action"`
	Reason    string `json:"reason"`
}

func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
