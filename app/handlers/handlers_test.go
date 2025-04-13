package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"restfulapi/app/models"

	"github.com/golang-jwt/jwt/v5"
)

func resetUsers() {
	users = []models.User{}
}

func TestRegisterHandler(t *testing.T) {
	// Reset users between tests
	resetUsers()

	tests := []struct {
		name           string
		credentials    models.Credentials
		expectedStatus int
		expectedBody   map[string]string
	}{
		{
			name: "Successful Registration",
			credentials: models.Credentials{
				Email:    "test@example.com",
				Password: "password123",
			},
			expectedStatus: http.StatusCreated,
			expectedBody: map[string]string{
				"message": "User registered successfully",
			},
		},
		{
			name: "Duplicate User",
			credentials: models.Credentials{
				Email:    "test@example.com",
				Password: "password123",
			},
			expectedStatus: http.StatusConflict,
			expectedBody: map[string]string{
				"message": "User already exists",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.credentials)
			req, err := http.NewRequest("POST", "/register", bytes.NewBuffer(body))
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(RegisterHandler)

			handler.ServeHTTP(rr, req)

			if tc.expectedStatus != rr.Code {
				t.Fatalf("Expected: %d, Got: %d", tc.expectedStatus, rr.Code)
			}

			if tc.expectedBody != nil {
				var response map[string]string
				err = json.NewDecoder(rr.Body).Decode(&response)
				if err != nil {
					t.Fatal(err)
				}
				if tc.expectedBody["message"] != response["message"] {
					t.Fatalf("Expected: %v, Got: %v", tc.expectedBody, response)
				}
			}
		})
	}
}

// GenerateTestToken creates a JWT token for testing
func GenerateTestToken(userID int, secret []byte, expiration time.Duration) string {
	// Create token expiration time
	expirationTime := time.Now().Add(expiration)

	// Define the claims
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     expirationTime.Unix(),
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret key
	tokenString, _ := token.SignedString(secret)

	return tokenString
}

// GenerateExpiredToken creates an expired JWT token for testing
func GenerateExpiredToken(userID int, secret []byte) string {
	// Create token expiration time (in the past)
	expirationTime := time.Now().Add(-15 * time.Minute)

	// Define the claims
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     expirationTime.Unix(),
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret key
	tokenString, _ := token.SignedString(secret)

	return tokenString
}
