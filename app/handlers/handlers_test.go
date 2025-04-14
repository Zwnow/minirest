package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"restfulapi/app/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
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

func TestLoginHandler(t *testing.T) {
	// Reset users
	resetUsers()

	// Register test user
	testUser := models.Credentials{
		Email:    "login@example.com",
		Password: "password123",
	}

	// Register directly
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testUser.Password), bcrypt.DefaultCost)
	users = append(users, models.User{
		Id:       1,
		Email:    testUser.Email,
		Password: string(hashedPassword),
	})

	tests := []struct {
		name           string
		credentials    models.Credentials
		expectedStatus int
		checkToken     bool
	}{
		{
			name: "Successful Login",
			credentials: models.Credentials{
				Email:    "login@example.com",
				Password: "password123",
			},
			expectedStatus: http.StatusOK,
			checkToken:     true,
		},
		{
			name: "User Not Found",
			credentials: models.Credentials{
				Email:    "nonexistent@example.com",
				Password: "password123",
			},
			expectedStatus: http.StatusUnauthorized,
			checkToken:     false,
		},
		{
			name: "Wrong Password",
			credentials: models.Credentials{
				Email:    "login@example.com",
				Password: "wrongpassword",
			},
			expectedStatus: http.StatusUnauthorized,
			checkToken:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.credentials)
			req, err := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(LoginHandler)

			handler.ServeHTTP(rr, req)

			if tc.expectedStatus != rr.Code {
				t.Fatalf("Expected: %d, Got: %d", tc.expectedStatus, rr.Code)
			}

			if tc.checkToken {
				var response map[string]string
				err := json.NewDecoder(rr.Body).Decode(&response)
				if err != nil {
					t.Fatal(err)
				}

				if response["token"] == "" {
					t.Fatal("Expected token in response")
				}
			}
		})
	}
}

func TestAuthMiddleware(t *testing.T) {
	resetUsers()
	users = append(users, models.User{Id: 1, Email: "middleware@example.com"})

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Generate a valid token
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &models.Claims{
		UserID: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	validToken, _ := token.SignedString(jwtKey)

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "Valid Token",
			authHeader:     "Bearer " + validToken,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "No Token",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid Token Format",
			authHeader:     "InvalidToken",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Expired Token",
			authHeader:     "Bearer " + generateExpiredToken(),
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/profile", nil)
			if err != nil {
				t.Fatal(err)
			}

			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}

			rr := httptest.NewRecorder()

			middleware := AuthMiddleware(nextHandler)
			middleware.ServeHTTP(rr, req)

			if tc.expectedStatus != rr.Code {
				t.Fatalf("Expected: %d, Got: %d", tc.expectedStatus, rr.Code)
			}
		})
	}
}

// Helper function to generate an expired token
func generateExpiredToken() string {
	expirationTime := time.Now().Add(-15 * time.Minute)
	claims := &models.Claims{
		UserID: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	expiredToken, _ := token.SignedString(jwtKey)
	return expiredToken
}

func TestMailVerification(t *testing.T) {
	resetUsers()
	testUser := models.User{Id: 1, Email: "mail@example.com", EmailVerificationCode: uuid.NewString()}
	users = append(users, testUser)
	// TODO finish test
}

func TestProfileHandler(t *testing.T) {
	resetUsers()
	testUser := models.User{Id: 2, Email: "profile@example.com"}
	users = append(users, testUser)

	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &models.Claims{
		UserID: testUser.Id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	validToken, _ := token.SignedString(jwtKey)

	invalidUserClaims := &models.Claims{
		UserID: 9999,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	invalidUserToken := jwt.NewWithClaims(jwt.SigningMethodHS256, invalidUserClaims)
	nonExistentUserToken, _ := invalidUserToken.SignedString(jwtKey)

	tests := []struct {
		name           string
		token          string
		expectedStatus int
		checkBody      bool
	}{
		{
			name:           "Valid User",
			token:          validToken,
			expectedStatus: http.StatusOK,
			checkBody:      true,
		},
		{
			name:           "Non-existent User",
			token:          nonExistentUserToken,
			expectedStatus: http.StatusNotFound,
			checkBody:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/api/profile", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Authorization", "Bearer "+tc.token)

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(ProfileHandler)

			handler.ServeHTTP(rr, req)

			if tc.expectedStatus != rr.Code {
				t.Fatalf("Expected: %d, Got: %d", tc.expectedStatus, rr.Code)
			}

			if tc.checkBody {
				var response map[string]any
				err = json.NewDecoder(rr.Body).Decode(&response)
				if err != nil {
					t.Fatal(err)
				}

				if fmt.Sprintf("%d", testUser.Id) != response["id"] {
					t.Fatalf("Expected ID: %v, Got: %v", testUser.Id, response["id"])
				}

				if testUser.Email != response["email"] {
					t.Fatalf("Expected ID: %v, Got: %v", testUser.Email, response["email"])
				}
			}
		})
	}
}

func TestIntegration(t *testing.T) {
	resetUsers()

	r := mux.NewRouter()
	SetupAuthRoutes(r)

	testUser := models.Credentials{
		Email:    "integration@example.com",
		Password: "integration123",
	}

	t.Run("Register User", func(t *testing.T) {
		body, _ := json.Marshal(testUser)
		req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()

		r.ServeHTTP(rr, req)

		if http.StatusCreated != rr.Code {
			t.Fatalf("Expected: %d, Got: %d", http.StatusCreated, rr.Code)
		}
	})

	var token string
	t.Run("Login User", func(t *testing.T) {
		body, _ := json.Marshal(testUser)
		req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(body))

		rr := httptest.NewRecorder()

		r.ServeHTTP(rr, req)

		if http.StatusOK != rr.Code {
			t.Fatalf("Expected: %d, Got: %d", http.StatusOK, rr.Code)
		}

		var response map[string]string
		json.NewDecoder(rr.Body).Decode(&response)
		token = response["token"]
		if token == "" {
			t.Fatal("Token is empty")
		}
	})

	t.Run("Access Protected Route", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/profile", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		r.ServeHTTP(rr, req)

		if http.StatusOK != rr.Code {
			t.Fatalf("Expected: %d, Got: %d", http.StatusOK, rr.Code)
		}

		var response map[string]any
		json.NewDecoder(rr.Body).Decode(&response)
		if testUser.Email != response["email"] {
			t.Fatalf("Expected: %s, Got: %s", testUser.Email, response["email"])
		}
	})
}
