package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"restfulapi/app/models"
	"restfulapi/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/bcrypt"
)

func withPostgres(t *testing.T) (*sql.DB, config.Config, func(), func()) {
	os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	cfg := config.Load()

	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:latest",
		postgres.WithDatabase("test-db"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(5*time.Second)),
	)
	if err != nil {
		t.Fatalf("failed to start container: %s", err)
	}

	cfg.Postgres.Host, err = pgContainer.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}

	p, err := pgContainer.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatal(err)
	}

	cfg.Postgres.Port = p.Int()
	cfg.Postgres.User = "postgres"
	cfg.Postgres.Password = "postgres"
	cfg.Postgres.DBName = "test-db"
	cfg.Mailjet.Active = "false"

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		t.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		t.Fatalf("failed to ping database: %s", err)
	}

	cleanup := func() {
		db.Close()
		pgContainer.Terminate(ctx)
	}

	deleteUsers := func() {
		_, err := db.Exec("DELETE FROM users")
		if err != nil {
			t.Fatal(err)
		}
	}

	// UUID Extension
	_, err = db.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`)
	if err != nil {
		t.Fatalf("failed to add uuid extension: %s", err)
	}

	_, err = db.Exec(`
        CREATE TABLE users (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            email TEXT UNIQUE NOT NULL,
            email_verification_code TEXT NOT NULL,
            email_verified BOOLEAN DEFAULT FALSE,
            password TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        )
    `)
	if err != nil {
		t.Fatalf("failed to create user schema: %s", err)
	}

	return db, cfg, cleanup, deleteUsers
}

func TestRunner(t *testing.T) {
	_, cfg, cleanup, deleteUsers := withPostgres(t)
	defer cleanup()

	t.Run("TestRegisterHandler", testRegisterHandler(cfg, t))
	deleteUsers()
	t.Run("TestLoginHandler", testLoginHandler(cfg, t))
	deleteUsers()
	t.Run("TestAuthMiddleware", testAuthMiddleware(cfg, t))
	deleteUsers()
	t.Run("TestProfileHandler", testProfileHandler(cfg, t))
}

func testRegisterHandler(cfg config.Config, t1 *testing.T) func(t *testing.T) {
	return func(t *testing.T) {
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
					"message": "User already exists or different problem",
				},
			},
		}

		for _, tc := range tests {
			t1.Run(tc.name, func(t *testing.T) {
				body, _ := json.Marshal(tc.credentials)
				req, err := http.NewRequest("POST", "/register", bytes.NewBuffer(body))
				if err != nil {
					t.Fatal(err)
				}

				rr := httptest.NewRecorder()
				handler := http.HandlerFunc(RegisterHandler(cfg))

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
}

func testLoginHandler(cfg config.Config, t1 *testing.T) func(t *testing.T) {
	return func(t *testing.T) {
		// Register test user
		testUser := models.Credentials{
			Email:    "login@example.com",
			Password: "password123",
		}

		// Register directly
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testUser.Password), bcrypt.DefaultCost)
		_, err := insertUser(models.User{
			Email:    testUser.Email,
			Password: string(hashedPassword),
		}, cfg)
		if err != nil {
			t1.Fatal(err)
		}

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
			t1.Run(tc.name, func(t *testing.T) {
				body, _ := json.Marshal(tc.credentials)
				req, err := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
				if err != nil {
					t.Fatal(err)
				}

				rr := httptest.NewRecorder()
				handler := http.HandlerFunc(LoginHandler(cfg))

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
}

func testAuthMiddleware(cfg config.Config, t1 *testing.T) func(t *testing.T) {
	return func(t *testing.T) {
		// Register test user
		testUser := models.Credentials{
			Email:    "middleware@example.com",
			Password: "password123",
		}

		// Register directly
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testUser.Password), bcrypt.DefaultCost)
		user, err := insertUser(models.User{
			Email:    testUser.Email,
			Password: string(hashedPassword),
		}, cfg)
		if err != nil {
			t1.Fatal(err)
		}

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Generate a valid token
		expirationTime := time.Now().Add(15 * time.Minute)
		claims := &models.Claims{
			UserID: user.Id,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expirationTime),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		validToken, _ := token.SignedString([]byte(cfg.General.JwtKey))

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
				authHeader:     "Bearer " + generateExpiredToken(cfg),
				expectedStatus: http.StatusUnauthorized,
			},
		}

		for _, tc := range tests {
			t1.Run(tc.name, func(t *testing.T) {
				req, err := http.NewRequest("GET", "/profile", nil)
				if err != nil {
					t.Fatal(err)
				}

				if tc.authHeader != "" {
					req.Header.Set("Authorization", tc.authHeader)
				}

				rr := httptest.NewRecorder()

				wrapped := AuthMiddleware(cfg)(nextHandler)
				wrapped.ServeHTTP(rr, req)

				if tc.expectedStatus != rr.Code {
					t.Fatalf("Expected: %d, Got: %d", tc.expectedStatus, rr.Code)
				}
			})
		}
	}
}

// Helper function to generate an expired token
func generateExpiredToken(cfg config.Config) string {
	expirationTime := time.Now().Add(-15 * time.Minute)
	claims := &models.Claims{
		UserID: uuid.New(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	expiredToken, _ := token.SignedString([]byte(cfg.General.JwtKey))
	return expiredToken
}

/*
func TestMailVerification(t *testing.T) {
	resetUsers()
	testUser := models.User{Id: 1, Email: "mail@example.com", EmailVerificationCode: uuid.NewString()}
	users = append(users, testUser)
	// TODO finish test
}
*/

func testProfileHandler(cfg config.Config, t1 *testing.T) func(t *testing.T) {
	return func(t *testing.T) {
		// Register test user
		testUser := models.Credentials{
			Email:    "profile@example.com",
			Password: "password123",
		}

		// Register directly
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testUser.Password), bcrypt.DefaultCost)
		user, err := insertUser(models.User{
			Email:    testUser.Email,
			Password: string(hashedPassword),
		}, cfg)
		if err != nil {
			t1.Fatal(err)
		}

		expirationTime := time.Now().Add(15 * time.Minute)
		claims := &models.Claims{
			UserID: user.Id,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expirationTime),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		validToken, _ := token.SignedString([]byte(cfg.General.JwtKey))

		invalidUserClaims := &models.Claims{
			UserID: uuid.New(),
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expirationTime),
			},
		}

		invalidUserToken := jwt.NewWithClaims(jwt.SigningMethodHS256, invalidUserClaims)
		nonExistentUserToken, _ := invalidUserToken.SignedString([]byte(cfg.General.JwtKey))

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
			t1.Run(tc.name, func(t *testing.T) {
				req, err := http.NewRequest("GET", "/api/profile", nil)
				if err != nil {
					t.Fatal(err)
				}

				req.Header.Set("Authorization", "Bearer "+tc.token)

				rr := httptest.NewRecorder()
				handler := http.HandlerFunc(ProfileHandler(cfg))

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

					if fmt.Sprintf("%s", user.Id) != response["id"] {
						t.Fatalf("Expected ID: %v, Got: %v", user.Id, response["id"])
					}

					if testUser.Email != response["email"] {
						t.Fatalf("Expected ID: %v, Got: %v", testUser.Email, response["email"])
					}
				}
			})
		}
	}
}

func testIntegration(cfg config.Config, t1 *testing.T) func(t *testing.T) {
	return func(t *testing.T) {
		// Register test user
		testUser := models.Credentials{
			Email:    "integration@example.com",
			Password: "integration123",
		}

		r := mux.NewRouter()
		SetupAuthRoutes(r, cfg)

		t1.Run("Register User", func(t *testing.T) {
			body, _ := json.Marshal(testUser)
			req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(body))
			rr := httptest.NewRecorder()

			r.ServeHTTP(rr, req)

			if http.StatusCreated != rr.Code {
				t.Fatalf("Expected: %d, Got: %d", http.StatusCreated, rr.Code)
			}
		})

		var token string
		t1.Run("Login User", func(t *testing.T) {
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

		t1.Run("Access Protected Route", func(t *testing.T) {
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
}
