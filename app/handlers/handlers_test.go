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

	rdb "restfulapi/app/db"
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

	_, err = db.Exec(rdb.GetUserTableQuery())
	if err != nil {
		t.Fatalf("failed to create user schema: %s", err)
	}

	_, err = db.Exec(rdb.GetPasswordResetTokenTableQuery())
	if err != nil {
		t.Fatalf("failed to create password reset token schema: %s", err)
	}

	return db, cfg, cleanup, deleteUsers
}

func TestRunner(t *testing.T) {
	_, cfg, cleanup, deleteUsers := withPostgres(t)
	defer cleanup()

	t.Run("TestRegisterHandler", testRegisterHandler(cfg))
	deleteUsers()
	deleteUsers()
	t.Run("TestLoginHandler", testLoginHandler(cfg))
	t.Run("TestAuthMiddleware", testAuthMiddleware(cfg))
	deleteUsers()
	t.Run("TestProfileHandler", testProfileHandler(cfg))
	deleteUsers()
	t.Run("TestIntegration", testIntegration(cfg))
	t.Run("TestEmailVerification", testMailVerification(cfg))
	deleteUsers()
	t.Run("TestPasswordReset", testPasswordResetGeneration(cfg))
}

func testRegisterHandler(cfg config.Config) func(t *testing.T) {
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
					Password: "password!123",
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
					Password: "password!123",
				},
				expectedStatus: http.StatusConflict,
				expectedBody: map[string]string{
					"message": "User already exists or different problem",
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

func testLoginHandler(cfg config.Config) func(t *testing.T) {
	return func(t *testing.T) {
		// Register test user
		testUser := models.Credentials{
			Email:    "login@example.com",
			Password: "password!123",
		}

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testUser.Password), bcrypt.DefaultCost)
		_, err := insertUser(models.User{
			Email:    testUser.Email,
			Password: string(hashedPassword),
		}, cfg)
		if err != nil {
			t.Fatal(err)
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
					Password: "password!123",
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

func testAuthMiddleware(cfg config.Config) func(t *testing.T) {
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
			t.Fatal(err)
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
			t.Run(tc.name, func(t *testing.T) {
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

func testMailVerification(cfg config.Config) func(t *testing.T) {
	return func(t *testing.T) {
		// Register test user
		testUser := models.User{
			Email:    "mail@example.com",
			Password: "password!123",
		}

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testUser.Password), bcrypt.DefaultCost)
		user, err := insertUser(models.User{
			Email:                 testUser.Email,
			Password:              string(hashedPassword),
			EmailVerificationCode: uuid.NewString(),
		}, cfg)
		if err != nil {
			t.Fatal(err)
		}

		tests := []struct {
			name             string
			verificationCode string
			expectedStatus   int
		}{
			{
				name:             "Valid Code",
				verificationCode: user.EmailVerificationCode,
				expectedStatus:   http.StatusOK,
			},
			{
				name:             "Empty Code",
				verificationCode: "",
				expectedStatus:   http.StatusNotFound,
			},
			{
				name:             "Wrong Code",
				verificationCode: "djfdklsgn",
				expectedStatus:   http.StatusBadRequest,
			},
		}

		r := mux.NewRouter()
		SetupAuthRoutes(r, cfg)

		for _, tc := range tests {
			req, err := http.NewRequest("GET", fmt.Sprintf("/verify/%s", tc.verificationCode), nil)
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()

			r.ServeHTTP(rr, req)

			if tc.expectedStatus != rr.Code {
				t.Fatalf("Expected Code: %d, Got: %d", tc.expectedStatus, rr.Code)
			}
		}
	}
}

func testPasswordResetGeneration(cfg config.Config) func(t *testing.T) {
	return func(t *testing.T) {
		// Register test user
		testUser := models.User{
			Email:    "password@example.com",
			Password: "password!123",
		}

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testUser.Password), bcrypt.DefaultCost)
		_, err := insertUser(models.User{
			Email:    testUser.Email,
			Password: string(hashedPassword),
		}, cfg)
		if err != nil {
			t.Fatal(err)
		}

		tests := []struct {
			name           string
			email          string
			expectedStatus int
			checkUser      bool
		}{
			{
				name:           "Generate Password Reset Token",
				email:          testUser.Email,
				expectedStatus: http.StatusOK,
				checkUser:      true,
			},
			{
				name:           "Invalid E-Mail",
				email:          "some@email.com",
				expectedStatus: http.StatusBadRequest,
				checkUser:      false,
			},
		}

		r := mux.NewRouter()
		SetupAuthRoutes(r, cfg)

		for _, tc := range tests {
			body, _ := json.Marshal(map[string]string{"email": tc.email})
			req, err := http.NewRequest("POST", "/password-reset", bytes.NewBuffer(body))
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()

			r.ServeHTTP(rr, req)

			if tc.expectedStatus != rr.Code {
				t.Fatalf("Expected Code: %d, Got: %d", tc.expectedStatus, rr.Code)
			}

			if tc.checkUser {
				user, err := findUserByEmail(tc.email, cfg)
				if err != nil {
					t.Fatal(err)
				}
				_, err = getPasswordResetTokenByUserId(user.Id, cfg)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func testPasswordReset(cfg config.Config) func(t *testing.T) {
	return func(t *testing.T) {
		/*
			testUser := models.User{
				Email:    "pwd@example.com",
				Password: "password!123",
			}

			insertedUser, err := insertUser(testUser, cfg)
			if err != nil {
				t.Fatal(err)
			}
		*/
	}
}

func testProfileHandler(cfg config.Config) func(t *testing.T) {
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
			t.Fatal(err)
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
			t.Run(tc.name, func(t *testing.T) {
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

func testIntegration(cfg config.Config) func(t *testing.T) {
	return func(t *testing.T) {
		// Register test user
		testUser := models.Credentials{
			Email:    "integration@example.com",
			Password: "integration!123",
		}

		r := mux.NewRouter()
		SetupAuthRoutes(r, cfg)

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
}
