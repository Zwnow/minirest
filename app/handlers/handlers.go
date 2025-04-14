package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"restfulapi/app/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

var (
	users = []models.User{}
	mu    sync.Mutex
)

// TODO: add to env
var jwtKey = []byte("fdsjgh2o3bg2Wt2Y31bnxl342gvxA")

type contextKey string

const UserContextKey contextKey = "userID"

func SetupAuthRoutes(r *mux.Router) {
	r.Use(RecoveryMiddleware)
	r.Use(SecureHeadersMiddleware)
	r.HandleFunc("/register", RegisterHandler).Methods("POST")
	r.HandleFunc("/login", LoginHandler).Methods("POST")

	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(AuthMiddleware)
	protected.HandleFunc("/profile", ProfileHandler).Methods("GET")
	protected.HandleFunc("/verify/{code}", EmailVerificationHandler).Methods("GET")
}

func EmailVerificationHandler(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(UserContextKey)
	if id == nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "User not found in context"})
		return
	}

	userId := id.(int)

	// Get User
	// TODO: replace with db
	var user models.User
	userFound := false
	for _, u := range users {
		if u.Id == userId {
			user = u
			userFound = true
		}
	}

	if !userFound {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "User not found"})
		return
	}

	code := mux.Vars(r)["code"]
	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing verification code"})
		return
	}

	if code == user.EmailVerificationCode {
		// TODO: replace with db
		for i := range users {
			if user.Id == users[i].Id {
				users[i].EmailVerified = true
			}
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Email verified successfully"})
		return
	}
	w.WriteHeader(http.StatusBadRequest)
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var creds models.Credentials

	// Parse request body
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "No credentials provided"})
		return
	}

	mu.Lock()
	defer mu.Unlock()

	// Check if user already exists
	for _, user := range users {
		if user.Email == creds.Email {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"message": "User already exists",
			})
			return
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Create new user (TODO: add database)
	// Can panic, TODO: handle safely (uuid.NewString)
	newUser := models.User{
		Id:                    len(users) + 1,
		Email:                 creds.Email,
		EmailVerified:         false,
		EmailVerificationCode: uuid.NewString(),
		Password:              string(hashedPassword),
	}

	users = append(users, newUser)

	// Send verification mail
	go func() {
		err := SendRegistrationMail("svenotimm@gmail.com", "Sven-Ole Timm", newUser.EmailVerificationCode)
		if err != nil {
			log.Printf("Failed to send registration mail: %v\n", err)
		}
	}()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User registered successfully",
	})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds models.Credentials

	// Parse request body
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Find user
	var user models.User
	userFound := false

	for _, u := range users {
		if u.Email == creds.Email {
			user = u
			userFound = true
			break
		}
	}

	if !userFound {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// token expiration time
	expirationTime := time.Now().Add(15 * time.Minute)

	// Create Claims
	claims := &models.Claims{
		UserID: user.Id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret key
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Return token to client
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("AuthMiddleware called")
		// Get token
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Remove Bearer Prefix
		if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
			tokenStr = tokenStr[7:]
		}

		// Parse and validate token
		claims := &models.Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), UserContextKey, claims.UserID)

		// Token is valid, proceed
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.Header().Set("Connection", "close")
				fmt.Println(err)
				debug.PrintStack()
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func SecureHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevents XSS by specifying which dynamic resources are allowed to load
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		// Prevents MIME sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Prevents site from being embedded in an iframe, clickjacking protection
		w.Header().Set("X-Frame-Options", "DENY")
		// Enforces HTTPS and protects agains downgrade attacks
		// TODO: Enable later
		// w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		// Referrer-Policy
		w.Header().Set("Referrer-Policy", "no-referrer")

		next.ServeHTTP(w, r)
	})
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
		tokenStr = tokenStr[7:]
	}

	claims := &models.Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
		return jwtKey, nil
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var user models.User
	userFound := false

	for _, u := range users {
		if u.Id == claims.UserID {
			user = u
			userFound = true
			break
		}
	}

	if !userFound {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":    strconv.Itoa(user.Id),
		"email": user.Email,
	})
}
