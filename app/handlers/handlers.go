package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
    "regexp"
    "errors"
	"time"
    "unicode"

	"restfulapi/app/db"
	"restfulapi/app/models"
	"restfulapi/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const UserContextKey contextKey = "userID"

func SetupAuthRoutes(r *mux.Router, cfg config.Config) {
	r.Use(RecoveryMiddleware)
	r.Use(SecureHeadersMiddleware)
	r.HandleFunc("/register", RegisterHandler(cfg)).Methods("POST")
	r.HandleFunc("/login", LoginHandler(cfg)).Methods("POST")
	r.HandleFunc("/password-reset", PasswordResetMailHandler(cfg)).Methods("POST")
	r.HandleFunc("/password-reset/{code}", PasswordResetHandler(cfg)).Methods("POST")
	r.HandleFunc("/verify/{code}", EmailVerificationHandler(cfg)).Methods("GET")

	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(AuthMiddleware(cfg))
	protected.HandleFunc("/profile", ProfileHandler(cfg)).Methods("GET")
}

func EmailVerificationHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
        code := mux.Vars(r)["code"]
		if code == "" {
			errorResponse(http.StatusBadRequest, "Missing verification code", w)
            log.Println("code empty")
			return
		}

		user, err := findUserByEmailVerificationToken(code, cfg)
		if err != nil {
			if err == sql.ErrNoRows {
				errorResponse(http.StatusBadRequest, "User not found", w)
                log.Println(err)
				return
			}
			errorResponse(http.StatusInternalServerError, "", w)
			log.Println(err)
			return
        }

        user.EmailVerified = true
        err = verifyUserEmail(user, cfg)
        if err != nil {
            errorResponse(http.StatusInternalServerError, "Failed to verify user email", w)
            log.Println(err)
            return
        }

        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]string{"message": "Email verified successfully"})
	}
}

type PasswordResetRequest struct {
    Email string `json:"email"`
}

func PasswordResetMailHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
        var req PasswordResetRequest

		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Println(err)
			return
		}

		user, err := findUserByEmail(req.Email, cfg)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Println(err)
			return
		}

		user.PasswordResetCode = uuid.NewString()
		err = setPasswordResetCode(user, cfg)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Println(err)
			return
		}

		SendPasswordResetMail(cfg, user)
	}
}

func PasswordResetHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var password string

		code := mux.Vars(r)["code"]

		err := json.NewDecoder(r.Body).Decode(&password)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Println(err)
			return
		}

        if err := isStrongPassword(password); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
        }

		user, err := findUserByPasswordResetToken(code, cfg)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Println(err)
			return
		}

		err = updateUserPassword(cfg, user, password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Println(err)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func RegisterHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var creds models.Credentials

		// Parse request body
		err := json.NewDecoder(r.Body).Decode(&creds)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "No credentials provided"})
			return
		}

        if err := isValidEmail(creds.Email); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
        }

        if err := isStrongPassword(creds.Password); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
        }

		// Check if user already exists
		_, err = findUserByEmail(creds.Email, cfg)
		if err != sql.ErrNoRows {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"message": "User already exists or different problem",
			})
			log.Println(err)
			return
		}

		// Hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Can panic, TODO: handle safely (uuid.NewString)
		newUser := models.User{
			Email:                 creds.Email,
			EmailVerified:         false,
			EmailVerificationCode: uuid.NewString(),
			Password:              string(hashedPassword),
		}

		_, err = insertUser(newUser, cfg)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Send verification mail
		go func() {
			err := SendRegistrationMail(cfg, newUser.Email, "Sven-Ole Timm", newUser.EmailVerificationCode)
			if err != nil {
				log.Printf("Failed to send registration mail: %v\n", err)
			}
		}()

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "User registered successfully",
		})
	}
}

func LoginHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var creds models.Credentials

		// Parse request body
		err := json.NewDecoder(r.Body).Decode(&creds)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Println(err)
			return
		}

		// Find user
		user, err := findUserByEmail(creds.Email, cfg)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			log.Println(err)
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			log.Println(err)
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
		tokenString, err := token.SignedString([]byte(cfg.General.JwtKey))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Println(err)
			return
		}

		// Return token to client
		json.NewEncoder(w).Encode(map[string]string{
			"token": tokenString,
		})
	}
}

func AuthMiddleware(cfg config.Config) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
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
				return []byte(cfg.General.JwtKey), nil
			})

			if err != nil || !token.Valid {
				w.WriteHeader(http.StatusUnauthorized)
				log.Println(err)
				return
			}
			ctx := context.WithValue(r.Context(), UserContextKey, claims.UserID)

			// Token is valid, proceed
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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

func ProfileHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
			tokenStr = tokenStr[7:]
		}

		claims := &models.Claims{}
		_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
			return []byte(cfg.General.JwtKey), nil
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		user, err := findUserByID(claims.UserID, cfg)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"id":    user.Id.String(),
			"email": user.Email,
		})
	}
}

func findUserByEmail(email string, cfg config.Config) (models.User, error) {
	var user models.User

	db, err := db.NewPostgres(cfg.Postgres)
	if err != nil {
		return user, err
	}
	defer db.Close()

	query := `
    SELECT id, email, email_verification_code, email_verified, password_reset_code, password, created_at, updated_at
    FROM users
    WHERE email = $1
    `

	err = db.QueryRow(query, email).Scan(
		&user.Id,
		&user.Email,
		&user.EmailVerificationCode,
		&user.EmailVerified,
		&user.PasswordResetCode,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return user, err
	}

	return user, nil
}

func findUserByID(id uuid.UUID, cfg config.Config) (models.User, error) {
	var user models.User

	db, err := db.NewPostgres(cfg.Postgres)
	if err != nil {
		return user, err
	}
	defer db.Close()

	query := `
    SELECT id, email, email_verification_code, email_verified, password, created_at, updated_at
    FROM users
    WHERE id = $1
    `

	err = db.QueryRow(query, id).Scan(
		&user.Id,
		&user.Email,
		&user.EmailVerificationCode,
		&user.EmailVerified,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return user, err
	}

	return user, nil
}
func findUserByEmailVerificationToken(token string, cfg config.Config) (models.User, error) {
	var user models.User

	db, err := db.NewPostgres(cfg.Postgres)
	if err != nil {
		return user, err
	}
	defer db.Close()

	query := `
    SELECT id, email, email_verification_code, email_verified, password, created_at, updated_at
    FROM users
    WHERE email_verification_code = $1
    `

	err = db.QueryRow(query, token).Scan(
		&user.Id,
		&user.Email,
		&user.EmailVerificationCode,
		&user.EmailVerified,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return user, err
	}

	return user, nil
}

func findUserByPasswordResetToken(token string, cfg config.Config) (models.User, error) {
	var user models.User

	db, err := db.NewPostgres(cfg.Postgres)
	if err != nil {
		return user, err
	}
	defer db.Close()

	query := `
    SELECT id, email, email_verification_code, email_verified, password, created_at, updated_at
    FROM users
    WHERE password_reset_code = $1
    `

	err = db.QueryRow(query, token).Scan(
		&user.Id,
		&user.Email,
		&user.EmailVerificationCode,
		&user.PasswordResetCode,
		&user.EmailVerified,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return user, err
	}

	return user, nil
}

func updateUserPassword(cfg config.Config, user models.User, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	db, err := db.NewPostgres(cfg.Postgres)
	if err != nil {
		return err
	}
	defer db.Close()

	query := `
    UPDATE users SET
        password_reset_code = "", 
        password = $1
        updated_at = now()
    WHERE id = $2
    `

	_, err = db.Exec(query, hashedPassword, user.Id)
	if err != nil {
		return err
	}

	return nil
}

func verifyUserEmail(user models.User, cfg config.Config) error {
	db, err := db.NewPostgres(cfg.Postgres)
	if err != nil {
		return err
	}
	defer db.Close()

	query := `
    UPDATE users SET
        email_verified = TRUE, 
        updated_at = now()
    WHERE id = $1
    `

	_, err = db.Exec(query, user.Id)
	if err != nil {
		return err
	}

	return nil
}

func setPasswordResetCode(user models.User, cfg config.Config) error {
	db, err := db.NewPostgres(cfg.Postgres)
	if err != nil {
		return err
	}
	defer db.Close()

	query := `
    UPDATE users SET
        password_reset_code = $1, 
        updated_at = now()
    WHERE id = $2
    `

	_, err = db.Exec(query, user.PasswordResetCode, user.Id)
	if err != nil {
		return err
	}

	return nil
}

func errorResponse(status int, errorText string, w http.ResponseWriter) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": errorText,
	})
}

func insertUser(user models.User, cfg config.Config) (models.User, error) {
	db, err := db.NewPostgres(cfg.Postgres)
	if err != nil {
		return user, err
	}
	defer db.Close()

	query := `
    INSERT INTO users (email, email_verification_code, email_verified, password)
    VALUES ($1, $2, $3, $4)
    RETURNING id, created_at, updated_at
    `

	err = db.QueryRow(query,
		user.Email,
		user.EmailVerificationCode,
		user.EmailVerified,
		user.Password,
	).Scan(&user.Id, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return user, err
	}

	return user, nil
}

func isValidEmail(email string) error {
	const emailRegex = `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegex)

	if !re.MatchString(email) {
		return errors.New("invalid email format")
	}
	return nil
}

func isStrongPassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	if len(password) > 72 {
		return errors.New("password must be at most 72 characters long")
	}

	var hasLetter, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsLetter(ch):
			hasLetter = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	if !hasLetter {
		return errors.New("password must include at least one letter")
	}
	if !hasDigit {
		return errors.New("password must include at least one digit")
	}
	if !hasSpecial {
		return errors.New("password must include at least one special character")
	}

	return nil
}
