package models

import "github.com/golang-jwt/jwt/v5"

type User struct {
	Id       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"-"`
}

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}
