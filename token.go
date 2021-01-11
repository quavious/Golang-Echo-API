package main

import "github.com/dgrijalva/jwt-go"

type jwtCustomClaims struct {
	jwt.StandardClaims
	ID int `json:"user_id"`
}
