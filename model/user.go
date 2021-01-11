package model

import (
	"golang.org/x/crypto/bcrypt"
)

// User contains minimal user informations.
type User struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// PasswordHash changes plain password string to hashed password.
func (u *User) PasswordHash() (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(u.Password), 14)
	return string(bytes), err
}

// PasswordCheck confines if password is match the hashed.
func (u *User) PasswordCheck(hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(u.Password))
	return err == nil
}
