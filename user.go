package main

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

// User represents the user model
type User struct {
	ID              string
	Name            string
	DisplayName     string
	Credentials     []webauthn.Credential // Renamed field from WebAuthnCredentials to Credentials
}

// WebAuthnID returns the user's ID as byte slice
func (u *User) WebAuthnID() []byte {
	return []byte(u.ID)
}

// WebAuthnName returns the user's username
func (u *User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the user's display name
func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnIcon is not used in this example but required by the interface
func (u *User) WebAuthnIcon() string {
	return ""
}

// WebAuthnCredentials returns the user's credentials
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials // Return the renamed field
}

// AddCredential adds a WebAuthn credential to the user
func (u *User) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred) // Use the renamed field
}

// UserDB is a simple in-memory user database
type UserDB struct {
	users map[string]*User
}

// NewUserDB creates a new UserDB
func NewUserDB() *UserDB {
	return &UserDB{
		users: make(map[string]*User),
	}
}

// GetUser returns a user by username
func (db *UserDB) GetUser(username string) (*User, bool) {
	user, exists := db.users[username]
	return user, exists
}

// AddUser adds a new user to the database
func (db *UserDB) AddUser(user *User) {
	db.users[user.Name] = user
}