package main

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var (
	webAuthn     *webauthn.WebAuthn
	userDB       *UserDB
	sessionStore *sessions.CookieStore
)

func main() {
	// Register the SessionData type with gob
	gob.Register(webauthn.SessionData{})
	
	// Initialize the user database
	userDB = NewUserDB()

	// Initialize WebAuthn
	var err error
	webAuthn, err = InitWebAuthn()
	if err != nil {
		log.Fatal("Failed to initialize WebAuthn:", err)
	}

	// Initialize session store with a secure key (should be a proper secret in production)
	sessionStore = sessions.NewCookieStore([]byte("secure-session-key"))

	// Create a new router
	r := mux.NewRouter()

	// Set up routes
	r.HandleFunc("/", homeHandler).Methods("GET")
	r.HandleFunc("/register", beginRegistrationHandler).Methods("GET")
	r.HandleFunc("/register/begin", beginRegistrationHandler).Methods("POST")
	r.HandleFunc("/register/finish", finishRegistrationHandler).Methods("POST")
	r.HandleFunc("/login", loginPageHandler).Methods("GET")
	r.HandleFunc("/login/begin", beginLoginHandler).Methods("POST")
	r.HandleFunc("/login/finish", finishLoginHandler).Methods("POST")
	r.HandleFunc("/dashboard", dashboardHandler).Methods("GET")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")
	
	// New routes for adding passkeys
	r.HandleFunc("/add-passkey/begin", beginAddPasskeyHandler).Methods("POST")
	r.HandleFunc("/add-passkey/finish", finishAddPasskeyHandler).Methods("POST")

	// Serve static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Start the server
	fmt.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// homeHandler renders the home page
func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// loginPageHandler renders the login page
func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// beginRegistrationHandler starts the registration process
func beginRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	// If it's a GET request, render the registration page
	if r.Method == "GET" {
		tmpl, err := template.ParseFiles("templates/register.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	}

	// For POST request, handle the registration
	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	// Check if user already exists
	if _, exists := userDB.GetUser(username); exists {
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}

	// Create a new user
	user := &User{
		ID:          username,
		Name:        username,
		DisplayName: username,
	}
	userDB.AddUser(user)

	// Generate registration options
	options, sessionData, err := webAuthn.BeginRegistration(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store session data
	session, _ := sessionStore.Get(r, "registration-session")
	session.Values["username"] = username
	session.Values["sessionData"] = sessionData
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send registration options to client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// finishRegistrationHandler completes the registration process
func finishRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	// Get session data
	session, err := sessionStore.Get(r, "registration-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get username and session data from session
	username, ok := session.Values["username"].(string)
	if !ok {
		http.Error(w, "User not found in session", http.StatusBadRequest)
		return
	}

	sessionData, ok := session.Values["sessionData"].(webauthn.SessionData)
	if !ok {
		http.Error(w, "Session data not found", http.StatusBadRequest)
		return
	}

	// Get user from database
	user, exists := userDB.GetUser(username)
	if !exists {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Parse response
	response, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Complete registration
	credential, err := webAuthn.CreateCredential(user, sessionData, response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Add credential to user
	user.AddCredential(*credential)

	// Clear session
	session.Options.MaxAge = -1
	session.Save(r, w)

	// Successful response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// beginLoginHandler starts the login process
func beginLoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	// Get user from database
	user, exists := userDB.GetUser(username)
	if !exists {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Generate login options
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store session data
	session, _ := sessionStore.Get(r, "login-session")
	session.Values["username"] = username
	session.Values["sessionData"] = sessionData
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send login options to client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// finishLoginHandler completes the login process
func finishLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Get session data
	session, err := sessionStore.Get(r, "login-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get username and session data from session
	username, ok := session.Values["username"].(string)
	if !ok {
		http.Error(w, "User not found in session", http.StatusBadRequest)
		return
	}

	sessionData, ok := session.Values["sessionData"].(webauthn.SessionData)
	if !ok {
		http.Error(w, "Session data not found", http.StatusBadRequest)
		return
	}

	// Get user from database
	user, exists := userDB.GetUser(username)
	if !exists {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Parse response
	response, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Complete login
	_, err = webAuthn.ValidateLogin(user, sessionData, response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Clear login session
	session.Options.MaxAge = -1
	session.Save(r, w)

	// Create authenticated session
	authSession, _ := sessionStore.Get(r, "auth-session")
	authSession.Values["authenticated"] = true
	authSession.Values["username"] = username
	authSession.Save(r, w)

	// Successful response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// dashboardHandler shows the user dashboard
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated
	session, _ := sessionStore.Get(r, "auth-session")
	auth, ok := session.Values["authenticated"].(bool)
	if !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username, ok := session.Values["username"].(string)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	tmpl, err := template.ParseFiles("templates/dashboard.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, map[string]string{"Username": username})
}

// logoutHandler logs out the user
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "auth-session")
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// beginAddPasskeyHandler starts the process of adding a new passkey
func beginAddPasskeyHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated
	session, _ := sessionStore.Get(r, "auth-session")
	auth, ok := session.Values["authenticated"].(bool)
	if !ok || !auth {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	// Get username from session
	username, ok := session.Values["username"].(string)
	if !ok {
		http.Error(w, "Username not found in session", http.StatusBadRequest)
		return
	}

	// Get user from database
	user, exists := userDB.GetUser(username)
	if !exists {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Generate registration options for additional passkey
	options, sessionData, err := webAuthn.BeginRegistration(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store session data
	addPasskeySession, _ := sessionStore.Get(r, "add-passkey-session")
	addPasskeySession.Values["username"] = username
	addPasskeySession.Values["sessionData"] = sessionData
	err = addPasskeySession.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send registration options to client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// finishAddPasskeyHandler completes the process of adding a new passkey
func finishAddPasskeyHandler(w http.ResponseWriter, r *http.Request) {
	// Get session data
	session, err := sessionStore.Get(r, "add-passkey-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get username and session data from session
	username, ok := session.Values["username"].(string)
	if !ok {
		http.Error(w, "User not found in session", http.StatusBadRequest)
		return
	}

	sessionData, ok := session.Values["sessionData"].(webauthn.SessionData)
	if !ok {
		http.Error(w, "Session data not found", http.StatusBadRequest)
		return
	}

	// Get user from database
	user, exists := userDB.GetUser(username)
	if !exists {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Parse response
	response, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Complete registration
	credential, err := webAuthn.CreateCredential(user, sessionData, response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Add credential to user
	user.AddCredential(*credential)

	// Clear session
	session.Options.MaxAge = -1
	session.Save(r, w)

	// Successful response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}