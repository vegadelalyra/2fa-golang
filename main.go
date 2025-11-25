package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"image/png"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"github.com/pquerna/otp/totp"
)

// --- 1. IN-MEMORY DATABASE ---
type User struct {
	Name        string
	TOTPSecret  string // Stores Google Auth Secret
	TOTPEnabled bool   // Flag to check if 2FA is active
}

var (
	users  = map[string]*User{}
	userMu sync.RWMutex
	tmpl   *template.Template
)

// --- 2. CONFIGURATION & SETUP ---
func main() {
	var err error
	// Load the separated HTML file
	tmpl, err = template.ParseFiles("index.html")
	if err != nil {
		log.Fatal("Error loading index.html: ", err)
	}

	r := mux.NewRouter()

	// Page Routes
	r.HandleFunc("/", handleIndex).Methods("GET")
	r.HandleFunc("/dashboard", handleDashboard).Methods("GET")
	r.HandleFunc("/logout", handleLogout).Methods("GET")

	// TOTP API
	r.HandleFunc("/api/totp/generate", handleTOTPGenerate).Methods("POST")
	r.HandleFunc("/api/totp/validate", handleTOTPValidate).Methods("POST")
	r.HandleFunc("/api/totp/disable", handleTOTPDisable).Methods("POST") // Accepts password in body now

	// WITHDRAWAL (TOTP Only)
	r.HandleFunc("/api/withdraw/totp", handleWithdrawalTOTP).Methods("POST")

	fmt.Println("Server started at http://localhost:8080")
	log.Println("DEBUG: Logging initialized.")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// --- 3. HANDLERS ---

func handleIndex(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username != "" {
		log.Printf("DEBUG: Login attempt for user: %s", username)
		userMu.Lock()
		if _, exists := users[username]; !exists {
			log.Printf("DEBUG: Creating new user: %s", username)
			users[username] = &User{Name: username}
		} else {
			log.Printf("DEBUG: User %s found in memory.", username)
		}
		userMu.Unlock()

		http.SetCookie(w, &http.Cookie{Name: "session_user", Value: username, Path: "/"})
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	tmpl.ExecuteTemplate(w, "login", nil)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		log.Println("DEBUG: Dashboard access denied. No session.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	log.Printf("DEBUG: Serving dashboard for %s (2FA Enabled: %v)", user.Name, user.TOTPEnabled)
	tmpl.ExecuteTemplate(w, "dashboard", user)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	log.Println("DEBUG: Logging out user.")
	http.SetCookie(w, &http.Cookie{Name: "session_user", Value: "", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- 4. TOTP LOGIC ---

func handleTOTPGenerate(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	log.Printf("DEBUG: Generating new TOTP key for %s", user.Name)

	key, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      "GoWallet",
		AccountName: user.Name,
	})

	var buf bytes.Buffer
	img, _ := key.Image(200, 200)
	png.Encode(&buf, img)
	qrBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	json.NewEncoder(w).Encode(map[string]string{
		"secret": key.Secret(),
		"url":    key.URL(),
		"qr":     "data:image/png;base64," + qrBase64,
	})
}

func handleTOTPValidate(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Secret string
		Code   string
	}
	json.NewDecoder(r.Body).Decode(&req)

	log.Printf("DEBUG: Validating Setup Code for %s. Code: %s", user.Name, req.Code)

	secretToTest := req.Secret
	if secretToTest == "" {
		secretToTest = user.TOTPSecret
	}

	if totp.Validate(req.Code, secretToTest) {
		log.Printf("DEBUG: Code Valid! Enabling 2FA for %s", user.Name)
		// If this was a setup request, save the secret
		if !user.TOTPEnabled && req.Secret != "" {
			userMu.Lock()
			user.TOTPSecret = req.Secret
			user.TOTPEnabled = true
			userMu.Unlock()
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	} else {
		log.Printf("DEBUG: Invalid Code for %s", user.Name)
		http.Error(w, "Invalid Code", http.StatusUnauthorized)
	}
}

// Updated: Handle disabling 2FA with Password Check
func handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse the password from the request
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	log.Printf("DEBUG: Request to disable 2FA for %s. Verifying password.", user.Name)

	// SIMPLIFIED DEMO RULE: Password must equal Username
	if req.Password != user.Name {
		log.Printf("DEBUG: Password mismatch for %s", user.Name)
		http.Error(w, "Incorrect Password", http.StatusUnauthorized)
		return
	}

	log.Printf("DEBUG: Password verified. Disabling 2FA for %s", user.Name)

	userMu.Lock()
	user.TOTPEnabled = false
	user.TOTPSecret = ""
	userMu.Unlock()

	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "2FA Disabled"})
}

func handleWithdrawalTOTP(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct{ Code string }
	json.NewDecoder(r.Body).Decode(&req)

	log.Printf("DEBUG: Processing Withdrawal for %s. Verifying Code: %s", user.Name, req.Code)

	if !user.TOTPEnabled {
		log.Printf("DEBUG: Failed. 2FA not set up for %s", user.Name)
		http.Error(w, "TOTP not set up", http.StatusBadRequest)
		return
	}

	valid := totp.Validate(req.Code, user.TOTPSecret)

	if valid {
		log.Printf("DEBUG: Withdrawal APPROVED for %s", user.Name)
		json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Withdrawal Processed via Code!"})
	} else {
		log.Printf("DEBUG: Withdrawal DENIED for %s. Invalid Code.", user.Name)
		http.Error(w, "Invalid Code", http.StatusUnauthorized)
	}
}

// --- 5. HELPERS ---
func getUser(r *http.Request) *User {
	c, err := r.Cookie("session_user")
	if err != nil {
		return nil
	}
	userMu.RLock()
	defer userMu.RUnlock()
	return users[c.Value]
}
