package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// Global variables to store credentials
var (
	clientID     string
	clientSecret string
	redirectURL  string
	tenant       string
	config       oauth2.Config
)

// ReadConfig reads key-value pairs from config.txt file and returns a map
/* Example config.txt
client_id=sdffsdf
client_secret=sdfsdf
redirect_url=http://localhost:8080/callback
tenant=sdfsdfsd
*/
func ReadConfig(filename string) (map[string]string, error) {
	config := make(map[string]string)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Ignore empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid config line: %s", line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		config[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Validate required fields
	requiredKeys := []string{"client_id", "client_secret", "redirect_url", "tenant"}
	for _, key := range requiredKeys {
		if config[key] == "" {
			return nil, fmt.Errorf("missing required config: %s", key)
		}
	}

	return config, nil
}

func main() {
	// Load config from file
	configData, err := ReadConfig("config.txt")
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	// Assign values to global variables
	var exists bool
	if clientID, exists = configData["client_id"]; !exists || clientID == "" {
		log.Fatal("client_id not found in config file")
	}

	if clientSecret, exists = configData["client_secret"]; !exists || clientSecret == "" {
		log.Fatal("client_secret not found in config file")
	}

	if redirectURL, exists = configData["redirect_url"]; !exists || redirectURL == "" {
		log.Fatal("redirect_url not found in config file")
	}

	if tenant, exists = configData["tenant"]; !exists || tenant == "" {
		log.Fatal("tenant not found in config file")
	}

	// Initialize OAuth2 config with updated values
	config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     microsoft.AzureADEndpoint(tenant),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

	log.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	// Display a login link
	fmt.Fprintf(w, "<html><body><a href='/login'>Login with Entra ID</a></body></html>")
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Redirect the user to Entra ID's login page
	authCodeURL := config.AuthCodeURL("state")
	http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Get the OAuth2 token from the callback request
	ctx := context.Background()
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code in the request", http.StatusBadRequest)
		return
	}

	// Exchange the authorization code for a token
	token, err := config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set up an OpenID Connect verifier
	provider, err := oidc.NewProvider(ctx, fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenant))
	if err != nil {
		http.Error(w, "Failed to get provider: "+err.Error(), http.StatusInternalServerError)
		return
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
		// Skip issuer check to allow for tenant-specific issuers
		SkipIssuerCheck: true})

	// Verify the ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in token", http.StatusInternalServerError)
		return
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract user info from the ID token
	var claims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse ID token claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	userEmail := claims.Email
	if userEmail == "" {
		userEmail = claims.PreferredUsername
	}

	fmt.Fprintf(w, "Hello, %s!", userEmail)
}
