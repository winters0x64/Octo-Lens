package web

import (
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	oauthStateCookie = "oauth_state"
	allowedDomain    = "scapia.cards"
)

func newOAuthConfig(clientID, clientSecret, redirectBase string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectBase + "/auth/google/callback",
		Scopes: []string{
			"openid",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
}

func (s *Server) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := generateToken(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	isHTTPS := r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookie,
		Value:    state,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   isHTTPS,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, s.oauthCfg.AuthCodeURL(state, oauth2.AccessTypeOnline), http.StatusFound)
}

func (s *Server) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify CSRF state
	stateCookie, err := r.Cookie(oauthStateCookie)
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid OAuth state", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oauthStateCookie, MaxAge: -1, Path: "/"})

	// Exchange code for token
	token, err := s.oauthCfg.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Fetch user info from Google
	client := s.oauthCfg.Client(r.Context(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		HD            string `json:"hd"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "failed to parse user info", http.StatusInternalServerError)
		return
	}

	// Enforce domain restriction — only @scapia.cards
	if userInfo.HD != allowedDomain || !userInfo.VerifiedEmail {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `<!doctype html><html><body style="font-family:sans-serif;padding:40px">
<h2>Access denied</h2><p>Only <strong>@%s</strong> accounts are allowed.<br>
Signed in as: <code>%s</code></p>
<p><a href="/login">← Back to login</a></p></body></html>`,
			allowedDomain, userInfo.Email)
		return
	}

	// Create session
	sessionID, err := s.sessions.create()
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	isHTTPS := r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})
	http.Redirect(w, r, "/", http.StatusFound)
}
