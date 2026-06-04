package web

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SessionAuth returns middleware that enforces session-cookie auth on protected routes.
// Public paths (login page, auth endpoints, static assets, webhooks) are exempt.
func SessionAuth(sessions *sessionStore, requireAuth bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if !requireAuth {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// Paths that never require a session
			if path == "/login" ||
				path == "/health" ||
				strings.HasPrefix(path, "/auth/") ||
				strings.HasPrefix(path, "/css/") ||
				strings.HasPrefix(path, "/js/") ||
				path == "/webhooks/github" {
				next.ServeHTTP(w, r)
				return
			}

			cookie, err := r.Cookie(sessionCookieName)
			if err != nil || !sessions.valid(cookie.Value) {
				if strings.HasPrefix(path, "/api/") {
					w.Header().Set("Content-Type", "application/json")
					http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
				} else {
					http.Redirect(w, r, "/login", http.StatusFound)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders adds CSP, CORS, and other security headers.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' https://avatars.githubusercontent.com")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// CORS: deny all cross-origin requests
		origin := r.Header.Get("Origin")
		if origin != "" {
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimiter limits a specific path to one request per interval.
type RateLimiter struct {
	mu       sync.Mutex
	lastCall time.Time
	interval time.Duration
}

func NewRateLimiter(interval time.Duration) *RateLimiter {
	return &RateLimiter{interval: interval}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if time.Since(rl.lastCall) < rl.interval {
		return false
	}
	rl.lastCall = time.Now()
	return true
}

// RedactedLogger logs requests without query parameters or auth headers.
func RedactedLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(ww, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, ww.status, time.Since(start).Round(time.Millisecond))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
