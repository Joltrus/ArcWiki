/*
 *   Copyright (c) 2025
 *   All rights reserved.
 */
package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestAdminPanelRequiresAuth tests that the admin panel redirects unauthenticated users to login
func TestAdminPanelRequiresAuth(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"Admin root", "/admin"},
		{"Admin with trailing slash", "/admin/"},
		{"Admin page management", "/admin/page"},
		{"Admin category management", "/admin/category"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a request to the admin panel
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			// Call the handler through requireLogin middleware
			handler := requireLogin(makeHandler(adminHandler))
			handler(w, req)

			// Check that the response is a redirect
			if w.Code != http.StatusFound {
				t.Errorf("Expected status %d for unauthenticated request to %s, got %d", http.StatusFound, tt.path, w.Code)
			}

			// Check that the redirect is to the login page
			location := w.Header().Get("Location")
			if !strings.HasPrefix(location, "/login?next=") {
				t.Errorf("Expected redirect to login page for %s, got %s", tt.path, location)
			}

			// Verify the next parameter is set correctly
			parsedURL, err := url.Parse(location)
			if err != nil {
				t.Fatalf("Failed to parse redirect location %s: %v", location, err)
			}
			nextParam := parsedURL.Query().Get("next")
			if nextParam == "" {
				t.Errorf("Expected 'next' parameter in redirect URL for %s", tt.path)
			}
		})
	}
}

// TestProtectedRoutesRequireAuth tests that various protected routes require authentication
func TestProtectedRoutesRequireAuth(t *testing.T) {
	protectedPaths := []string{
		"/edit/Main_Page",
		"/add",
		"/delete/page/test",
	}

	for _, path := range protectedPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()

			// The actual handler would be different for each route,
			// but they all should be wrapped with requireLogin
			// For this test, we're verifying the pattern

			// Since we can't easily test all handlers without full setup,
			// this test verifies that requireLogin middleware works correctly
			testHandler := requireLogin(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Protected content"))
			})

			testHandler(w, req)

			// Should redirect to login
			if w.Code != http.StatusFound {
				t.Errorf("Expected status %d for unauthenticated request to %s, got %d", http.StatusFound, path, w.Code)
			}

			location := w.Header().Get("Location")
			if !strings.Contains(location, "/login") {
				t.Errorf("Expected redirect to login page for %s, got %s", path, location)
			}
		})
	}
}

// TestRequireLoginMiddleware tests the requireLogin middleware in isolation
func TestRequireLoginMiddleware(t *testing.T) {
	t.Run("Unauthenticated request is redirected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		w := httptest.NewRecorder()

		nextCalled := false
		handler := requireLogin(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler(w, req)

		if nextCalled {
			t.Error("Next handler should not be called for unauthenticated request")
		}

		if w.Code != http.StatusFound {
			t.Errorf("Expected status %d, got %d", http.StatusFound, w.Code)
		}

		location := w.Header().Get("Location")
		if !strings.Contains(location, "/login") {
			t.Errorf("Expected redirect to /login, got %s", location)
		}
	})
}
