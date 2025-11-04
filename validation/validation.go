/*
 *   Copyright (c) 2024 Edward Stock
 
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package validation

import (
	"errors"
	"html"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// MaxTitleLength defines the maximum length for page/category titles
	MaxTitleLength = 255
	// MaxBodyLength defines the maximum length for page body content
	MaxBodyLength = 1000000 // 1MB of text
	// MaxUsernameLength defines the maximum length for usernames
	MaxUsernameLength = 50
	// MaxPasswordLength defines the maximum length for passwords
	MaxPasswordLength = 128
	// MaxSearchQueryLength defines the maximum length for search queries
	MaxSearchQueryLength = 200
)

var (
	// ErrEmptyInput indicates that a required input is empty
	ErrEmptyInput = errors.New("input cannot be empty")
	// ErrTooLong indicates that input exceeds maximum length
	ErrTooLong = errors.New("input exceeds maximum length")
	// ErrInvalidFormat indicates that input has invalid format
	ErrInvalidFormat = errors.New("invalid input format")
	// ErrInvalidCharacters indicates that input contains invalid characters
	ErrInvalidCharacters = errors.New("input contains invalid characters")
)

// ValidateTitle validates and sanitizes page/category titles
func ValidateTitle(title string) (string, error) {
	// Trim whitespace
	title = strings.TrimSpace(title)

	// Check if empty
	if title == "" {
		return "", ErrEmptyInput
	}

	// Check length
	if utf8.RuneCountInString(title) > MaxTitleLength {
		return "", ErrTooLong
	}

	// Sanitize: remove control characters and normalize
	title = sanitizeString(title)

	// Validate: titles should not contain certain special characters
	if strings.ContainsAny(title, "\n\r\t<>\"'&;") {
		return "", ErrInvalidCharacters
	}

	return title, nil
}

// ValidateBody validates and sanitizes page body content
func ValidateBody(body string) (string, error) {
	// Body can be empty for new pages
	body = strings.TrimSpace(body)

	// Check length
	if utf8.RuneCountInString(body) > MaxBodyLength {
		return "", ErrTooLong
	}

	// Sanitize: remove control characters except newlines and tabs
	body = sanitizeBodyContent(body)

	return body, nil
}

// ValidateUsername validates and sanitizes usernames
func ValidateUsername(username string) (string, error) {
	// Trim whitespace
	username = strings.TrimSpace(username)

	// Check if empty
	if username == "" {
		return "", ErrEmptyInput
	}

	// Check length
	if len(username) > MaxUsernameLength {
		return "", ErrTooLong
	}

	// Usernames should only contain alphanumeric, underscore, hyphen
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username) {
		return "", ErrInvalidCharacters
	}

	return username, nil
}

// ValidatePassword validates password
func ValidatePassword(password string) error {
	// Password should not be empty
	if password == "" {
		return ErrEmptyInput
	}

	// Check length
	if len(password) > MaxPasswordLength {
		return ErrTooLong
	}

	// Password should have minimum length of 3 for security
	if len(password) < 3 {
		return ErrInvalidFormat
	}

	return nil
}

// ValidateSearchQuery validates and sanitizes search queries
func ValidateSearchQuery(query string) (string, error) {
	// Trim whitespace
	query = strings.TrimSpace(query)

	// Empty search is allowed (redirects to search page)
	if query == "" {
		return "", nil
	}

	// Check length
	if utf8.RuneCountInString(query) > MaxSearchQueryLength {
		return "", ErrTooLong
	}

	// Sanitize: remove control characters
	query = sanitizeString(query)

	return query, nil
}

// ValidateCategoryName validates and sanitizes category names
func ValidateCategoryName(name string) (string, error) {
	// Category names follow same rules as titles
	return ValidateTitle(name)
}

// SanitizeForLog sanitizes strings for logging to prevent log injection
func SanitizeForLog(s string) string {
	// Remove newlines and carriage returns to prevent log injection
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	
	// Truncate long strings for logs
	const maxLogLength = 200
	if utf8.RuneCountInString(s) > maxLogLength {
		runes := []rune(s)
		s = string(runes[:maxLogLength]) + "..."
	}
	
	return s
}

// SanitizeHTML escapes HTML special characters to prevent XSS
func SanitizeHTML(s string) string {
	return html.EscapeString(s)
}

// sanitizeString removes control characters except space
func sanitizeString(s string) string {
	var result strings.Builder
	for _, r := range s {
		// Keep printable characters and space
		if (r >= 32 && r != 127) || r == '\t' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// sanitizeBodyContent removes dangerous control characters but keeps newlines and tabs
func sanitizeBodyContent(s string) string {
	var result strings.Builder
	for _, r := range s {
		// Keep printable characters, newlines, tabs
		if (r >= 32 && r != 127) || r == '\n' || r == '\r' || r == '\t' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// ValidatePathParameter validates path parameters from URLs
func ValidatePathParameter(param string) (string, error) {
	// Trim whitespace
	param = strings.TrimSpace(param)

	// Check if empty
	if param == "" {
		return "", ErrEmptyInput
	}

	// Check length
	if utf8.RuneCountInString(param) > MaxTitleLength {
		return "", ErrTooLong
	}

	// Path parameters should not contain path traversal sequences
	if strings.Contains(param, "..") || strings.Contains(param, "./") || strings.Contains(param, "\\") {
		return "", ErrInvalidCharacters
	}

	return param, nil
}
