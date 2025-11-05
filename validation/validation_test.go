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
	"strings"
	"testing"
)

func TestValidateTitle(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errType   error
		wantValue string
	}{
		{"valid title", "Test Page", false, nil, "Test Page"},
		{"title with spaces", "  Test Page  ", false, nil, "Test Page"},
		{"empty title", "", true, ErrEmptyInput, ""},
		{"title with newline gets sanitized", "Test\nPage", false, nil, "TestPage"}, // newline gets removed by sanitization
		{"title with HTML", "Test<script>", true, ErrInvalidCharacters, ""},
		{"title with quotes", "Test\"Page", true, ErrInvalidCharacters, ""},
		{"very long title", strings.Repeat("a", MaxTitleLength+1), true, ErrTooLong, ""},
		{"valid long title", strings.Repeat("a", MaxTitleLength), false, nil, strings.Repeat("a", MaxTitleLength)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateTitle(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTitle() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != tt.errType {
				t.Errorf("ValidateTitle() error type = %v, want %v", err, tt.errType)
			}
			if !tt.wantErr && got != tt.wantValue {
				t.Errorf("ValidateTitle() = %v, want %v", got, tt.wantValue)
			}
		})
	}
}

func TestValidateBody(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errType   error
		wantValue string
	}{
		{"valid body", "Test content", false, nil, "Test content"},
		{"empty body", "", false, nil, ""},
		{"body with newlines", "Test\nContent\n", false, nil, "Test\nContent"},
		{"very long body", strings.Repeat("a", MaxBodyLength+1), true, ErrTooLong, ""},
		{"valid long body", strings.Repeat("a", 1000), false, nil, strings.Repeat("a", 1000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateBody(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateBody() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != tt.errType {
				t.Errorf("ValidateBody() error type = %v, want %v", err, tt.errType)
			}
			if !tt.wantErr && got != tt.wantValue {
				t.Errorf("ValidateBody() = %v, want %v", got, tt.wantValue)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errType   error
		wantValue string
	}{
		{"valid username", "admin", false, nil, "admin"},
		{"username with underscore", "test_user", false, nil, "test_user"},
		{"username with hyphen", "test-user", false, nil, "test-user"},
		{"username with numbers", "user123", false, nil, "user123"},
		{"empty username", "", true, ErrEmptyInput, ""},
		{"username with space", "test user", true, ErrInvalidCharacters, ""},
		{"username with special chars", "test@user", true, ErrInvalidCharacters, ""},
		{"too long username", strings.Repeat("a", MaxUsernameLength+1), true, ErrTooLong, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateUsername(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUsername() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != tt.errType {
				t.Errorf("ValidateUsername() error type = %v, want %v", err, tt.errType)
			}
			if !tt.wantErr && got != tt.wantValue {
				t.Errorf("ValidateUsername() = %v, want %v", got, tt.wantValue)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errType error
	}{
		{"valid password", "password123", false, nil},
		{"minimum length password", "abc", false, nil},
		{"empty password", "", true, ErrEmptyInput},
		{"too short password", "ab", true, ErrInvalidFormat},
		{"too long password", strings.Repeat("a", MaxPasswordLength+1), true, ErrTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != tt.errType {
				t.Errorf("ValidatePassword() error type = %v, want %v", err, tt.errType)
			}
		})
	}
}

func TestValidateSearchQuery(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errType   error
		wantValue string
	}{
		{"valid query", "test search", false, nil, "test search"},
		{"empty query", "", false, nil, ""},
		{"query with spaces", "  test  ", false, nil, "test"},
		{"too long query", strings.Repeat("a", MaxSearchQueryLength+1), true, ErrTooLong, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateSearchQuery(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSearchQuery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != tt.errType {
				t.Errorf("ValidateSearchQuery() error type = %v, want %v", err, tt.errType)
			}
			if !tt.wantErr && got != tt.wantValue {
				t.Errorf("ValidateSearchQuery() = %v, want %v", got, tt.wantValue)
			}
		})
	}
}

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no special chars", "test", "test"},
		{"with newline", "test\nlog", "test\\nlog"},
		{"with carriage return", "test\rlog", "test\\rlog"},
		{"with both", "test\n\rlog", "test\\n\\rlog"},
		{"long string", strings.Repeat("a", 250), strings.Repeat("a", 200) + "..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeForLog(tt.input); got != tt.want {
				t.Errorf("SanitizeForLog() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeHTML(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no special chars", "test", "test"},
		{"with HTML tags", "<script>alert('xss')</script>", "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"},
		{"with ampersand", "test & more", "test &amp; more"},
		{"with quotes", `test "quoted"`, "test &#34;quoted&#34;"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeHTML(tt.input); got != tt.want {
				t.Errorf("SanitizeHTML() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidatePathParameter(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errType   error
		wantValue string
	}{
		{"valid path", "test", false, nil, "test"},
		{"empty path", "", true, ErrEmptyInput, ""},
		{"path traversal ..", "../../etc", true, ErrInvalidCharacters, ""},
		{"path traversal ./", "./test", true, ErrInvalidCharacters, ""},
		{"path with backslash", "test\\file", true, ErrInvalidCharacters, ""},
		{"too long path", strings.Repeat("a", MaxTitleLength+1), true, ErrTooLong, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidatePathParameter(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePathParameter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != tt.errType {
				t.Errorf("ValidatePathParameter() error type = %v, want %v", err, tt.errType)
			}
			if !tt.wantErr && got != tt.wantValue {
				t.Errorf("ValidatePathParameter() = %v, want %v", got, tt.wantValue)
			}
		})
	}
}
