/*
 *   Copyright (c) 2025
 *   All rights reserved.
 */
package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/ArcWiki/ArcWiki/validation"
	"github.com/gorilla/sessions"
	"github.com/houseme/mobiledetect"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

const envFile = ".env"

// session store
var store *sessions.CookieStore

// database handle for auth
var authDB *sql.DB

func init() {
	// Ensure .env with SESSION_KEY
	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			log.Fatalf("auth: cannot generate session key: %v", err)
		}
		b64 := base64.StdEncoding.EncodeToString(raw)
		if err := ioutil.WriteFile(envFile, []byte("SESSION_KEY="+b64+"\n"), 0600); err != nil {
			log.Fatalf("auth: cannot write %s: %v", envFile, err)
		}
	}

	// Load SESSION_KEY
	_ = godotenv.Load(envFile)
	b64key := os.Getenv("SESSION_KEY")
	if b64key == "" {
		log.Fatal("auth: SESSION_KEY not set")
	}
	key, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil {
		log.Fatalf("auth: invalid SESSION_KEY: %v", err)
	}

	// Determine whether cookie should be marked Secure.
	// Default to false (so local dev on http works). Set SESSION_SECURE=true in production to enable Secure cookies.
	secureFlag := false
	if strings.ToLower(os.Getenv("SESSION_SECURE")) == "true" {
		secureFlag = true
	}

	// Initialize Gorilla session store
	store = sessions.NewCookieStore(key)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		Secure:   secureFlag,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// InitAuthDB simply opens the database and checks connectivity.
// All schema creation happens in db/database.go.
func InitAuthDB(path string) error {
	var err error
	authDB, err = sql.Open("sqlite3", path)
	if err != nil {
		return err
	}
	return authDB.Ping()
}
func requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "cookie-name")
		auth, ok := session.Values["authenticated"].(bool)

		if !ok || !auth {
			// Preserve the requested URL so we can return after login.
			escaped := url.QueryEscape(r.URL.RequestURI())
			http.Redirect(w, r, "/login?next="+escaped, http.StatusFound)
			return
		}

		next(w, r)
	}
}

// getUserAgent helper
func getUserAgent(r *http.Request) string {
	detect := mobiledetect.New(r, nil)
	if detect.IsMobile() || detect.IsTablet() {
		return Mobile
	}
	return Desktop
}

// CreateUser inserts a bcrypt-hashed user; no-op if username exists.
func CreateUser(username, plainPassword string, isAdmin bool) error {
	// Validate username
	validatedUsername, err := validation.ValidateUsername(username)
	if err != nil {
		log.WithField("error", err).Warn("Invalid username during user creation")
		return err
	}

	// Validate password
	if err := validation.ValidatePassword(plainPassword); err != nil {
		log.WithField("error", err).Warn("Invalid password during user creation")
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = authDB.Exec(
		"INSERT INTO users(username,password,is_admin) VALUES(?,?,?)",
		validatedUsername, string(hash), boolToInt(isAdmin),
	)
	if err != nil && !isUniqueConstraintError(err) {
		return err
	}
	return nil
}

// Authenticate verifies credentials and returns (ok, isAdmin, error).
func Authenticate(username, plainPassword string) (bool, bool, error) {
	// Validate username
	validatedUsername, err := validation.ValidateUsername(username)
	if err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"username": validation.SanitizeForLog(username),
		}).Warn("Invalid username during authentication")
		return false, false, nil
	}

	// Validate password
	if err := validation.ValidatePassword(plainPassword); err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"username": validation.SanitizeForLog(validatedUsername),
		}).Warn("Invalid password during authentication")
		return false, false, nil
	}

	var storedHash string
	var isAdminInt int
	err = authDB.QueryRow(
		"SELECT password,is_admin FROM users WHERE username = ?", validatedUsername,
	).Scan(&storedHash, &isAdminInt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, false, nil
		}
		return false, false, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(plainPassword)); err != nil {
		return false, false, nil
	}
	return true, isAdminInt == 1, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isUniqueConstraintError(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

/* ---------------- HTTP Handlers ---------------- */

func loginFormHandler(w http.ResponseWriter, r *http.Request, title string, userAgent string) {
	size := `<div class="col-11 d-none d-sm-block">`
	if userAgent == Mobile {
		size = `<div class="col-12 d-block d-sm-none">`
	}

	// Preserve any "next" query param so the login form can include it.
	nextParam := r.URL.Query().Get("next")
	nextInput := ""
	if nextParam != "" {
		// Keep the raw value in the hidden input; it's validated on POST.
		escaped := template.HTMLEscapeString(nextParam)
		nextInput = fmt.Sprintf(`<input type="hidden" name="next" value="%s">`, escaped)
	}

	bodyMark := fmt.Sprintf(`<form action="/loginPost" method="post">
        <div class="form-group">
          <label for="username">Username:</label>
          <input class="form-control" type="text" id="username" name="username">
        </div>
        <div class="form-group">
          <label for="password">Password:</label>
          <input class="form-control" type="password" id="password" name="password">
        </div>
        %s
        <button class="bg-dark hover:bg-gray-100 text-white font-semibold py-2 px-4 border border-gray-400 rounded shadow" type="submit">Login</button>
    </form>`, nextInput)

	parsedText := addHeadingIDs(bodyMark)
	happyhtml := createHeadingList(parsedText)
	categoryLink := findAllCategoryLinks(happyhtml)
	noLinks := removeCategoryLinks(happyhtml)
	perfecthtml := parseWikiText(noLinks)
	internalLinks := convertLinksToAnchors(perfecthtml)
	safeBodyHTML := template.HTML(internalLinks)

	safeMenu, err := loadMenu()
	if err != nil {
		log.Error("error loading menu")
	}

	p := Page{
		NavTitle:     config.SiteTitle,
		ThemeColor:   template.HTML(arcWikiLogo()),
		CTitle:       removeUnderscores(title),
		Title:        "login",
		Body:         safeBodyHTML,
		Size:         template.HTML(size),
		Menu:         safeMenu,
		CategoryLink: categoryLink,
	}

	renderTemplate(w, "login", &p)
}

func logout(w http.ResponseWriter, r *http.Request, title string, userAgent string) {
	session, _ := store.Get(r, "cookie-name")
	session.Values["authenticated"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func loginHandler(w http.ResponseWriter, r *http.Request, title string, userAgent string) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	user := r.FormValue("username")
	pass := r.FormValue("password")

	ok, isAdmin, err := Authenticate(user, pass)
	if err != nil {
		log.Errorf("auth error: %v", err)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}
	if !ok {
		log.WithField("username", validation.SanitizeForLog(user)).Warn("Failed login attempt")
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	session, _ := store.Get(r, "cookie-name")
	session.Values["authenticated"] = true
	session.Values["is_admin"] = isAdmin
	if err := session.Save(r, w); err != nil {
		log.Errorf("session save error: %v", err)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	log.Infof("Logged in: %s (admin=%v)", validation.SanitizeForLog(user), isAdmin)

	// Respect next param if provided, but validate it to avoid open redirects.
	next := r.FormValue("next")
	if next == "" {
		next = "/admin"
	} else {
		// Basic validation: must be an internal path (start with a single '/'), and not contain protocol.
		if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, "://") {
			log.Warnf("Invalid next parameter after login: %s", next)
			next = "/admin"
		}
	}

	http.Redirect(w, r, next, http.StatusSeeOther)
}