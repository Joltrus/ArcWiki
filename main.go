/*
 *   Copyright (c) 2024 Edward Stock
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package main

import (
	"encoding/json"
	"fmt"
	"html/template"

	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ArcWiki/ArcWiki/db"
	"github.com/ArcWiki/ArcWiki/validation"
	"github.com/houseme/mobiledetect"
	log "github.com/sirupsen/logrus"

	_ "github.com/mattn/go-sqlite3"
)

const Desktop = "desktop"
const Mobile = "mobile"

// Allowed route segments
var allowedPaths = []string{
	"search", "results", "admin", "add", "addpage", "edit", "delete",
	"savecat", "save", "title", "login", "loginPost", "logout", "Category", "Special",
}

// validPath matches the top-level route and an optional parameter segment
var validPath = regexp.MustCompile("^/(" + strings.Join(allowedPaths, "|") + `)(?:/([^/?#]+))?$`)

func viewHandler(w http.ResponseWriter, r *http.Request, title string, userAgent string) {
	path := r.URL.Path
	category := ""

	if strings.HasPrefix(path, "/title/") {
		category = strings.TrimPrefix(path, "/title/")
	} else {
		category = title
	}

	log.WithFields(log.Fields{
		"path":     validation.SanitizeForLog(path),
		"title":    validation.SanitizeForLog(title),
		"category": validation.SanitizeForLog(category),
	}).Debug("ViewHandler called")

	switch {

	case category == "":
		log.Info("No title/category given. Falling back to Main_Page.")
		renderOrRedirect(w, r, "Main_Page", userAgent)

	case strings.HasPrefix(category, "Help:"):
		handleHelpPage(w, r, category, userAgent)

	case strings.HasPrefix(category, "Special:Random"):
		handleRandomPage(w, r)

	case strings.HasPrefix(category, "Special:"):
		handleSpecialPage(w, r, category, userAgent)

	case strings.Contains(category, ":"):
		handleCategoryPage(w, r, title, category, userAgent)

	default:
		renderOrRedirect(w, r, title, userAgent)
	}
}

func handleHelpPage(w http.ResponseWriter, r *http.Request, category, userAgent string) {
	specialPageName := strings.TrimSpace(strings.TrimPrefix(category, "Help:"))
	p, err := loadPage("Help-"+specialPageName, userAgent)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"page":  validation.SanitizeForLog(specialPageName),
		}).Error("Help page not found")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	renderTemplate(w, "title", p)
}
func handleRandomPage(w http.ResponseWriter, r *http.Request) {
	db, err := db.LoadDatabase()
	if err != nil {
		log.WithError(err).Error("Failed to load DB for random page")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	defer db.Close()

	var title string
	if err := db.QueryRow("SELECT title FROM Pages ORDER BY RANDOM() LIMIT 1").Scan(&title); err != nil {
		log.Warn("No pages found for random redirect")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/title/"+title, http.StatusFound)
}
func handleSpecialPage(w http.ResponseWriter, r *http.Request, category, userAgent string) {
	specialPageName := strings.TrimSpace(strings.TrimPrefix(category, "Special:"))
	p, err := loadPageSpecial(specialPageName, userAgent)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"page":  validation.SanitizeForLog(specialPageName),
		}).Error("Special page error")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	renderTemplate(w, "title", p)
}
func handleCategoryPage(w http.ResponseWriter, r *http.Request, title, category, userAgent string) {
	parts := strings.SplitN(category, ":", 2)
	if len(parts) < 2 {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	categoryName := strings.TrimSpace(parts[1])
	p, err := loadPageCategory(categoryName, userAgent)

	if err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"category": validation.SanitizeForLog(categoryName),
		}).Error("Failed to load category")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	renderTemplate(w, "title", p)
}
func renderOrRedirect(w http.ResponseWriter, r *http.Request, title, userAgent string) {
	p, err := loadPage(title, userAgent)
	if err != nil {
		log.WithField("title", validation.SanitizeForLog(title)).Error("Falling back to Main_Page")
		http.Redirect(w, r, "/title/Main_Page", http.StatusFound)
		return
	}
	renderTemplate(w, "title", p)
}

// Edit Handler with a switch for editing Categories
func editHandler(w http.ResponseWriter, r *http.Request, title string, userAgent string) {
	updated_at := "Not Available"
	log.WithField("title", validation.SanitizeForLog(title)).Debug("Edit handler called")
	size := ""
	if userAgent == Desktop {
		size = "<div class=\"col-11 d-none d-sm-block\">"
	} else {
		size = "<div class=\"col-12 d-block d-sm-none\">"
	}
	category := r.URL.Path[len("/title/"):]

	switch {
	case strings.Contains(category, ":"):
		categoryParts := strings.Split(category, ":")
		categoryName := strings.TrimSpace(categoryParts[1])
		log.WithField("category", validation.SanitizeForLog(categoryName)).Debug("Category edit")

		session, _ := store.Get(r, "cookie-name")
		auth, ok := session.Values["authenticated"].(bool)

		if !ok || !auth {
			http.Redirect(w, r, "/error", http.StatusFound)
			return
		} else {

			ep, err := loadCategoryNoHtml(categoryName, userAgent)

			if err != nil {
				ep = &EditPage{CTitle: categoryName, Title: categoryName, Size: template.HTML(size), UpdatedDate: updated_at}
			}
			renderEditPageTemplate(w, "editCategory", ep)
		}
	default:

		// check our user is logged in
		session, _ := store.Get(r, "cookie-name")
		auth, ok := session.Values["authenticated"].(bool)

		if !ok || !auth {
			http.Redirect(w, r, "/error", http.StatusFound)
			return
		} else {

			ep, err := loadPageNoHtml(title, userAgent)
			if err != nil {
				safeMenu, _ := loadMenu()
				ep = &EditPage{
					NavTitle:    config.SiteTitle,
					ThemeColor:  template.HTML(arcWikiLogo()),
					CTitle:      removeUnderscores(title),
					Title:       title,
					Body:        template.HTML(""),
					Menu:        safeMenu,
					Size:        template.HTML(size),
					UpdatedDate: "Not yet created",
				}
			}

			renderEditPageTemplate(w, "edit", ep)
		}
	}
}

func saveCatHandler(w http.ResponseWriter, r *http.Request, title string, userAgent string) {
	body := r.FormValue("body")

	// Validate body
	validatedBody, err := validation.ValidateBody(body)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"title": validation.SanitizeForLog(title),
		}).Error("Invalid body during saveCatHandler")
		http.Error(w, "Invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}

	p := &Page{Title: title, Body: template.HTML(validatedBody)}
	err = p.saveCat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/title/Special:Categories", http.StatusFound)
}

// main.go

func makeHandler(fn func(http.ResponseWriter, *http.Request, string, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cleanPath := strings.TrimSuffix(r.URL.Path, "/")

		// Special case: root path ("/") → treat as Main_Page
		if cleanPath == "" {
			fn(w, r, "Main_Page", getUserAgent(r))
			return
		}

		m := validPath.FindStringSubmatch(cleanPath)
		if m == nil {
			log.WithField("path", validation.SanitizeForLog(r.URL.Path)).Error("Handler Error: path did not match validPath regex")
			http.NotFound(w, r)
			return
		}

		title := m[2]
		if title == "" && (m[1] == "admin" || m[1] == "search" || m[1] == "login") {
			title = m[1] // treat route as the title
		}
		fn(w, r, title, getUserAgent(r))

	}
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the resource type and title using strings.SplitN

	session, _ := store.Get(r, "cookie-name")
	auth, ok := session.Values["authenticated"].(bool)

	if !ok || !auth {
		http.Redirect(w, r, "/error", http.StatusFound)
		return
	} else {
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/delete/"), "/", 2)
		if len(parts) != 2 {
			http.Error(w, r, "Invalid URL format", http.StatusBadRequest)
			return
		}
		resourceType := parts[0]
		title := parts[1]

		// Handle deletion based on resource type
		if resourceType == "page" {
			// Handle deletion of a page
			p := &Page{Title: title}
			err := p.deletePage()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/admin/manage", http.StatusFound)
		} else if resourceType == "category" {
			// Handle deletion of a category
			cat := &Category{Title: title}
			err := cat.deleteCategory()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/admin/manage", http.StatusFound)
		} else {
			// Handle invalid resource type
			http.Redirect(w, r, "/error", http.StatusFound)
		}
	}
}

func addHandler(w http.ResponseWriter, r *http.Request) {
	// check our user is logged in
	session, _ := store.Get(r, "cookie-name")
	auth, ok := session.Values["authenticated"].(bool)

	if !ok || !auth {
		http.Redirect(w, r, "/error", http.StatusFound)
		return
	} else {
		detect := mobiledetect.New(r, nil)
		size := ""
		if detect.IsMobile() || detect.IsTablet() {
			size = "<div class=\"col-12 d-block d-sm-none\">"
		} else {
			size = "<div class=\"col-11 d-none d-sm-block\">"
		}

		title := ""
		safeMenu, err := loadMenu()
		if err != nil {
			log.Error("Error Loading Menu:", err)
		}
		ap := &AddPage{NavTitle: config.SiteTitle, ThemeColor: template.HTML(arcWikiLogo()), CTitle: "Add Page", Title: title, Menu: safeMenu, Size: template.HTML(size), UpdatedDate: ""}

		renderAddPageTemplate(w, "add", ap)
	}
}

// Error page needs to be used
func errorPage(w http.ResponseWriter, r *http.Request) {
	detect := mobiledetect.New(r, nil)
	userAgent := ""
	if detect.IsMobile() || detect.IsTablet() {
		userAgent = Mobile
	} else {
		userAgent = Desktop
	}
	p, err := loadPageSpecial("specialPageName", userAgent)
	if err != nil {
		http.Error(w, "Error loading HTML file", http.StatusInternalServerError)
		return
	}
	renderTemplate(w, "errorPage", p)

}
func dbsql(stater string, args ...interface{}) error {
	db, err := db.LoadDatabase()
	if err != nil {
		log.Error("Error Loading Database:", err)

	}
	defer db.Close() // Ensure database closure

	stmt, err := db.Prepare(stater)
	if err != nil {
		log.Error("Database Error: ", err)
	}
	defer stmt.Close() // Close the prepared statement

	_, err = stmt.Exec(args...) // Execute the statement with provided arguments
	if err != nil {
		log.Error("Database Error: ", err)
	}

	return nil // Indicate successful execution
}

// moved here for ease
var templates = template.Must(template.ParseFiles(
	"templates/search.html",
	"templates/header.html",
	"templates/footer.html",
	"templates/navbar.html",
	"templates/edit.html",
	"templates/editCategory.html",
	"templates/title.html",
	"templates/login.html",
	"templates/add.html",
	"templates/errorPage.html",
))

func renderTemplate(w http.ResponseWriter, tmpl string, p *Page) {

	err := templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		log.Error("Error Occurred in renderTemplate: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
func renderEditPageTemplate(w http.ResponseWriter, tmpl string, ep *EditPage) {
	err := templates.ExecuteTemplate(w, tmpl+".html", ep)
	if err != nil {
		log.Error("Error Occurred in renderEditPageTemplate: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func renderAddPageTemplate(w http.ResponseWriter, tmpl string, ap *AddPage) {
	err := templates.ExecuteTemplate(w, tmpl+".html", ap)
	if err != nil {
		log.Error("Error Occurred in renderEditPageTemplate: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type Config struct {
	SiteTitle string     `json:"siteTitle"`
	TColor    string     `json:"TColor"`
	Menu      []MenuItem `json:"menu"`
}

type Admin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type MenuItem struct {
	Name string `json:"name"`
	Link string `json:"link"`
}

var config Config

func loadMenu() (template.HTML, error) {
	var links strings.Builder

	for _, menuItem := range config.Menu {
		links.WriteString(fmt.Sprintf("<li><a href=\"%s\">%s</a></li>\n", menuItem.Link, menuItem.Name))
	}

	return template.HTML(links.String()), nil
}

func main() {
	// Start log
	log.SetFormatter(&log.TextFormatter{
		DisableColors:   false,
		FullTimestamp:   true,
		TimestampFormat: "15:04:05",
	})
	log.SetLevel(log.InfoLevel)
	log.Info("Starting your instance of ArcWiki")

	// Ensure the main application schema is up
	db.DBSetup()

	// Initialize the auth database
	if err := InitAuthDB("arcWiki.db"); err != nil {
		log.Fatalf("Auth DB init error: %v", err)
	}

	// Seed a single admin on first run
	var userCount int
	if err := authDB.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
		log.Fatalf("Unable to check users table: %v", err)
	}
	if userCount == 0 {
		// Prefer Docker env variables, fall back to defaults
		adminUser := os.Getenv("USERNAME")
		adminPass := os.Getenv("PASSWORD")
		if adminUser == "" || adminPass == "" {
			log.Warn("No USERNAME/PASSWORD env vars found; defaulting to admin/admin")
			adminUser = "admin"
			adminPass = "admin"
		}
		if err := CreateUser(adminUser, adminPass, true); err != nil {
			log.Fatalf("Seeding admin user failed: %v", err)
		}
		log.Infof("Seeded admin user '%s' (admin)", adminUser)
	}

	// Load site configuration
	configBytes, err := os.ReadFile("config/config.json")
	if err != nil {
		log.Panic("Error reading config/config.json:", err)
	}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		log.Panic("Error parsing config:", err)
	}
	if os.Getenv("COLOR") != "" {
		config.TColor = os.Getenv("COLOR")
	}
	if os.Getenv("SITENAME") != "" {
		config.SiteTitle = os.Getenv("SITENAME")
	}

	// Background updater
	go func() {
		for {
			if err := updateSubCategoryLinks(); err != nil {
				log.Error("Error updating subcategories:", err)
			}
			time.Sleep(60 * time.Second)
		}
	}()

	// HTTP routes
	// Protect admin routes with requireLogin and handle /admin and /admin/*
	http.HandleFunc("/admin", requireLogin(func(w http.ResponseWriter, r *http.Request) {
		adminHandler(w, r, "", getUserAgent(r))
	}))

	http.HandleFunc("/admin/", requireLogin(func(w http.ResponseWriter, r *http.Request) {
		// Determine subpath after /admin/
		sub := strings.TrimPrefix(r.URL.Path, "/admin/")
		sub = strings.TrimSuffix(sub, "/")
		if sub == "" {
			// direct /admin/ → admin index
			adminHandler(w, r, "", getUserAgent(r))
			return
		}

		// /admin/manage or /admin/manage/... should map to admin page management
		if strings.HasPrefix(sub, "manage") || strings.HasPrefix(sub, "page") {
			adminHandler(w, r, "page", getUserAgent(r))
			return
		}

		// /admin/category or /admin/category/...
		if strings.HasPrefix(sub, "category") {
			adminHandler(w, r, "category", getUserAgent(r))
			return
		}

		// If first segment equals a known admin subpage, pass it as title
		parts := strings.SplitN(sub, "/", 2)
		adminHandler(w, r, parts[0], getUserAgent(r))
	}))

	http.HandleFunc("/", makeHandler(viewHandler))
	http.HandleFunc("/search", makeHandler(SearchHandler))
	http.HandleFunc("/query", QueryHandler)
	http.HandleFunc("/add", addHandler)
	http.HandleFunc("/addpage", addPage)
	http.HandleFunc("/delete/", deleteHandler)
	http.HandleFunc("/category/", addCat)
	http.HandleFunc("/savecat/", makeHandler(saveCatHandler))

	http.HandleFunc("/logout", makeHandler(logout))
	http.HandleFunc("/logout/", makeHandler(logout)) // handle trailing slash

	http.HandleFunc("/login", makeHandler(loginFormHandler))
	http.HandleFunc("/loginPost", makeHandler(loginHandler))
	http.HandleFunc("/title/", makeHandler(viewHandler))
	http.HandleFunc("/edit/", makeHandler(editHandler))
	http.HandleFunc("/save/", makeHandler(saveHandler))
	http.HandleFunc("/error", errorPage)

	// Static assets
	fs := http.FileServer(http.Dir("./assets"))
	http.Handle("/assets/", http.StripPrefix("/assets/", fs))

	log.Fatal(http.ListenAndServe(":8080", nil))
}
