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
	dbh, err := db.LoadDatabase()
	if err != nil {
		log.WithError(err).Error("Failed to load DB for random page")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	defer dbh.Close()

	var title string
	if err := dbh.QueryRow("SELECT title FROM Pages ORDER BY RANDOM() LIMIT 1").Scan(&title); err != nil {
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
dbh, err := db.LoadDatabase()
if err != nil {
	log.Error("Error Loading Database:", err)

}
defer dbh.Close() // Ensure database closure

stmt, err := dbh.Prepare(stater)
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

The file content is truncated here in the read response. If you want the rest of main.go I can fetch it.
