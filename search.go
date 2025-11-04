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

package main

import (
	"database/sql"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/ArcWiki/ArcWiki/db"
	"github.com/ArcWiki/ArcWiki/validation"
	"github.com/gomarkdown/markdown"
	"github.com/houseme/mobiledetect"
	log "github.com/sirupsen/logrus"
)

type Result struct {
	Title string `sql:"title"`
	Body  string `sql:"body"`
}

type SearchData struct {
	ThemeColor template.HTML
	NavTitle   string
	Menu       template.HTML
	CTitle     string
	Results    []Result
	Size       template.HTML
}

func QueryHandler(w http.ResponseWriter, r *http.Request) {
	query := strings.ToLower(strings.TrimSpace(r.FormValue("query")))

	// Validate search query
	validatedQuery, err := validation.ValidateSearchQuery(query)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"query": validation.SanitizeForLog(query),
		}).Warn("Invalid search query")
		http.Error(w, "Invalid search query: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.WithField("query", validation.SanitizeForLog(validatedQuery)).Info("Search Query")

	if validatedQuery == "" {
		http.Redirect(w, r, "/search", http.StatusFound)
		return
	}

	dbConn, err := db.LoadDatabase()
	if err != nil {
		log.Error("Database Error:", err)
		http.Error(w, "Internal DB error", http.StatusInternalServerError)
		return
	}
	defer dbConn.Close()

	// Normalize query input: allow underscores, spaces, and lowercase matching
	likeQuery := "%" + strings.ReplaceAll(validatedQuery, " ", "_") + "%"
	altLikeQuery := "%" + strings.ReplaceAll(validatedQuery, "_", " ") + "%"

	stmt, err := dbConn.Prepare(`
		SELECT title, body 
		FROM Pages 
		WHERE LOWER(title) LIKE LOWER(?) 
		OR LOWER(title) LIKE LOWER(?)
		OR LOWER(REPLACE(title, '_', ' ')) LIKE LOWER(?)
	`)
	if err != nil {
		log.Error("Failed to prepare query:", err)
		http.Error(w, "Search error", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	rows, err := stmt.Query(likeQuery, altLikeQuery, "%"+validatedQuery+"%")
	if err != nil {
		log.Error("Failed to run search query:", err)
		http.Error(w, "Search execution error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	detect := mobiledetect.New(r, nil)
	userAgent := Mobile
	if !detect.IsMobile() && !detect.IsTablet() {
		userAgent = Desktop
	}

	size := ""
	if userAgent == Desktop {
		size = "<div class=\"col-11 d-none d-sm-block\">"
	} else {
		size = "<div class=\"col-12 d-block d-sm-none\">"
	}

	safeMenu, err := loadMenu()
	if err != nil {
		log.Error("Error loading menu:", err)
	}

	searchResults := SearchData{
		ThemeColor: template.HTML(arcWikiLogo()),
		Size:       template.HTML(size),
		Menu:       safeMenu,
		NavTitle:   config.SiteTitle,
		CTitle:     "Search Results",
	}

	for rows.Next() {
		var result Result
		if err := rows.Scan(&result.Title, &result.Body); err != nil {
			log.Error("Row scan error:", err)
			continue
		}
		words := strings.Fields(result.Body)
		if len(words) > 7 {
			result.Body = strings.Join(words[:7], " ") + "..."
		} else {
			result.Body = strings.Join(words, " ")
		}
		searchResults.Results = append(searchResults.Results, result)
	}

	tmpls := template.New("")
	tmpls, err = tmpls.ParseFiles(
		"templates/results.html",
		"templates/navbar.html",
		"templates/header.html",
		"templates/footer.html",
	)
	if err != nil {
		log.Error("Template parsing failed:", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	if err := tmpls.ExecuteTemplate(w, "results.html", searchResults); err != nil {
		log.Error("Template execution failed:", err)
		http.Error(w, "Template rendering error", http.StatusInternalServerError)
	}
}

func SearchHandler(w http.ResponseWriter, r *http.Request, title string, userAgent string) {
	//category := r.URL.Path[len("/title/"):]
	if len(r.URL.Path) >= len("/title/") && r.URL.Path[:len("/title/")] == "/title/" {
		// Path starts with "/title/" and has enough characters for slicing
		//category := r.URL.Path[len("/title/"):]

		// Process the extracted category

		switch {

		default:
			log.Info("No category specified, defaulting to normal view")

			// Load the page for standard title viewing
			p, err := LoadNothing(title, userAgent)
			if err != nil {
				log.Error("viewHandler: Something weird happened:", err)

				http.Redirect(w, r, "/title/Main_Page", http.StatusFound)
				return
			}

			renderTemplate(w, "search", p)

		}
	} else {

		// Load the page for standard title viewing
		p, err := LoadNothing("Main_Page", userAgent)
		if err != nil {
			log.Error("Viewer handler something odd happened:", err)
			//http.Redirect(w, r, "/title/Main_Page", http.StatusFound)
			return
		}
		renderTemplate(w, "search", p)
	}

}
func LoadNothing(title string, userAgent string) (*Page, error) {

	safeMenu, err := loadMenu()
	if err != nil {
		log.Error("Error Loading Menu:", err)
	}
	size := ""
	if userAgent == Desktop {
		size = "<div class=\"col-11 d-none d-sm-block\">"
	} else {
		size = "<div class=\"col-12 d-block d-sm-none\">"
	}
	db, err := db.LoadDatabase()
	if err != nil {
		log.Error("Error Loading Database:", err)

	}

	stmt, err := db.Prepare("SELECT title, body, updated_at FROM Pages WHERE title = ?")
	if err != nil {
		return nil, err
	}

	row := stmt.QueryRow(title)

	defer db.Close()   // Close the database connection
	defer stmt.Close() // Close the prepared statement

	var body string
	var updated_at time.Time
	err = row.Scan(&title, &body, &updated_at)
	bodyMark := markdown.ToHTML([]byte(body), nil, nil)
	parsedText := addHeadingIDs(string(bodyMark))
	happyhtml := createHeadingList(parsedText)
	//This grabs all Category links
	categoryLink := findAllCategoryLinks(happyhtml)
	//noLinks := removeCategoryLinks(happyhtml)
	//fmt.Println(noLinks)
	///perfecthtml := parseWikiText(noLinks)

	//internalLinks := convertLinksToAnchors(perfecthtml)
	//safeBodyHTML := template.HTML(internalLinks)
	footer := "This page was last modified on " + formatDateTime(updated_at)

	//need to double check this as I'm not certain why this is
	if err == nil { // Page found in database
		// ... (existing code for markdown parsing and HTML generation)
		return &Page{NavTitle: config.SiteTitle, ThemeColor: template.HTML(arcWikiLogo()), CTitle: "Search", Title: "title", Body: "", Size: template.HTML(size), Menu: safeMenu, CategoryLink: categoryLink, UpdatedDate: footer}, nil
	} else if err != sql.ErrNoRows { // Handle other SQLite errors
		log.Error("Error Database Found No Rows:", err)
		return nil, err
	}

	return &Page{NavTitle: config.SiteTitle, ThemeColor: template.HTML(arcWikiLogo()), CTitle: "Search", Title: "title", Body: "", Size: template.HTML(size), Menu: safeMenu, UpdatedDate: "footer"}, nil
	//return nil, fmt.Errorf("File not found: %s.txt", title) // File not found in any folder
}
