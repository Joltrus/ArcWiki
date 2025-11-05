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
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ArcWiki/ArcWiki/db"
	"github.com/ArcWiki/ArcWiki/validation"
	log "github.com/sirupsen/logrus"
)

type Category struct {
	Title string
	Body  string
	//user_id int
	Size template.HTML
	Menu template.HTML
	ID   int
}

func (p *Category) deleteCategory() error {
	// Validate title
	validatedTitle, err := validation.ValidateCategoryName(p.Title)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"title": validation.SanitizeForLog(p.Title),
		}).Error("Invalid category name during deleteCategory")
		return err
	}

	db, err := db.LoadDatabase()

	if err != nil {

		log.Error("Database Error", err)

	}
	defer db.Close()

	stmt, err := db.Prepare("DELETE FROM Categories WHERE title = ?")
	if err != nil {
		log.Error("Database Error", err)
	}
	defer stmt.Close()

	result, err := stmt.Exec(validatedTitle)
	if err != nil {
		log.Error("Database Error", err)
	}

	rowsDeleted, err := result.RowsAffected()
	if err != nil {
		log.Error("Database Error", err)
	}

	if rowsDeleted > 0 {

		log.WithFields(log.Fields{
			"rows":  rowsDeleted,
			"title": validation.SanitizeForLog(validatedTitle),
		}).Info("Deleted category")
	} else {
		log.WithField("title", validation.SanitizeForLog(validatedTitle)).Info("No category found")
	}
	return nil
}
func (p *Page) saveCat() error {
	// Validate title
	validatedTitle, err := validation.ValidateCategoryName(p.Title)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"title": validation.SanitizeForLog(p.Title),
		}).Error("Invalid category name during saveCat")
		return err
	}

	// Validate body
	validatedBody, err := validation.ValidateBody(string(p.Body))
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"title": validation.SanitizeForLog(validatedTitle),
		}).Error("Invalid body during saveCat")
		return err
	}

	log.WithFields(log.Fields{
		"title": validation.SanitizeForLog(validatedTitle),
	}).Info("Saving category")

	err = dbsql("UPDATE Categories SET body = ? WHERE title = ?", validatedBody, validatedTitle)
	if err != nil {
		log.Error("Database Error", err)

	}

	return nil

}
func getCategoryIDByName(categoryName string) (int, error) {
	//new
	db, err := db.LoadDatabase()
	if err != nil {
		log.Error("Database Error", err)
		return 0, err
	}
	defer db.Close()

	stmt, err := db.Prepare("SELECT id FROM Categories WHERE title = ?")
	if err != nil {
		log.Error("Database Error", err)
		return 0, err
	}
	defer stmt.Close()

	row := stmt.QueryRow(categoryName)
	var categoryID int
	err = row.Scan(&categoryID)
	if err != nil {
		if err == sql.ErrNoRows {

			return 0, nil // Category not found
		}
		return 0, err
	}

	return categoryID, nil
}

func addCat(w http.ResponseWriter, r *http.Request) {
	//new
	categoryName := r.URL.Path[len("/category/"):]

	// Validate category name
	validatedCategoryName, err := validation.ValidateCategoryName(categoryName)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"name":  validation.SanitizeForLog(categoryName),
		}).Error("Invalid category name during addCat")
		http.Error(w, "Invalid category name: "+err.Error(), http.StatusBadRequest)
		return
	}

	db, err := db.LoadDatabase()
	if err != nil {
		log.Error("Database Error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return

	}
	defer db.Close()

	stmt, err := db.Prepare("INSERT INTO Categories (title, body, user_id) VALUES (?, ?, ?)")
	if err != nil {
		log.Error("Database Error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return

	}
	defer stmt.Close()

	res, err := stmt.Exec(canonicalizeTitle(validatedCategoryName), "", 1)
	if err != nil {
		log.Error("Database Error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return

	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		// Handle error
	} else if rowsAffected != 1 {
		log.Error("Unexpected number of rows affected:", rowsAffected)
	} else {
		log.Info("Category inserted successfully!")
		http.Redirect(w, r, "/title/Special:Categories", http.StatusFound)
	}
	log.WithField("name", validation.SanitizeForLog(validatedCategoryName)).Debug("Category Name")

}
func checkCategoryExistence(categoryName string) bool {

	db, err := db.LoadDatabase()
	if err != nil {
		log.Error("Database Error", err)
	}
	defer db.Close()

	// Define the category name to check

	// Prepare the SQL query
	stmt, err := db.Prepare("SELECT EXISTS(SELECT 1 FROM Categories WHERE title = ?)")
	if err != nil {
		log.Error("Database Error", err)
	}
	defer stmt.Close()

	// Execute the query with the category name
	var exists bool
	err = stmt.QueryRow(categoryName).Scan(&exists)
	if err != nil {
		log.Error("Database Error", err)
	}
	return exists

}

// displays categories and sub-categories on the Category:somename page
func loadPageCategory(categoryName string, userAgent string) (*Page, error) {
	// Determine layout size
	size := ""
	if userAgent == Desktop {
		size = `<div class="col-11 d-none d-sm-block">`
	} else {
		size = `<div class="col-12 d-block d-sm-none">`
	}

	// Load site menu
	safeMenu, err := loadMenu()
	if err != nil {
		log.Error("Error loading menu:", err)
	}

	// Find matching pages and subcategories
	matchingPages := findPagesInCategory(categoryName)
	matchingSubCatPages := loadLinksFromSubCategoryFile(categoryName)
	log.Infof("Subcategories for '%s': %+v", categoryName, matchingSubCatPages)

	// Format lists
	categories := formatPageList(matchingPages)
	subcategories := formatSubCatList(matchingSubCatPages)

	// Assemble body content
	var bodyHTML strings.Builder
	if checkCategoryExistence(categoryName) {
		if subcategories != "" {
			bodyHTML.WriteString(`<h2 class="wikih2">Subcategories</h2>`)
			bodyHTML.WriteString(subcategories)
		}
		if categories != "" {
			bodyHTML.WriteString(`<h2 class="wikih2">Pages in category</h2>`)
			bodyHTML.WriteString(categories)
		} else {
			bodyHTML.WriteString(`<p>This category currently contains no pages or media.</p>`)
		}
	} else {
		// Offer to create category if it doesn't exist
		bodyHTML.WriteString(fmt.Sprintf(
			`<a style="color:red" href="/category/%s">Add This Category</a>`, categoryName))
	}

	// Build final page
	return &Page{
		NavTitle:   config.SiteTitle,
		ThemeColor: template.HTML(arcWikiLogo()),
		CTitle:     "Category:" + removeUnderscores(categoryName), // Displayed title
		Title:      categoryName,                                  // For URLs and internal logic
		Body:       template.HTML(bodyHTML.String()),
		Size:       template.HTML(size),
		Menu:       safeMenu,
	}, nil
}

// looks for a file using the same name as the current category loaded prefixed with sub-category name it then generates the the Subcategory pages for this
func loadLinksFromSubCategoryFile(categoryName string) []string {
	db, err := db.LoadDatabase()
	if err != nil {
		log.Error("Error Loading Database:", err)
	}
	defer db.Close()

	// Get the category ID
	categoryID, err := getCategoryIDByName(categoryName)
	if err != nil {
		return nil
	}
	log.Debug(categoryID)
	//fmt.Println(categoryID)

	// Retrieve page paths from CategoryPages
	rows, err := db.Query("SELECT Categories.title FROM SubCategoryPages JOIN Categories ON Categories.id = SubCategoryPages.category_id WHERE SubCategoryPages.subcategory_id = ?", categoryID)

	if err != nil {
		return nil
	}
	defer rows.Close()

	var matchingPages []string
	for rows.Next() {
		var path string
		err := rows.Scan(&path)
		if err != nil {
			return nil
		}
		matchingPages = append(matchingPages, path)
	}

	return matchingPages
}
func findPagesInCategory(categoryName string) []string {
	db, err := db.LoadDatabase()
	if err != nil {
		return nil
	}
	defer db.Close()

	// Get the category ID
	categoryID, err := getCategoryIDByName(categoryName)
	if err != nil {
		return nil
	}

	// Retrieve page paths from CategoryPages
	rows, err := db.Query("SELECT Pages.title FROM Pages JOIN CategoryPages ON Pages.id = CategoryPages.page_id WHERE CategoryPages.category_id = ?", categoryID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var matchingPages []string
	for rows.Next() {
		var path string
		err := rows.Scan(&path)
		if err != nil {
			return nil
		}
		matchingPages = append(matchingPages, path)
	}

	return matchingPages
}

// Formats the links for displaying on web
func formatPageList(pages []string) string {
	baseURL := "/title/"
	// Construct the HTML content for the page list
	// (Implement your desired formatting here)
	linksByLetter := make(map[rune][]string)
	for _, page := range pages {

		linkTitle := filepath.Base(page)
		linkTitleWithoutExt := strings.TrimSuffix(linkTitle, ".txt")
		firstLetter, _ := utf8.DecodeRuneInString(linkTitleWithoutExt)
		firstLetter = unicode.ToUpper(firstLetter)
		// Help title changed to Help:somepage
		if strings.HasPrefix(linkTitleWithoutExt, "Help-") {
			linkTitleWithoutExt = "Help:" + linkTitleWithoutExt[5:]
		}
		//fmt.Println(linkTitle)
		linksByLetter[firstLetter] = append(linksByLetter[firstLetter], fmt.Sprintf("<li><a href=\"%s%s\">%s</a></li>", baseURL, linkTitleWithoutExt, linkTitleWithoutExt))

	}
	keys := make([]string, 0, len(linksByLetter))
	for k := range linksByLetter {
		keys = append(keys, string(k))
	}
	sort.Strings(keys) // Sort keys alphabetically
	var html string
	//var html string
	for _, letter := range keys {
		linkList := linksByLetter[rune(letter[0])] // Access list using converted string
		// ... (rest of your code for generating HTML list)
		html += fmt.Sprintf("<h3>%s</h3><ul>\n%s\n</ul>", letter, strings.Join(linkList, "\n"))
	}
	// for letter, linkList := range linksByLetter {

	// 	html += fmt.Sprintf("<h3>%c</h3><ul>\n%s\n</ul>", letter, strings.Join(linkList, "\n"))
	// }

	return html
}
func formatSubCatList(pages []string) string {
	baseURL := "/title/"
	// Construct the HTML content for the page list

	linksByLetter := make(map[rune][]string)
	for _, page := range pages {

		linkTitle := filepath.Base(page)
		linkTitleWithoutExt := strings.TrimSuffix(linkTitle, ".txt")
		firstLetter, _ := utf8.DecodeRuneInString(linkTitleWithoutExt)
		firstLetter = unicode.ToUpper(firstLetter)
		if strings.HasPrefix(linkTitleWithoutExt, "help-") {
			linkTitleWithoutExt = "Help:" + linkTitleWithoutExt[5:]
		}
		linksByLetter[firstLetter] = append(linksByLetter[firstLetter], fmt.Sprintf("<li><a href=\"%sCategory:%s\">%s</a></li>", baseURL, linkTitleWithoutExt, linkTitleWithoutExt))
	}
	keys := make([]string, 0, len(linksByLetter))
	for k := range linksByLetter {
		keys = append(keys, string(k))
	}
	sort.Strings(keys) // Sort keys alphabetically
	var html string
	//var html string
	for _, letter := range keys {
		linkList := linksByLetter[rune(letter[0])] // Access list using converted string
		// ... (rest of your code for generating HTML list)
		html += fmt.Sprintf("<h3>%s</h3><ul>\n%s\n</ul>", letter, strings.Join(linkList, "\n"))
	}
	// var html string
	// for letter, linkList := range linksByLetter {
	// 	html += fmt.Sprintf("<h3>%c</h3><ul>\n%s\n</ul>", letter, strings.Join(linkList, "\n"))
	// }
	return html
}
func loadCategoryNoHtml(title string, userAgent string) (*EditPage, error) {
	size := ""
	safeMenu, err := loadMenu()
	if err != nil {
		log.Error("Error Loading Menu:", err)
	}
	if userAgent == Desktop {
		size = "<div class=\"col-11 d-none d-sm-block\">"
	} else {
		size = "<div class=\"col-12 d-block d-sm-none\">"
	}
	db, err := db.LoadDatabase()
	if err != nil {
		log.Error("Error Loading Database:", err)
	}
	stmt, err := db.Prepare("SELECT title, body FROM Categories WHERE title = ?")
	if err != nil {
		return nil, err
	}

	row := stmt.QueryRow(title)
	defer db.Close()   // Close the database connection
	defer stmt.Close() // Close the prepared statement

	var body string
	err = row.Scan(&title, &body)
	if err != nil {
		return nil, err
	}

	return &EditPage{NavTitle: config.SiteTitle, ThemeColor: template.HTML(arcWikiLogo()), CTitle: removeUnderscores(title), Title: title, Body: template.HTML(body), Menu: template.HTML(safeMenu), Size: template.HTML(size)}, nil
}
