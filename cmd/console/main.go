package main

import (
	"html/template"
	"log/slog"
	"net/http"
	"os"
)

var templates *template.Template

func init() {
	// D3 Resolved: Zero external UI dependencies, parsing raw HTML templates
	templates = template.Must(template.ParseGlob("../../console/templates/*.html"))
}

func main() {
	slog.Info("Starting Securedeck Console UI")

	// Serve CSS/JS statics
	fs := http.FileServer(http.Dir("../../console/static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Dashboard Route
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		
		// HTMX requests can be optimized here later, but standard layout wraps all for now
		err := templates.ExecuteTemplate(w, "layout.html", nil)
		if err != nil {
			slog.Error("Template error", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	slog.Info("Console running", "url", "http://localhost:"+port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
}
