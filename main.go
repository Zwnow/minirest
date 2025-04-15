package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"restfulapi/app/db"
	"restfulapi/app/handlers"
	"restfulapi/config"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Failed to load environment")
	}

	// Load configuration
	cfg := config.Load()
	log.Printf("MAIL SENDING ACTIVE: %v\n", cfg.Mailjet.Active)

	r := mux.NewRouter()
	handlers.SetupAuthRoutes(r)

	// Setup db
	err = db.SetupDatabase(cfg.Postgres)
	if err != nil {
		log.Fatalf("Failed to set up database: %s", err)
	}

	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}

func printRoutes(r *mux.Router) {
	r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		fmt.Printf("Route: %s, Methods: %v\n", path, methods)
		return nil
	})
}
