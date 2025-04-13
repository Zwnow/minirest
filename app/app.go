package app

import (
	"net/http"

	"github.com/gorilla/mux"
)

func Init() {
	r := mux.NewRouter()

	http.Handle("/", r)
}
