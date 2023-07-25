//https://mattermost.com/blog/how-to-build-an-authentication-microservice-in-golang-from-scratch/

package main

import (
	"fmt"
	"net/http"

	"github.com/q10357/AuthWGo/authservice"
)

func main() {
	fmt.Println("Server starting...")
	mux := http.NewServeMux()

	mux.HandleFunc("/signin", authservice.SigninHandler)
	mux.HandleFunc("/signup", authservice.SignupHandler)

	server := &http.Server{
		Addr:    "127.0.0.1:3333",
		Handler: mux,
	}

	err := server.ListenAndServe()
	if err != nil {
		fmt.Printf("Error Booting the Server\nError: %s\n", err)
	}
}
