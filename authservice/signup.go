package authservice

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/q10357/AuthWGo/authservice/data"
)

// adds user to db
func SignupHandler(rw http.ResponseWriter, r *http.Request) {
	// error handling (should also handle possible SQL injections)
	body := map[string]interface{}{}
	json.NewDecoder(r.Body).Decode(&body)
	fmt.Println(body)

	if _, ok := body["Email"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Email missing"))
	}
	if _, ok := body["Username"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Username Missing"))
		return
	}
	if _, ok := body["PasswordHash"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Hash Missing"))
		return
	}

	// validate and add user
	success := data.AddNewUserObject(body["Email"].(string), body["Username"].(string),
		body["PasswordHash"].(string), 0)

	// !success => user exists
	if !success {
		rw.WriteHeader(http.StatusConflict)
		rw.Write([]byte("Email / Username already exists"))
		return
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("User Created"))
}
