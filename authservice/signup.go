package authservice

import (
	"net/http"

	"github.com/q10357/AuthWGo/authservice/data"
)

// adds user to db
func SignupHandler(rw http.ResponseWriter, r *http.Request) {
	// error handling (should also handle possible SQL injections)
	if _, ok := r.Header["Email"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Email missing"))
	}
	if _, ok := r.Header["Username"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Username Missing"))
		return
	}
	if _, ok := r.Header["Passwordhash"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Hash Missing"))
		return
	}

	// validate and add user
	success := data.AddNewUserObject(r.Header["Email"][0], r.Header["Username"][0],
		r.Header["PasswordHash"][0], 0)

	// !success => user exists
	if !success {
		rw.WriteHeader(http.StatusConflict)
		rw.Write([]byte("Email / Username already exists"))
		return
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("User Created"))
}
