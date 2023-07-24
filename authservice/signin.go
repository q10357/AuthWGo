// Schemes : http
// BasePath : /auth
// Version : 1.0.0

// Consumes:
// 	- application/json

// Produces:
// 	- application/json

package authservice

import (
	"errors"
	"net/http"

	"github.com/q10357/AuthWGo/authservice/data"
)

// private function, searches for user in database
func validateUser(email string, pswdhash string) (bool, error) {
	u, exists := data.GetUserObject(email)
	if !exists {
		return false, errors.New("user not found")
	}
	pswdCheck := u.ValidatePasswordHash(pswdhash)

	if(!pswdCheck){
		//provided password is wrong
		return false, nil
	}

	return true, nil
}

// if user not found / login nor validated, returns Unauthorized error
// if found, JWT token is sent to client
func SigninHandler(rw http.ResponseWriter, r *http.Request) {
	// validate request headers
	if _, ok := r.Header["Email"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Email Missing"))
		return
	}
	if _, ok := r.Header["Passwordhash"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Passwordhash Missing"))
		return
	}

	//user exists?
	valid, err := 
}
