// Schemes : http
// BasePath : /auth
// Version : 1.0.0

// Consumes:
// 	- application/json

// Produces:
// 	- application/json

package authservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/q10357/AuthWGo/authservice/data"
	"github.com/q10357/AuthWGo/authservice/jwt"
)

// private function, searches for user in database
func validateUser(email string, pswdhash string) (bool, error) {
	u, exists := data.GetUserObject(email)
	if !exists {
		return false, errors.New("user not found")
	}
	pswdCheck := u.ValidatePasswordHash(pswdhash)

	if !pswdCheck {
		//provided password is wrong
		return false, nil
	}

	return true, nil
}

func getSignedToken() (string, error) {
	claimsMap := map[string]string{
		"sub": "1",
		"iss": "knowsearch.ml",
		"exp": fmt.Sprint(time.Now().Add(time.Minute * 1).Unix()),
	}

	//secret := "Secure_Random_string"
	secret := "S0m3_R4n90m_sss"
	header := "HS256"

	tokenString, err := jwt.GenerateToken(header, claimsMap, secret)
	if err != nil {
		return tokenString, err
	}
	return tokenString, nil
}

// if user not found / login nor validated, returns Unauthorized error
// if found, JWT token is sent to client
func SigninHandler(rw http.ResponseWriter, r *http.Request) {
	// validate request headers
	body := map[string]interface{}{}
	json.NewDecoder(r.Body).Decode(&body)
	fmt.Println(body)

	if _, ok := body["Email"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Email Missing"))
		return
	}
	if _, ok := body["PasswordHash"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Passwordhash Missing"))
		return
	}

	//user exists?
	valid, err := validateUser(body["Email"].(string), body["PasswordHash"].(string))

	if err != nil {
		//user not found
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("User not Found"))
		return
	}

	if !valid {
		//wrong credentials
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("Incorrect Password"))
		return
	}

	//Valid login
	tokenStr, err := getSignedToken()
	if err != nil {
		fmt.Println(err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Internal Server Error"))
		return
	}

	fmt.Println("Login successfull")
	fmt.Println(tokenStr)

	http.SetCookie(rw, &http.Cookie{
		Name:     "token",
		Value:    tokenStr,
		HttpOnly: true,
	})
	rw.WriteHeader(http.StatusOK)
}
