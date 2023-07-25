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
	"strconv"
	"time"

	"github.com/q10357/AuthWGo/authservice/data"
	"github.com/q10357/AuthWGo/authservice/jwt"
)

// private function, searches for user in database
func validateUser(email string, pswdhash string, ui *data.UserInfo) (bool, error) {
	u, exists := data.GetUserObject(email)
	if !exists {
		return false, errors.New("user not found")
	}
	pswdCheck := u.ValidatePasswordHash(pswdhash)

	if !pswdCheck {
		//provided password is wrong
		return false, nil
	}

	//Setting userinfo for claims
	ui.IsAdmin = u.CheckIfAdmin()
	ui.Id = u.GetUserId()

	return true, nil
}

func getSignedToken(ui *data.UserInfo) (string, error) {
	//secret := "Secure_Random_string"
	claimsMap := map[string]string{
		"sub":   strconv.FormatUint(ui.Id, 10),
		"admin": strconv.FormatBool(ui.IsAdmin),
		"exp":   fmt.Sprint(time.Now().Add(time.Minute * 1).Unix()),
	}

	tokenString, err := jwt.GenerateToken(claimsMap)

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

	var ui data.UserInfo

	//user exists?
	valid, err := validateUser(body["Email"].(string), body["PasswordHash"].(string), &ui)

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
	tokenStr, err := getSignedToken(&ui)

	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Internal Server Error"))
		return
	}

	fmt.Println("Login successfull")

	http.SetCookie(rw, &http.Cookie{
		Name:     "token",
		Value:    tokenStr,
		HttpOnly: true,
	})
	rw.WriteHeader(http.StatusOK)
}
