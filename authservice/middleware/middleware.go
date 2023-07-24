package middleware

import (
	"net/http"

	"github.com/q10357/AuthWGo/authservice/jwt"
)

// we want all our routes to be authenticated, here we validate the token
func tokenValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		// is token present?
		if _, ok := r.Header["Token"]; !ok {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte("Token missing"))
			return
		}
		token := r.Header["Token"][0]
		check, err := jwt.ValidateToken(token, "S0m3_R4n90m_sss")

		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte("Token Validation Failed"))
			return
		}
		if !check {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte("Token Invalid"))
			return
		}
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("Authorized Token"))
	})
}
