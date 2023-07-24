package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Generate tokens
func GenerateToken(header string, payload map[string]string, secret string) (string, error) {
	//create new hash of type SHA256, pass secret to it
	h := hmac.New(sha256.New, []byte(secret))

	//Encode header as base64 string
	header64 := base64.StdEncoding.EncodeToString([]byte(header))

	//Marshal (ibject to json string) payload, then base encode the string
	payloadstr, err := json.Marshal(payload)

	if err != nil {
		//Mashal function returned an error
		fmt.Println("Error generating Token")
		//return payloadstr as string and error
		return string(payloadstr), err
	}
	//Continue
	payload64 := base64.StdEncoding.EncodeToString(payloadstr)

	//Concat strings, seperate by "."
	message := header64 + "." + payload64

	//Unsigned msg ready
	unsignedStr := header + string(payloadstr)

	//write to SHA256 to hash. Use to generate signature
	h.Write([]byte(unsignedStr))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	//This is the token
	tokenStr := message + "." + signature
	return tokenStr, nil
}

func ValidateToken(token string, secret string) (bool, error) {
	//Three parts seperated by "."
	splitToken := strings.Split(token, ".")

	if len(splitToken) != 3 {
		return false, nil
	}

	//decode header & payload into strings
	//header is the first element of the array
	header, err := base64.StdEncoding.DecodeString(splitToken[0])
	if err != nil {
		return false, err
	}
	//followed by our payload
	payload, err := base64.StdEncoding.DecodeString(splitToken[1])
	if err != nil {
		return false, err
	}

	//create signature
	unsignedStr := string(header) + string(payload)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(unsignedStr))

	//base encode unsignedStr to base64 string
	signature := base64.StdEncoding.EncodeToString([]byte(unsignedStr))
	fmt.Println(signature)

	// if not equal => reject token
	if signature != splitToken[2] {
		return false, nil
	}

	// VALID TOKEN
	return true, nil
}
