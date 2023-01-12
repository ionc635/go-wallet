package jwt

import (
	"log"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	Key string `json:"key"`
}

func CreateToken(key string) string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = key
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()
	accessToken, err := token.SignedString([]byte("asdgjkl;asjd;lf"))
	if err != nil {
		log.Fatal(err)
	}
	return accessToken
}

func TokenVerfy(token string) {
}
