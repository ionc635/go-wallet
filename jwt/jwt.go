package jwt

import (
	"errors"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
)

type AuthTokenClaims struct {
	Key string `json:"key"`
	jwt.StandardClaims
}

func CreateToken(key string) string {
	claims := AuthTokenClaims{
		Key: key,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: jwt.At(time.Now().Add(time.Hour * 1000000)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	accessToken, err := token.SignedString([]byte("asdgjkl;asjd;lf"))
	if err != nil {
		log.Fatal(err)
	}
	return accessToken
}

func VerfyToken(token string) string {
	claims := AuthTokenClaims{}
	key := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			ErrUnexpectedSigningMethod := errors.New("unexpected signing method")
			return nil, ErrUnexpectedSigningMethod
		}
		return []byte("asdgjkl;asjd;lf"), nil
	}

	_, err := jwt.ParseWithClaims(token, &claims, key)
	if err != nil {
		log.Fatal(err)
	}
	return claims.Key
}
