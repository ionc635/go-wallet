package jwt

import (
	"errors"
	"log"
	"time"

	conf "lecture/go-wallet/config"

	"github.com/dgrijalva/jwt-go/v4"
)

type AuthTokenClaims struct {
	Key string `json:"key"`
	jwt.StandardClaims
}

var config = conf.GetConfig("config/config.toml")

var (
	PRIVATE_KEY = config.Jwt.PrivateKey
	EXPIRES     = config.Jwt.Expires
)

func CreateToken(key string) string {
	claims := AuthTokenClaims{
		Key: key,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: jwt.At(time.Now().Add(time.Hour * time.Duration(EXPIRES))),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	accessToken, err := token.SignedString([]byte(PRIVATE_KEY))
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
		return []byte(PRIVATE_KEY), nil
	}

	_, err := jwt.ParseWithClaims(token, &claims, key)
	if err != nil {
		log.Fatal(err)
	}
	return claims.Key
}
