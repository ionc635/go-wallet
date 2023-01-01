package main

import "lecture/go-wallet/router"

func main() {
	router := router.GetRouter()
	router.Run(":8080")
}
