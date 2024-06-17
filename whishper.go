package main

import (
	"fmt"
	"log"
	"whishper/restRouter"
	"whishper/storageApi"
)

func main() {

	storage := storageApi.Init()
	router := restRouter.Init(&storage)

	fmt.Println(storage)

	// Start server
	log.Fatal(router.App.Listen(":3000"))
}
