package main

import (
	"log"

	"hnex.com/internal/app"
	"hnex.com/internal/config"
)

func main() {
	env := config.LoadEnv()

	db, err := config.ConnectDB(env)
	if err != nil {
		log.Fatal(err.Error())
	}

	app.Start(db, env.PORT)
}
