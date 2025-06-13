package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Env struct {
	NODE_ENV    string
	DEV_DB_URL  string
	PROD_DB_URL string
	PORT        int
}

func LoadEnv() *Env {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	PORT, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		log.Fatal("Error parsing PORT")
	}

	return &Env{
		NODE_ENV:    os.Getenv("NODE_ENV"),
		DEV_DB_URL:  os.Getenv("DEV_DB_URL"),
		PROD_DB_URL: os.Getenv("PROD_DB_URL"),
		PORT:        PORT,
	}
}
