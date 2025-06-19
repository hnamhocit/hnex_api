package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Env struct {
	DB_URL string
	PORT   int
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
		DB_URL: os.Getenv("DB_URL"),
		PORT:   PORT,
	}
}
