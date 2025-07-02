package config

import "github.com/redis/go-redis/v9"

var RedisClient = redis.NewClient(&redis.Options{
	Addr:     "127.0.0.1:6379",
	Username: "default",
	Password: "",
})
