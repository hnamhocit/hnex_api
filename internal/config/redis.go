package config

import "github.com/redis/go-redis/v9"

var RedisClient = redis.NewClient(&redis.Options{
	Addr:     "redis-11766.c322.us-east-1-2.ec2.redns.redis-cloud.com",
	Username: "Default",
	Password: "IcGX6KNGc9lMJqZxq3cnRZDpDkFsGIgX",
})
