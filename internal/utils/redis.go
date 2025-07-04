package utils

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"
)

func ToRedisHash(obj interface{}) (map[string]interface{}, error) {
	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal object to JSON: %w", err)
	}

	var objMap map[string]interface{}
	err = json.Unmarshal(jsonBytes, &objMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to map: %w", err)
	}

	return objMap, nil
}

func SetRedisHash(ctx context.Context, rdb *redis.Client, key string, obj interface{}) error {
	objMap, err := ToRedisHash(obj)
	if err != nil {
		return fmt.Errorf("failed to convert struct to Redis hash map: %w", err)
	}

	cmd := rdb.HSet(ctx, key, objMap)
	if cmd.Err() != nil {
		return fmt.Errorf("failed to HSet struct: %w", cmd.Err())
	}
	return nil
}
