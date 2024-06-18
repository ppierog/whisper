package storageApi

import (
	"context"

	"github.com/redis/go-redis/v9"
)

type StorageApi struct {
	RedisClient *redis.Client
	//RedisCtx context.Context
}

func Init() StorageApi {
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set yet
		DB:       0,  // use default DB
	})
	return StorageApi{RedisClient: client}
}

func (s StorageApi) Set(key string, value string) {
	ctx := context.Background()
	err := s.RedisClient.Set(ctx, key, value, 0).Err()
	if err != nil {
		panic(err)
	}
}

func (s StorageApi) Get(key string) string {
	ctx := context.Background()
	val, err := s.RedisClient.Get(ctx, key).Result()

	if err != nil {
		panic(err)
	}
	return val

}
