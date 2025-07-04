package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"hnex.com/internal/config"
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
	"hnex.com/internal/utils"
)

// Declaration

type BanService struct {
	repo *repositories.BanRepository
}

func NewBanService(repo *repositories.BanRepository) *BanService {
	return &BanService{repo: repo}
}

// Helper

func (s *BanService) getKey(id string) string {
	return fmt.Sprintf("ban:%s", id)
}

// Code

type BannedUser struct {
	Reason      string `json:"reason" redis:"reason"`
	ExpiresAt   int64  `json:"expires_at" redis:"expires_at"`
	CreatedAt   int64  `json:"created_at" redis:"created_at"`
	IsPermanent bool   `json:"is_permanent" redis:"is_permanent"`
}

func (s *BanService) Getban(ctx context.Context, userId string) (*BannedUser, error) {
	var bannedUser BannedUser
	redisKey := s.getKey(userId)
	now := time.Now()

	// 1. Check Redis
	data := config.RedisClient.HGetAll(ctx, redisKey)
	if data.Err() == nil && len(data.Val()) > 0 {
		if err := data.Scan(&bannedUser); err == nil {
			if bannedUser.IsPermanent {
				return &bannedUser, nil
			}

			if bannedUser.ExpiresAt > 0 && time.Unix(bannedUser.ExpiresAt, 0).Before(now) {
				config.RedisClient.Del(ctx, redisKey) // sync
				go s.repo.DeleteByUserId(userId)
				return nil, nil
			}

			return &bannedUser, nil
		}
		log.Printf("Fail to scan Redis ban data: %v", data.Err())
	}

	// 2. Fallback to DB
	ban, err := s.repo.FindOneByUserId(userId)
	if err != nil || ban == nil {
		return nil, err
	}

	bannedUser = BannedUser{
		Reason:      ban.Reason,
		ExpiresAt:   ban.ExpiresAt,
		CreatedAt:   ban.CreatedAt.Unix(),
		IsPermanent: ban.IsPermanent,
	}

	if !bannedUser.IsPermanent && bannedUser.ExpiresAt > 0 && time.Unix(bannedUser.ExpiresAt, 0).Before(now) {
		go s.repo.DeleteByUserId(userId)
		return nil, nil
	}

	// Cache lại Redis
	hash, err := utils.ToRedisHash(bannedUser)
	if err == nil {
		go func() {
			if err := config.RedisClient.HSet(ctx, redisKey, hash).Err(); err != nil {
				log.Printf("Failed to cache ban in Redis: %v", err)
			}

			if !bannedUser.IsPermanent {
				ttl := time.Until(time.Unix(bannedUser.ExpiresAt, 0))
				config.RedisClient.Expire(ctx, redisKey, ttl)
			}
		}()
	}

	return &bannedUser, nil
}

func (s *BanService) SetBan(ctx context.Context, userId, reason string, duration time.Duration, isPermanent bool) error {
	var expiresAt int64
	var redisTTL time.Duration
	now := time.Now()

	if !isPermanent {
		if duration <= 0 {
			return errors.New("ban duration must be > 0 for temporary bans")
		}
		expiresAt = now.Add(duration).Unix()
		redisTTL = duration
	}

	// Save to DB
	bannedUser := models.Ban{
		UserId:      userId,
		Reason:      reason,
		ExpiresAt:   expiresAt,
		IsPermanent: isPermanent,
	}
	if err := s.repo.Create(&bannedUser); err != nil {
		return err
	}

	// Save to Redis
	redisBannedUser := BannedUser{
		Reason:      reason,
		ExpiresAt:   expiresAt,
		CreatedAt:   now.Unix(),
		IsPermanent: isPermanent,
	}

	key := s.getKey(userId)
	pipe := config.RedisClient.Pipeline()

	hash, err := utils.ToRedisHash(redisBannedUser)
	if err != nil {
		return err
	}

	pipe.HSet(ctx, key, hash)
	if redisTTL > 0 {
		pipe.Expire(ctx, key, redisTTL)
	} else {
		pipe.Persist(ctx, key)
	}

	_, err = pipe.Exec(ctx)
	return err
}

func (s *BanService) RemoveBan(ctx context.Context, userId string) error {
	if err := s.repo.DeleteById(userId); err != nil {
		return err
	}

	return config.RedisClient.Del(ctx, s.getKey(userId)).Err()
}
