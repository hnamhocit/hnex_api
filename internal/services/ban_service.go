package services

import (
	"context"
	"fmt"
	"log"
	"time"

	"hnex.com/internal/config"
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
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
	Reason      string `json:"reason"`
	ExpiresAt   int64  `json:"expires_at"`
	CreatedAt   int64  `json:"banned_at"`
	IsPermanent bool   `json:"is_permanent,omitempty"`
}

func (s *BanService) GetBannedUser(ctx context.Context, userId string) (*BannedUser, error) {
	var bannedUser BannedUser
	redisKey := s.getKey(userId)
	now := time.Now()

	// Get from Redis
	data := config.RedisClient.HGetAll(ctx, redisKey)
	if data.Err() == nil && len(data.Val()) > 0 {
		if err := data.Scan(&bannedUser); err != nil {
			log.Printf("Fail to scan Redis ban data: %v", err)
		} else if bannedUser.CreatedAt > 0 {
			if bannedUser.IsPermanent {
				return &bannedUser, nil
			}

			if bannedUser.ExpiresAt > 0 && time.Unix(bannedUser.ExpiresAt, 0).Before(now) {
				go func() {
					if err := config.RedisClient.Del(ctx, redisKey).Err(); err != nil {
						log.Printf("Failed to delete Redis ban: %v", err)
					}

					if err := s.repo.DeleteByUserId(userId); err != nil {
						log.Printf("Failed to delete DB ban: %v", err)
					}
				}()

				return nil, nil
			}

			return &bannedUser, nil
		}
	}

	// Fallback to DB
	ban, err := s.repo.FindOneByUserId(userId)
	if err != nil {
		return nil, err
	}

	bannedUser = BannedUser{
		Reason:      ban.Reason,
		ExpiresAt:   ban.ExpiresAt.Unix(),
		CreatedAt:   ban.CreatedAt.Unix(),
		IsPermanent: ban.IsPermanent,
	}

	// Save to Redis
	go func() {
		if err := config.RedisClient.HSet(ctx, redisKey, bannedUser).Err(); err != nil {
			log.Printf("Failed to cache ban in Redis: %v", err)
		}
	}()

	// Expired check
	if !bannedUser.IsPermanent && bannedUser.ExpiresAt > 0 && time.Unix(bannedUser.ExpiresAt, 0).Before(now) {
		go func() {
			if err := s.repo.DeleteByUserId(userId); err != nil {
				log.Printf("Failed to delete expired ban: %v", err)
			}
		}()

		return nil, nil
	}

	return &bannedUser, nil
}

func (s *BanService) SetBannedUser(ctx context.Context, userId, reason string, duration time.Duration, isPermanent bool) error {
	var dbExpiresAt *time.Time
	var expiresAt int64
	var redisTTL time.Duration

	if !isPermanent {
		expTime := time.Now().Add(duration)
		dbExpiresAt = &expTime
		expiresAt = expTime.Unix()
		redisTTL = duration
	}

	// Save to DB
	bannedUser := models.Ban{
		UserId:      userId,
		Reason:      reason,
		ExpiresAt:   dbExpiresAt,
		IsPermanent: isPermanent,
	}
	if err := s.repo.Create(&bannedUser); err != nil {
		return err
	}

	// Save to Redis
	redisBannedUser := BannedUser{
		Reason:      reason,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now().Unix(),
		IsPermanent: isPermanent,
	}

	key := s.getKey(userId)
	pipe := config.RedisClient.Pipeline()
	pipe.HSet(ctx, key, redisBannedUser)

	if redisTTL > 0 {
		pipe.Expire(ctx, key, redisTTL)
	} else {
		pipe.Persist(ctx, key)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}

	return nil
}

func (s *BanService) RemoveBannedUser(ctx context.Context, userId string) error {
	if err := s.repo.DeleteById(userId); err != nil {
		return err
	}
	return config.RedisClient.Del(ctx, s.getKey(userId)).Err()
}
