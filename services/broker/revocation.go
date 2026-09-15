package broker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aryanference/securedeck/internal/db"
)

type RevocationCache struct {
	db       db.DB
	revoked  sync.Map
	interval time.Duration
}

func NewRevocationCache(database db.DB, refreshInterval time.Duration) *RevocationCache {
	return &RevocationCache{
		db:       database,
		interval: refreshInterval,
	}
}

func (c *RevocationCache) Start(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	// Initial load
	c.refresh(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refresh(ctx)
		}
	}
}

func (c *RevocationCache) refresh(ctx context.Context) {
	rows, err := c.db.QueryContext(ctx, "SELECT token_id FROM token_issuance_log WHERE revoked = 1")
	if err != nil {
		fmt.Printf("failed to refresh revocation cache: %v\n", err)
		return
	}
	defer rows.Close()

	newCache := sync.Map{}
	for rows.Next() {
		var tokenID string
		if err := rows.Scan(&tokenID); err != nil {
			continue
		}
		newCache.Store(tokenID, true)
	}

	c.revoked = newCache
}

func (c *RevocationCache) IsRevoked(jti string) bool {
	_, ok := c.revoked.Load(jti)
	return ok
}
