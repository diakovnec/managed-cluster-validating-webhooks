// Alternative approach: Rate limiting based solution
package ingresspodprotection

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu        sync.Mutex
	deletions map[string][]time.Time // user -> timestamps
	window    time.Duration
	maxCount  int
}

func NewRateLimiter(window time.Duration, maxCount int) *RateLimiter {
	return &RateLimiter{
		deletions: make(map[string][]time.Time),
		window:    window,
		maxCount:  maxCount,
	}
}

func (rl *RateLimiter) IsAllowed(user string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Clean old timestamps
	var validTimestamps []time.Time
	for _, ts := range rl.deletions[user] {
		if ts.After(cutoff) {
			validTimestamps = append(validTimestamps, ts)
		}
	}
	rl.deletions[user] = validTimestamps

	// Check if under limit
	if len(rl.deletions[user]) >= rl.maxCount {
		return false
	}

	// Add current deletion
	rl.deletions[user] = append(rl.deletions[user], now)
	return true
}

