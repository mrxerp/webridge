package auth

import (
	"math"
	"strconv"
	"sync"
	"time"

	"webridge/internal/config"
)

type attemptTracker struct {
	failures     int
	lockoutUntil time.Time
	backoffStep  int
	lastSeen     time.Time
}

// Bruteforce provides configurable login rate-limiting with exponential backoff,
// tracked separately by IP and by username. Both must clear for a login to proceed.
type Bruteforce struct {
	mu     sync.Mutex
	byIP   map[string]*attemptTracker
	byUser map[string]*attemptTracker
	cfg    config.LoginRateConfig
}

func NewBruteforce(cfg config.LoginRateConfig) *Bruteforce {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.WindowMinutes <= 0 {
		cfg.WindowMinutes = 15
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 1
	}
	if cfg.BackoffMaxMinutes <= 0 {
		cfg.BackoffMaxMinutes = 64
	}
	return &Bruteforce{
		byIP:   make(map[string]*attemptTracker),
		byUser: make(map[string]*attemptTracker),
		cfg:    cfg,
	}
}

// Check returns nil if the login attempt is allowed, or a reason string if locked.
// Caller should return 423 with the reason.
func (b *Bruteforce) Check(ip, username string) (locked bool, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()

	if t, ok := b.byIP[ip]; ok {
		b.clean(t, now)
		if now.Before(t.lockoutUntil) {
			remaining := time.Until(t.lockoutUntil).Truncate(time.Second)
			return true, "IP locked, try again in " + formatDuration(remaining)
		}
	}

	if t, ok := b.byUser[username]; ok {
		b.clean(t, now)
		if now.Before(t.lockoutUntil) {
			remaining := time.Until(t.lockoutUntil).Truncate(time.Second)
			return true, "account locked, try again in " + formatDuration(remaining)
		}
	}

	return false, ""
}

// RecordFailure increments failure counters and applies lockout if threshold is hit.
func (b *Bruteforce) RecordFailure(ip, username string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()

	ipTracker := b.getOrCreate(b.byIP, ip, now)
	userTracker := b.getOrCreate(b.byUser, username, now)

	ipTracker.failures++
	userTracker.failures++

	ipTracker.lastSeen = now
	userTracker.lastSeen = now

	// Lock IP if threshold hit
	if ipTracker.failures >= b.cfg.MaxAttempts {
		ipTracker.lockoutUntil = now.Add(time.Duration(b.computeLockout(ipTracker.backoffStep)) * time.Minute)
		ipTracker.backoffStep++
	}

	// Lock username if threshold hit
	if userTracker.failures >= b.cfg.MaxAttempts {
		userTracker.lockoutUntil = now.Add(time.Duration(b.computeLockout(userTracker.backoffStep)) * time.Minute)
		userTracker.backoffStep++
	}
}

// Reset clears both IP and username trackers on successful login.
func (b *Bruteforce) Reset(ip, username string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.byIP, ip)
	delete(b.byUser, username)
}

type LockInfo struct {
	Key          string    `json:"key"`
	Type         string    `json:"type"`
	Failures     int       `json:"failures"`
	LockoutUntil time.Time `json:"lockout_until"`
}

type BruteforceState struct {
	Config config.LoginRateConfig `json:"config"`
	Locks  []LockInfo             `json:"locks"`
}

// GetState returns current config and active locks for the admin UI.
func (b *Bruteforce) GetState() BruteforceState {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	var locks []LockInfo
	collect := func(m map[string]*attemptTracker, typ string) {
		for k, t := range m {
			b.clean(t, now)
			if t.failures > 0 {
				locks = append(locks, LockInfo{Key: k, Type: typ, Failures: t.failures, LockoutUntil: t.lockoutUntil})
			}
		}
	}
	collect(b.byIP, "ip")
	collect(b.byUser, "username")

	return BruteforceState{Config: b.cfg, Locks: locks}
}

// UpdateConfig updates the brute-force settings at runtime.
func (b *Bruteforce) UpdateConfig(cfg config.LoginRateConfig) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cfg.MaxAttempts > 0 {
		b.cfg.MaxAttempts = cfg.MaxAttempts
	}
	if cfg.WindowMinutes > 0 {
		b.cfg.WindowMinutes = cfg.WindowMinutes
	}
	if cfg.BackoffBase > 0 {
		b.cfg.BackoffBase = cfg.BackoffBase
	}
	if cfg.BackoffMaxMinutes > 0 {
		b.cfg.BackoffMaxMinutes = cfg.BackoffMaxMinutes
	}
}

// ResetByIP clears all lockout state for an IP.
func (b *Bruteforce) ResetByIP(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.byIP, ip)
}

// ResetByUsername clears all lockout state for a username.
func (b *Bruteforce) ResetByUsername(username string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.byUser, username)
}

// ResetAll clears all lockout state.
func (b *Bruteforce) ResetAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.byIP = make(map[string]*attemptTracker)
	b.byUser = make(map[string]*attemptTracker)
}

func (b *Bruteforce) getOrCreate(m map[string]*attemptTracker, key string, now time.Time) *attemptTracker {
	t, ok := m[key]
	if !ok {
		t = &attemptTracker{lastSeen: now}
		m[key] = t
	}
	return t
}

func (b *Bruteforce) clean(t *attemptTracker, now time.Time) {
	window := time.Duration(b.cfg.WindowMinutes*2*b.cfg.BackoffMaxMinutes) * time.Minute
	if now.Sub(t.lastSeen) > window {
		t.failures = 0
		t.backoffStep = 0
		t.lockoutUntil = time.Time{}
	}
}

func (b *Bruteforce) computeLockout(step int) int {
	lockout := float64(b.cfg.BackoffBase) * math.Pow(2, float64(step))
	max := float64(b.cfg.BackoffMaxMinutes)
	if lockout > max {
		lockout = max
	}
	return int(lockout)
}

func formatDuration(d time.Duration) string {
	minutes := int(math.Ceil(d.Minutes()))
	if minutes <= 1 {
		return "less than a minute"
	}
	return strconv.Itoa(minutes) + " minutes"
}
