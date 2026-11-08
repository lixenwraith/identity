package api

import (
	"math"
	"net/netip"
	"sync"
	"time"
)

// maxBudgetClients bounds the addresses a budget tracks; past it a new
// address is refused for a period, failing closed, as logwisp's table does.
const maxBudgetClients = 4096

// budget bounds one kind of attempt per client address: a bucket of burst
// tokens refilled over a period, a token refunded for an attempt that turned
// out not to count, such as a sign-in that succeeded.
type budget struct {
	burst   float64
	period  time.Duration
	mu      sync.Mutex
	clients map[string]*bucket
	swept   time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newBudget(burst int, period time.Duration) *budget {
	return &budget{burst: float64(burst), period: period, clients: make(map[string]*bucket)}
}

// take spends a token of addr's bucket, or says how long until one refills.
func (b *budget) take(addr string, now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Sub(b.swept) > b.period/6 {
		b.sweep(now)
	}
	key := budgetKey(addr)
	c := b.clients[key]
	if c == nil {
		if len(b.clients) >= maxBudgetClients {
			return b.period
		}
		c = &bucket{tokens: b.burst, at: now}
		b.clients[key] = c
	}
	c.refill(now, b.burst, b.period)
	if c.tokens < 1 {
		return time.Duration(math.Ceil((1 - c.tokens) / b.burst * float64(b.period)))
	}
	c.tokens--
	return 0
}

func (b *budget) refund(addr string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if c := b.clients[budgetKey(addr)]; c != nil {
		c.tokens = min(b.burst, c.tokens+1)
	}
}

func (c *bucket) refill(now time.Time, burst float64, period time.Duration) {
	if elapsed := now.Sub(c.at); elapsed > 0 {
		c.tokens = min(burst, c.tokens+float64(elapsed)/float64(period)*burst)
	}
	c.at = now
}

// sweep forgets the addresses whose buckets are full again, so the table
// holds the addresses that are spending, not every one that ever called.
func (b *budget) sweep(now time.Time) {
	b.swept = now
	for key, c := range b.clients {
		c.refill(now, b.burst, b.period)
		if c.tokens >= b.burst {
			delete(b.clients, key)
		}
	}
}

// budgetKey counts an IPv6 address by its /64, which one host usually holds
// whole, so a peer cannot escape its budget by moving within its prefix.
func budgetKey(addr string) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return addr
	}
	ip = ip.Unmap()
	if !ip.Is6() {
		return ip.String()
	}
	return netip.PrefixFrom(ip, 64).Masked().String()
}
