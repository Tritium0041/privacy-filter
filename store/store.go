// Package store 管理可逆脱敏会话中的短期映射状态。
package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const DefaultTTL = 5 * time.Minute

var (
	ErrNotFound = errors.New("session not found")
	ErrExpired  = errors.New("session expired")
)

// SessionStore 保存和读取可逆脱敏映射。
type SessionStore interface {
	Save(mapping map[string]string, ttl time.Duration) (string, error)
	Load(sessionID string) (map[string]string, error)
	Destroy(sessionID string) error
}

type sessionEntry struct {
	mapping   map[string]string
	expiresAt time.Time
}

// MemoryStore 是基于内存的并发安全 SessionStore。
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]sessionEntry
	now      func() time.Time
}

// NewMemoryStore 创建一个内存 store。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]sessionEntry),
		now:      time.Now,
	}
}

// Save 保存 mapping 的副本，并返回随机 session_id。
func (s *MemoryStore) Save(mapping map[string]string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", errors.New("ttl must be positive")
	}
	id, err := newSessionID()
	if err != nil {
		return "", err
	}
	entry := sessionEntry{
		mapping:   cloneMapping(mapping),
		expiresAt: s.now().Add(ttl),
	}
	s.mu.Lock()
	s.sessions[id] = entry
	s.mu.Unlock()
	return id, nil
}

// Load 返回 mapping 的副本。过期 session 会被删除并返回 ErrExpired。
func (s *MemoryStore) Load(sessionID string) (map[string]string, error) {
	s.mu.RLock()
	entry, ok := s.sessions[sessionID]
	now := s.now()
	s.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if !now.Before(entry.expiresAt) {
		s.mu.Lock()
		if current, ok := s.sessions[sessionID]; ok && !s.now().Before(current.expiresAt) {
			delete(s.sessions, sessionID)
		}
		s.mu.Unlock()
		return nil, ErrExpired
	}
	return cloneMapping(entry.mapping), nil
}

// Destroy 主动销毁 session。不存在时返回 ErrNotFound。
func (s *MemoryStore) Destroy(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[sessionID]; !ok {
		return ErrNotFound
	}
	delete(s.sessions, sessionID)
	return nil
}

func cloneMapping(mapping map[string]string) map[string]string {
	out := make(map[string]string, len(mapping))
	for k, v := range mapping {
		out[k] = v
	}
	return out
}

func newSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
