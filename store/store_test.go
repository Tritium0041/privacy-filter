package store

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestMemoryStoreSaveLoadCopiesMapping(t *testing.T) {
	s := NewMemoryStore()
	mapping := map[string]string{"[邮箱_0]": "a@b.com"}
	id, err := s.Save(mapping, time.Minute)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	mapping["[邮箱_0]"] = "changed@example.com"

	loaded, err := s.Load(id)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded["[邮箱_0]"] != "a@b.com" {
		t.Fatalf("Save 未保存副本: %#v", loaded)
	}
	loaded["[邮箱_0]"] = "mutated@example.com"

	loadedAgain, err := s.Load(id)
	if err != nil {
		t.Fatalf("Load again: %v", err)
	}
	if loadedAgain["[邮箱_0]"] != "a@b.com" {
		t.Fatalf("Load 未返回副本: %#v", loadedAgain)
	}
}

func TestMemoryStoreExpired(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore()
	s.now = func() time.Time { return now }
	id, err := s.Save(map[string]string{"[邮箱_0]": "a@b.com"}, time.Minute)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	now = now.Add(time.Minute)
	if _, err := s.Load(id); !errors.Is(err, ErrExpired) {
		t.Fatalf("Load expired error=%v want ErrExpired", err)
	}
	if _, err := s.Load(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session should be removed, got %v", err)
	}
}

func TestMemoryStoreDestroy(t *testing.T) {
	s := NewMemoryStore()
	id, err := s.Save(map[string]string{"[邮箱_0]": "a@b.com"}, time.Minute)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.Destroy(id); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := s.Load(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load after destroy error=%v want ErrNotFound", err)
	}
	if err := s.Destroy(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Destroy missing error=%v want ErrNotFound", err)
	}
}

func TestMemoryStoreConcurrentSaveLoad(t *testing.T) {
	s := NewMemoryStore()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := s.Save(map[string]string{"[邮箱_0]": "a@b.com"}, time.Minute)
			if err != nil {
				t.Errorf("Save: %v", err)
				return
			}
			if _, err := s.Load(id); err != nil {
				t.Errorf("Load: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestMemoryStoreRejectsNonPositiveTTL(t *testing.T) {
	s := NewMemoryStore()
	if _, err := s.Save(map[string]string{}, 0); err == nil {
		t.Fatal("Save with zero TTL should fail")
	}
}
