package allocator

import (
	"sync"
	"testing"
)

func TestAllocateSequential(t *testing.T) {
	dir := t.TempDir()
	a := New(dir + "/instances")
	got := map[int]bool{}
	for i := 0; i < 100; i++ {
		id, err := a.Allocate()
		if err != nil {
			t.Fatal(err)
		}
		if got[id] {
			t.Fatalf("duplicate ID %d", id)
		}
		got[id] = true
	}
	if len(got) != 100 {
		t.Fatalf("expected 100 unique, got %d", len(got))
	}
	if a.Peek() != 100 {
		t.Fatalf("peek=%d want 100", a.Peek())
	}
}

func TestAllocateConcurrentUnique(t *testing.T) {
	dir := t.TempDir()
	a := New(dir + "/instances")
	const n = 25
	var wg sync.WaitGroup
	ids := make([]int, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := a.Allocate()
			ids[i] = id
			errs[i] = err
		}(i)
	}
	wg.Wait()
	seen := map[int]bool{}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("alloc %d: %v", i, errs[i])
		}
		if seen[ids[i]] {
			t.Fatalf("concurrent collision on ID %d", ids[i])
		}
		seen[ids[i]] = true
	}
	if len(seen) != n {
		t.Fatalf("expected %d unique IDs, got %d", n, len(seen))
	}
}

func TestAllocatePersistent(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/instances"
	a1 := New(p)
	if _, err := a1.Allocate(); err != nil {
		t.Fatal(err)
	}
	if _, err := a1.Allocate(); err != nil {
		t.Fatal(err)
	}
	// A fresh allocator on the same path must continue from 2, not reuse 1/2.
	a2 := New(p)
	id, err := a2.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if id != 3 {
		t.Fatalf("expected persisted counter to yield 3, got %d", id)
	}
}
