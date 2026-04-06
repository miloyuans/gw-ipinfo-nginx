package syncx

import "sync"

type Group struct {
	mu sync.Mutex
	m  map[string]*call
}

type call struct {
	wg  sync.WaitGroup
	val any
	err error
}

func (g *Group) Do(key string, fn func() (any, error)) (any, error, bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*call)
	}
	if existing, ok := g.m[key]; ok {
		g.mu.Unlock()
		existing.wg.Wait()
		return existing.val, existing.err, true
	}

	current := &call{}
	current.wg.Add(1)
	g.m[key] = current
	g.mu.Unlock()

	current.val, current.err = fn()
	current.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	return current.val, current.err, false
}
