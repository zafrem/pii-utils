package provider

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
)

// MemStore is an in-memory Store for tests. It holds object bytes keyed by
// bucket and key, pages listings deterministically (sorted by key), and can be
// told to fail specific operations to exercise error handling.
type MemStore struct {
	objects map[string]map[string][]byte

	// PageSize sets how many objects List emits per page (0 = all in one page),
	// so tests can assert the scanner's per-page accounting and early stop.
	PageSize int
	// ListErr, if set, is returned by List instead of iterating.
	ListErr error
	// OpenErr maps a key to an error Open should return for it.
	OpenErr map[string]error
}

// NewMemStore builds an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{objects: map[string]map[string][]byte{}, OpenErr: map[string]error{}}
}

// Put stores an object's bytes.
func (m *MemStore) Put(bucket, key string, data []byte) {
	if m.objects[bucket] == nil {
		m.objects[bucket] = map[string][]byte{}
	}
	m.objects[bucket][key] = data
}

// List emits objects under prefix in key order, in pages of PageSize.
func (m *MemStore) List(ctx context.Context, bucket, prefix string, emit func([]Object) error) error {
	if m.ListErr != nil {
		return m.ListErr
	}
	var keys []string
	for k := range m.objects[bucket] {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	all := make([]Object, 0, len(keys))
	for _, k := range keys {
		all = append(all, Object{Key: k, Size: int64(len(m.objects[bucket][k]))})
	}

	if len(all) == 0 { // empty listing is still one LIST request, like S3
		return emit(nil)
	}
	pageSize := m.PageSize
	if pageSize <= 0 {
		pageSize = len(all)
	}
	for start := 0; start < len(all); start += pageSize {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := start + pageSize
		if end > len(all) {
			end = len(all)
		}
		if err := emit(all[start:end]); err != nil {
			if err == ErrStop {
				return nil
			}
			return err
		}
	}
	return nil
}

// Open returns a reader over the object's bytes, or an injected/absent error.
func (m *MemStore) Open(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	if err := m.OpenErr[key]; err != nil {
		return nil, err
	}
	data, ok := m.objects[bucket][key]
	if !ok {
		return nil, fmt.Errorf("memstore: no such object %s/%s", bucket, key)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}
