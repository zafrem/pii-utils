// Package provider abstracts object storage behind a small interface so the
// scanner can run against real cloud storage (S3Store) or an in-memory fake
// (MemStore) without change. Implementations own their own API calls, pagination,
// and rate limiting; the scanner stays provider-neutral orchestration.
package provider

import (
	"context"
	"errors"
	"io"
)

// Object is a single stored object discovered during listing.
type Object struct {
	Key  string
	Size int64
}

// ErrStop, when returned from a List page callback, stops listing without being
// reported as an error — e.g. once a sampling cap has been reached.
var ErrStop = errors.New("provider: stop listing")

// Store is the object-storage surface the scanner reads through.
type Store interface {
	// List streams objects under prefix, invoking emit once per page. Returning
	// a non-nil error from emit stops iteration and is propagated, except
	// ErrStop, which stops cleanly.
	List(ctx context.Context, bucket, prefix string, emit func([]Object) error) error
	// Open returns a reader over one object's bytes; the caller closes it.
	Open(ctx context.Context, bucket, key string) (io.ReadCloser, error)
}
