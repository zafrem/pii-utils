package provider

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/time/rate"
)

// S3Store reads objects from AWS S3. Every underlying API call passes through a
// shared token-bucket rate limiter so a large scan does not trip S3 request
// throttling (503 SlowDown); the SDK's adaptive retry layers on top.
type S3Store struct {
	client  *s3.Client
	limiter *rate.Limiter
}

// NewS3Store builds an S3Store. A RequestsPerSec of 0 disables client-side
// limiting (the SDK's adaptive retry still applies).
func NewS3Store(client *s3.Client, requestsPerSec float64, burst int) *S3Store {
	var lim *rate.Limiter
	if requestsPerSec > 0 {
		if burst < 1 {
			burst = 1
		}
		lim = rate.NewLimiter(rate.Limit(requestsPerSec), burst)
	}
	return &S3Store{client: client, limiter: lim}
}

func (s *S3Store) wait(ctx context.Context) error {
	if s.limiter == nil {
		return nil
	}
	return s.limiter.Wait(ctx)
}

// List paginates ListObjectsV2, rate-limiting each page request.
func (s *S3Store) List(ctx context.Context, bucket, prefix string, emit func([]Object) error) error {
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})
	for p.HasMorePages() {
		if err := s.wait(ctx); err != nil {
			return err
		}
		page, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("s3:ListObjectsV2 on %s/%s: %w", bucket, prefix, err)
		}
		objs := make([]Object, 0, len(page.Contents))
		for _, o := range page.Contents {
			objs = append(objs, Object{Key: aws.ToString(o.Key), Size: aws.ToInt64(o.Size)})
		}
		if err := emit(objs); err != nil {
			if errors.Is(err, ErrStop) {
				return nil
			}
			return err
		}
	}
	return nil
}

// Open rate-limits then issues a GetObject, returning the body reader.
func (s *S3Store) Open(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	if err := s.wait(ctx); err != nil {
		return nil, err
	}
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("s3:GetObject %s: %w", key, err)
	}
	return out.Body, nil
}
