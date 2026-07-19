package scanner

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/cost"
)

// S3Provider implements the Provider interface for AWS S3.
type S3Provider struct {
	client *s3.Client
}

// NewS3Provider builds an S3Provider.
func NewS3Provider(c *s3.Client) *S3Provider {
	return &S3Provider{client: c}
}

func (p *S3Provider) ListPages(ctx context.Context, bucket, prefix string, fn func([]Object) error) error {
	paginator := s3.NewListObjectsV2Paginator(p.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("s3:ListObjectsV2 on %s/%s: %w", bucket, prefix, err)
		}
		var objects []Object
		for _, o := range page.Contents {
			objects = append(objects, Object{
				Key:  aws.ToString(o.Key),
				Size: aws.ToInt64(o.Size),
			})
		}
		if err := fn(objects); err != nil {
			return err
		}
	}
	return nil
}

func (p *S3Provider) Open(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	out, err := p.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("s3:GetObject %s: %w", key, err)
	}
	return out.Body, nil
}

// S3Calculator implements the cost.Calculator interface for AWS S3.
type S3Calculator struct{}

func (c *S3Calculator) Estimate(inv cost.Inventory, sameAccount bool) cost.Estimate {
	return cost.ComputeAWS(inv, sameAccount)
}
