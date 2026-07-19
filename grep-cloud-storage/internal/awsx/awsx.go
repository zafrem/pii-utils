// Package awsx wraps AWS client construction, caller-identity lookup, and the
// same-account ownership check used before scanning a bucket.
package awsx

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// Clients bundles the AWS service clients the scanner needs.
type Clients struct {
	S3     *s3.Client
	STS    *sts.Client
	Region string
}

// New builds AWS clients from the default credential chain. Retry uses the SDK's
// adaptive mode, which reacts to S3 throttling (503 SlowDown) with client-side
// rate backoff — complementary to our own proactive rate limiter.
func New(ctx context.Context, region string, maxAttempts int) (*Clients, error) {
	if maxAttempts < 1 {
		maxAttempts = 10
	}
	optFns := []func(*config.LoadOptions) error{
		config.WithRetryMode(aws.RetryModeAdaptive),
		config.WithRetryMaxAttempts(maxAttempts),
	}
	if region != "" {
		optFns = append(optFns, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	if cfg.Region == "" {
		return nil, errors.New("no AWS region configured: pass --region or set AWS_REGION")
	}
	return &Clients{
		S3:     s3.NewFromConfig(cfg),
		STS:    sts.NewFromConfig(cfg),
		Region: cfg.Region,
	}, nil
}

// Identity describes who the caller is.
type Identity struct {
	Account     string
	ARN         string
	CanonicalID string // S3 canonical user ID of the caller's account
}

// WhoAmI returns the caller's account and canonical user ID. The canonical ID
// comes from ListBuckets (its Owner is the caller's account), which is what
// GetBucketAcl returns for buckets in the same account.
func (c *Clients) WhoAmI(ctx context.Context) (*Identity, error) {
	id, err := c.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("sts:GetCallerIdentity: %w", err)
	}
	out := &Identity{Account: aws.ToString(id.Account), ARN: aws.ToString(id.Arn)}

	lb, err := c.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err == nil && lb.Owner != nil {
		out.CanonicalID = aws.ToString(lb.Owner.ID)
	}
	// A missing canonical ID (e.g. no s3:ListAllMyBuckets permission) is not
	// fatal; SameAccount will report the check as indeterminate.
	return out, nil
}

// Ownership is the result of the same-account check for a bucket.
type Ownership struct {
	Bucket            string
	SameAccount       bool
	Indeterminate     bool   // ownership could not be confirmed either way
	BucketCanonicalID string // owner canonical ID reported by the bucket, if any
	CallerCanonicalID string
	Reason            string // human-readable explanation
}

// CheckBucketOwnership compares the bucket owner's canonical ID against the
// caller's. A mismatch means the bucket lives in a different account; an error
// or a missing canonical ID leaves the result indeterminate (caller should warn
// but may proceed).
func (c *Clients) CheckBucketOwnership(ctx context.Context, bucket string, caller *Identity) Ownership {
	res := Ownership{Bucket: bucket, CallerCanonicalID: caller.CanonicalID}

	acl, err := c.S3.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: aws.String(bucket)})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "AccessDenied" {
			res.Indeterminate = true
			res.Reason = "cannot read bucket ACL (AccessDenied) — bucket is likely owned by another account"
			return res
		}
		res.Indeterminate = true
		res.Reason = fmt.Sprintf("could not determine bucket owner: %v", err)
		return res
	}
	if acl.Owner != nil {
		res.BucketCanonicalID = aws.ToString(acl.Owner.ID)
	}
	if caller.CanonicalID == "" || res.BucketCanonicalID == "" {
		res.Indeterminate = true
		res.Reason = "caller or bucket canonical ID unavailable; ownership could not be confirmed"
		return res
	}
	res.SameAccount = res.BucketCanonicalID == caller.CanonicalID
	if res.SameAccount {
		res.Reason = "bucket owner matches the calling account"
	} else {
		res.Reason = "bucket owner differs from the calling account (cross-account access)"
	}
	return res
}
