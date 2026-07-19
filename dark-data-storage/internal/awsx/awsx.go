// Package awsx wraps AWS client construction, caller-identity lookup, and the
// bucket-discovery audit used to surface ungoverned ("dark") storage before
// scanning it for PII.
package awsx

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/zafrem/pii-utils/dark-data-storage/internal/discovery"
)

// Clients bundles the AWS service clients discovery and scanning need, plus the
// loaded config so region-specific S3 clients can be derived on demand.
type Clients struct {
	S3     *s3.Client
	STS    *sts.Client
	Region string

	cfg    aws.Config
	mu     sync.Mutex
	byRegn map[string]*s3.Client
}

// New builds AWS clients from the default credential chain. Retry uses the SDK's
// adaptive mode, which reacts to S3 throttling (503 SlowDown) with client-side
// rate backoff — complementary to the scanner's proactive rate limiter.
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
	c := &Clients{
		S3:     s3.NewFromConfig(cfg),
		STS:    sts.NewFromConfig(cfg),
		Region: cfg.Region,
		cfg:    cfg,
		byRegn: map[string]*s3.Client{},
	}
	c.byRegn[cfg.Region] = c.S3
	return c, nil
}

// S3ForRegion returns an S3 client pinned to a region, building and caching one
// as needed. Object-level calls (ListObjectsV2, GetObject) must hit the bucket's
// own region or S3 answers with a 301 redirect.
func (c *Clients) S3ForRegion(region string) *s3.Client {
	if region == "" {
		region = c.Region
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl, ok := c.byRegn[region]; ok {
		return cl
	}
	cl := s3.NewFromConfig(c.cfg, func(o *s3.Options) { o.Region = region })
	c.byRegn[region] = cl
	return cl
}

// Identity describes who the caller is.
type Identity struct {
	Account     string
	ARN         string
	CanonicalID string // S3 canonical user ID of the caller's account
}

// WhoAmI returns the caller's account and canonical user ID.
func (c *Clients) WhoAmI(ctx context.Context) (*Identity, error) {
	id, err := c.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("sts:GetCallerIdentity: %w", err)
	}
	out := &Identity{Account: aws.ToString(id.Account), ARN: aws.ToString(id.Arn)}
	if lb, err := c.S3.ListBuckets(ctx, &s3.ListBucketsInput{}); err == nil && lb.Owner != nil {
		out.CanonicalID = aws.ToString(lb.Owner.ID)
	}
	return out, nil
}

// S3 ACL grantee URIs that expose a bucket to the world.
const (
	uriAllUsers  = "http://acs.amazonaws.com/groups/global/AllUsers"
	uriAuthUsers = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

// DiscoverBuckets enumerates every bucket the caller owns and audits each one's
// exposure and governance posture, returning provider-neutral facts for the
// discovery package to score. Per-bucket audit failures are recorded on the
// bucket (as Errors) rather than aborting the whole discovery.
func (c *Clients) DiscoverBuckets(ctx context.Context, countCap int) ([]discovery.BucketFacts, error) {
	lb, err := c.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("s3:ListBuckets: %w", err)
	}
	facts := make([]discovery.BucketFacts, 0, len(lb.Buckets))
	for _, b := range lb.Buckets {
		name := aws.ToString(b.Name)
		f := discovery.BucketFacts{Name: name}
		if b.CreationDate != nil {
			f.CreatedAt = *b.CreationDate
		}
		f.Region = c.bucketRegion(ctx, name, &f)
		cl := c.S3ForRegion(f.Region)
		c.auditPublic(ctx, cl, name, &f)
		c.auditEncryption(ctx, cl, name, &f)
		c.auditTagging(ctx, cl, name, &f)
		if countCap > 0 {
			c.auditCount(ctx, cl, name, countCap, &f)
		}
		facts = append(facts, f)
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].Name < facts[j].Name })
	return facts, nil
}

func (c *Clients) bucketRegion(ctx context.Context, bucket string, f *discovery.BucketFacts) string {
	out, err := c.S3.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(bucket)})
	if err != nil {
		f.Errors = append(f.Errors, auditErr("region", err))
		return c.Region
	}
	// An empty LocationConstraint means us-east-1.
	if out.LocationConstraint == "" {
		return "us-east-1"
	}
	return string(out.LocationConstraint)
}

func (c *Clients) auditPublic(ctx context.Context, cl *s3.Client, bucket string, f *discovery.BucketFacts) {
	var byACL, byPolicy bool

	if acl, err := cl.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: aws.String(bucket)}); err != nil {
		f.Errors = append(f.Errors, auditErr("acl", err))
	} else {
		for _, g := range acl.Grants {
			if g.Grantee != nil && g.Grantee.Type == types.TypeGroup {
				if u := aws.ToString(g.Grantee.URI); u == uriAllUsers || u == uriAuthUsers {
					byACL = true
				}
			}
		}
	}

	if ps, err := cl.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: aws.String(bucket)}); err != nil {
		if !isNotFound(err) { // no bucket policy is normal, not an audit gap
			f.Errors = append(f.Errors, auditErr("policy-status", err))
		}
	} else if ps.PolicyStatus != nil {
		byPolicy = aws.ToBool(ps.PolicyStatus.IsPublic)
	}

	// A Public Access Block that restricts both ACLs and policies neutralizes the
	// exposure detected above.
	blocked := false
	if pab, err := cl.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(bucket)}); err != nil {
		if !isNotFound(err) {
			f.Errors = append(f.Errors, auditErr("public-access-block", err))
		}
	} else if cfg := pab.PublicAccessBlockConfiguration; cfg != nil {
		blocked = aws.ToBool(cfg.IgnorePublicAcls) && aws.ToBool(cfg.RestrictPublicBuckets)
	}

	switch {
	case byACL && byPolicy:
		f.PublicVia = "acl+policy"
	case byACL:
		f.PublicVia = "acl"
	case byPolicy:
		f.PublicVia = "policy"
	}
	f.Public = (byACL || byPolicy) && !blocked
	if !f.Public {
		f.PublicVia = ""
	}
}

func (c *Clients) auditEncryption(ctx context.Context, cl *s3.Client, bucket string, f *discovery.BucketFacts) {
	out, err := cl.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(bucket)})
	if err != nil {
		if isNotFound(err) || isCode(err, "ServerSideEncryptionConfigurationNotFoundError") {
			f.EncryptKnown, f.Encrypted = true, false
			return
		}
		f.Errors = append(f.Errors, auditErr("encryption", err))
		return
	}
	f.EncryptKnown = true
	f.Encrypted = out.ServerSideEncryptionConfiguration != nil &&
		len(out.ServerSideEncryptionConfiguration.Rules) > 0
}

func (c *Clients) auditTagging(ctx context.Context, cl *s3.Client, bucket string, f *discovery.BucketFacts) {
	out, err := cl.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: aws.String(bucket)})
	if err != nil {
		if isNotFound(err) || isCode(err, "NoSuchTagSet") {
			f.TagKnown, f.Tagged = true, false
			return
		}
		f.Errors = append(f.Errors, auditErr("tagging", err))
		return
	}
	f.TagKnown = true
	f.Tagged = len(out.TagSet) > 0
}

func (c *Clients) auditCount(ctx context.Context, cl *s3.Client, bucket string, countCap int, f *discovery.BucketFacts) {
	out, err := cl.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		MaxKeys: aws.Int32(int32(countCap)),
	})
	if err != nil {
		f.Errors = append(f.Errors, auditErr("list", err))
		return
	}
	f.Objects = int64(aws.ToInt32(out.KeyCount))
	f.ApproxCount = aws.ToBool(out.IsTruncated)
}

func auditErr(step string, err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return step + ": " + apiErr.ErrorCode()
	}
	return step + ": " + err.Error()
}

func isCode(err error, code string) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == code
}

func isNotFound(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "NoSuchPublicAccessBlockConfiguration", "NoSuchBucketPolicy", "NoSuchTagSet", "NotFound", "404":
		return true
	}
	return false
}
