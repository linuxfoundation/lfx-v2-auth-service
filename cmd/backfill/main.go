// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Command backfill runs the out-of-band CDP jobs.
//
// These are scheduled one-shot runs rather than a service: each invocation
// walks part of a population, resolves against live CDP, writes what it learned
// and exits. Running one by hand is the same command the CronJob runs, with
// --dry-run available on it.
//
//	backfill --job sweep [--dry-run] [--limit N] [--rate N]
//
// It is a separate binary from the server deliberately — it opens no listener,
// joins no leader election, and holds no NATS subscriptions.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/auth0"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/nats"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/service/backfill"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	logging "github.com/linuxfoundation/lfx-v2-auth-service/pkg/log"
)

// Build-time variables set via ldflags.
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// The out-of-band jobs. The flag takes a name rather than a boolean per job,
// so adding one does not change how the others are invoked.
const (
	// jobSweep is the full-cohort population sweep: it reaches users nothing
	// has processed yet, and keeps a cursor.
	jobSweep = "sweep"

	// jobRecheck is the dormant no-match re-check: it re-resolves users who
	// carry a no-match marker, and keeps no cursor at all.
	jobRecheck = "recheck"
)

var knownJobs = []string{jobSweep, jobRecheck}

const (
	// exitUsage is a bad invocation: an unknown job, or a flag that cannot
	// work. Kept distinct from a run failure so a CronJob's logs say which
	// of the two happened.
	exitUsage = 2

	// exitFailed is a run that started and could not finish.
	exitFailed = 1
)

const (
	// defaultMaxDuration bounds a single run so one invocation cannot still be
	// going when the next is due. The two jobs share one CDP allocation and are
	// scheduled disjointly; this is the in-process half of keeping them so.
	defaultMaxDuration = 1 * time.Hour

	// auth0Timeout bounds one Management API call. A cohort search is heavier
	// than the single-user reads elsewhere in the service, hence the headroom.
	auth0Timeout = 30 * time.Second

	// bucketOpenAttempts is how many times the cursor bucket is looked up
	// before the run gives up.
	//
	// The bucket is created by a JetStream CR in the same release, so on a
	// first install it can lag this job. A few short retries cover that. Past
	// that, failing is correct: the next scheduled run picks it up, and a
	// CronJob that hangs waiting is worse than one that exits.
	bucketOpenAttempts = 3

	// bucketOpenWait spaces those attempts.
	bucketOpenWait = 5 * time.Second

	// maxRateLimitRetries is how many times one user is retried after a 429.
	//
	// One: a 429 means this client's CDP budget is spent, and the users behind
	// this one are not going anywhere. Waiting out more than a single
	// Retry-After is the schedule's job, not this run's.
	maxRateLimitRetries = 1
)

func init() {
	logging.InitStructureLogConfig()
}

func main() {
	// The body is a separate function so its deferred cleanup — unregistering
	// the signal handler, cancelling the context — actually runs. os.Exit skips
	// defers, so calling it from inside the body would leak both.
	os.Exit(run())
}

// run executes one out-of-band job and returns the process exit code.
func run() int {
	job := flag.String("job", "", fmt.Sprintf("which out-of-band job to run (one of: %s)",
		strings.Join(knownJobs, ", ")))
	dryRun := flag.Bool("dry-run", false, "select and report without calling CDP or writing anything")
	limit := flag.Int("limit", 0, "maximum users to process this run (0 means no cap)")
	ratePerMinute := flag.Int("rate", backfill.DefaultRatePerMinute,
		"CDP calls per minute, shared by every out-of-band job on this M2M client")
	pageSize := flag.Int("page-size", auth0.DefaultSearchPageSize, "Auth0 search page size")
	startOffset := flag.Duration("start-offset", backfill.DefaultStartOffset,
		"how far back a cold-start cursor begins; this is what scopes the sweep, since the cohort query carries no upper bound")
	maxDuration := flag.Duration("max-duration", defaultMaxDuration,
		"stop the run after this long, keeping the position it reached")
	showVersion := flag.Bool("version", false, "print version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Printf("backfill %s (built %s, commit %s)\n", Version, BuildTime, GitCommit)
		return 0
	}

	if *job != jobSweep && *job != jobRecheck {
		known := strings.Join(knownJobs, ", ")
		if strings.TrimSpace(*job) == "" {
			fmt.Fprintf(os.Stderr, "error: --job is required (one of: %s)\n", known)
		} else {
			fmt.Fprintf(os.Stderr, "error: unknown job %q (one of: %s)\n", *job, known)
		}
		flag.Usage()
		return exitUsage
	}

	pacer, err := backfill.NewRatePacer(*ratePerMinute)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid --rate %d: %v\n", *ratePerMinute, err)
		return exitUsage
	}

	// SIGTERM is how Kubernetes ends a run that has outstayed its window, so it
	// cancels the context rather than killing the process: the sweep stops
	// between users, and the users it already wrote keep their markers.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, *maxDuration)
	defer cancel()

	slog.InfoContext(ctx, "starting out-of-band CDP job",
		"job", *job,
		"dry_run", *dryRun,
		"limit", *limit,
		"rate_per_minute", *ratePerMinute,
		"max_duration", maxDuration.String(),
		"version", Version,
	)

	opts := backfill.Options{
		DryRun:              *dryRun,
		Limit:               *limit,
		PageSize:            *pageSize,
		StartOffset:         *startOffset,
		MaxRateLimitRetries: maxRateLimitRetries,
	}

	var runErr error
	switch *job {
	case jobSweep:
		runErr = runSweep(ctx, pacer, opts)
	case jobRecheck:
		runErr = runRecheck(ctx, pacer, opts)
	}
	if runErr != nil {
		slog.ErrorContext(ctx, "the out-of-band CDP job failed", "job", *job, "error", runErr)
		return exitFailed
	}
	return 0
}

// runRecheck wires and runs the dormant no-match re-check.
//
// Deliberately lighter than the sweep: no NATS, because this job holds no
// cursor. Its population is re-derived from marker presence on every run.
func runRecheck(ctx context.Context, pacer backfill.Pacer, opts backfill.Options) error {
	auth0Config, err := newAuth0Config(ctx)
	if err != nil {
		return err
	}

	searcher, err := auth0.NewUserSearcher(httpclient.Config{
		Timeout:    auth0Timeout,
		MaxRetries: 0,
	}, auth0Config)
	if err != nil {
		return fmt.Errorf("creating the Auth0 user search: %w", err)
	}

	metadata, err := auth0.NewCDPMetadataWriter(httpclient.Config{
		Timeout:    auth0Timeout,
		MaxRetries: 0,
	}, auth0Config)
	if err != nil {
		return fmt.Errorf("creating the CDP metadata writer: %w", err)
	}

	cdpClient, err := newCDPClient(ctx, auth0Config)
	if err != nil {
		return err
	}

	recheck, err := backfill.NewRecheck(searcher, cdpClient, metadata, pacer, opts)
	if err != nil {
		return fmt.Errorf("creating the no-match re-check: %w", err)
	}

	stats, err := recheck.Run(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "no-match re-check stopped early",
			"scanned", stats.Scanned,
			"promoted", stats.Promoted,
			"conflicted", stats.Conflicted,
			"errors", stats.Errors,
			"completed_full_pass", stats.CompletedFullPass,
			"stopped_reason", stats.StoppedReason,
		)
		return err
	}

	// A partial pass is not a failed run, but it is not a healthy one either:
	// this job restarts from the beginning of its population every time, so
	// whatever the deadline cut off stays cut off.
	if !stats.CompletedFullPass {
		slog.WarnContext(ctx, "the no-match re-check did not reach the end of its population",
			"scanned", stats.Scanned,
			"stopped_reason", stats.StoppedReason,
			"hint", "raise --max-duration or --rate, or lower the population",
		)
	}
	return nil
}

// runSweep wires and runs the full-cohort population sweep.
func runSweep(ctx context.Context, pacer backfill.Pacer, opts backfill.Options) error {
	auth0Config, err := newAuth0Config(ctx)
	if err != nil {
		return err
	}

	searcher, err := auth0.NewUserSearcher(httpclient.Config{
		Timeout: auth0Timeout,
		// The shared client cannot replay a request body, and a search is
		// cheap to reissue on the next run.
		MaxRetries: 0,
	}, auth0Config)
	if err != nil {
		return fmt.Errorf("creating the Auth0 user search: %w", err)
	}

	metadata, err := auth0.NewCDPMetadataWriter(httpclient.Config{
		Timeout:    auth0Timeout,
		MaxRetries: 0,
	}, auth0Config)
	if err != nil {
		return fmt.Errorf("creating the CDP metadata writer: %w", err)
	}

	cdpClient, err := newCDPClient(ctx, auth0Config)
	if err != nil {
		return err
	}

	natsClient, err := newNATSClient(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if errClose := natsClient.Close(); errClose != nil {
			slog.WarnContext(ctx, "failed to close the NATS connection", "error", errClose)
		}
	}()

	cursor, err := openSweepCursor(ctx, natsClient)
	if err != nil {
		return err
	}

	sweep, err := backfill.NewSweep(searcher, cdpClient, metadata, cursor, pacer, opts)
	if err != nil {
		return fmt.Errorf("creating the population sweep: %w", err)
	}

	stats, err := sweep.Run(ctx)
	if err != nil {
		// How far the run got before it stopped is what decides whether to go
		// look at the cursor or at CDP, so it is reported even on the way out.
		slog.ErrorContext(ctx, "population sweep stopped early",
			"scanned", stats.Scanned,
			"written", stats.Written,
			"errors", stats.Errors,
			"stopped_reason", stats.StoppedReason,
		)
		return err
	}
	return nil
}

// newAuth0Config resolves the tenant and mints the Management API token
// manager.
func newAuth0Config(ctx context.Context) (auth0.Config, error) {
	tenant := os.Getenv(constants.Auth0TenantEnvKey)
	domain := os.Getenv(constants.Auth0DomainEnvKey)
	if domain == "" {
		if tenant == "" {
			return auth0.Config{}, fmt.Errorf("either %s or %s is required",
				constants.Auth0DomainEnvKey, constants.Auth0TenantEnvKey)
		}
		domain = fmt.Sprintf("%s.auth0.com", tenant)
	}

	config := auth0.Config{Tenant: tenant, Domain: domain}

	tokenManager, err := auth0.NewM2MTokenManager(ctx, config)
	if err != nil {
		return auth0.Config{}, fmt.Errorf("creating the Auth0 M2M token manager: %w", err)
	}
	config.M2MTokenManager = tokenManager

	return config, nil
}

// newCDPClient builds the CDP client.
//
// The CDP public API and the Auth0 Management API are different audiences, so
// this mints its own token manager rather than reusing the Management one.
func newCDPClient(ctx context.Context, auth0Config auth0.Config) (cdp.Client, error) {
	baseURL := os.Getenv(constants.CDPBaseURLEnvKey)
	audience := os.Getenv(constants.CDPAudienceEnvKey)
	if baseURL == "" || audience == "" {
		return nil, fmt.Errorf("both %s and %s are required",
			constants.CDPBaseURLEnvKey, constants.CDPAudienceEnvKey)
	}

	tokenManager, err := auth0.NewM2MTokenManagerForAudience(ctx, auth0Config, audience)
	if err != nil {
		return nil, fmt.Errorf("creating the CDP M2M token manager: %w", err)
	}

	return cdp.NewClient(cdp.Config{
		BaseURL:      strings.TrimSuffix(baseURL, "/"),
		TokenManager: tokenManager,
	}), nil
}

// newNATSClient connects to NATS for the cursor bucket.
func newNATSClient(ctx context.Context) (*nats.NATSClient, error) {
	url := os.Getenv("NATS_URL")
	if url == "" {
		url = "nats://localhost:4222"
	}

	client, err := nats.NewClient(ctx, nats.Config{
		URL:           url,
		Timeout:       10 * time.Second,
		MaxReconnect:  3,
		ReconnectWait: 2 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("connecting to NATS: %w", err)
	}
	return client, nil
}

// sweepCursorBucket is the bucket name the chart rendered.
func sweepCursorBucket() string {
	if name := strings.TrimSpace(os.Getenv(constants.SweepCursorBucketEnvKey)); name != "" {
		return name
	}
	return constants.KVBucketNameSweepCursor
}

// openSweepCursor opens the cursor bucket, retrying a bounded number of times.
func openSweepCursor(ctx context.Context, client *nats.NATSClient) (backfill.CursorStore, error) {
	bucket := sweepCursorBucket()

	var lastErr error
	for attempt := 1; attempt <= bucketOpenAttempts; attempt++ {
		err := client.KeyValueStore(ctx, bucket)
		if err == nil {
			kv, found := client.GetKVStore(bucket)
			if found {
				return backfill.NewKVCursorStore(kv)
			}
			err = fmt.Errorf("bucket %q opened but was not registered", bucket)
		}
		lastErr = err

		// A name NATS rejects is a typo in the chart, not a bucket still
		// reconciling. Retrying it spends the run's window on something that
		// cannot come right.
		if errors.Is(err, jetstream.ErrInvalidBucketName) {
			return nil, fmt.Errorf("the sweep cursor bucket name is invalid: %w", err)
		}

		if attempt < bucketOpenAttempts {
			slog.WarnContext(ctx, "the sweep cursor bucket is not available yet, retrying",
				"bucket", bucket,
				"attempt", attempt,
				"error", err,
			)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(bucketOpenWait):
			}
		}
	}

	return nil, fmt.Errorf("opening the sweep cursor bucket %q: %w", bucket, lastErr)
}
