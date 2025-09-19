package scanner

import (
	"context"
	"errors"
	"sync"
	"time"

	api "github.com/ensigniasec/run-mcp/internal/api"
	apigen "github.com/ensigniasec/run-mcp/internal/api-gen"
	"github.com/ensigniasec/run-mcp/internal/storage"
	"github.com/sirupsen/logrus"
)

const (
	backoffBase = 250 * time.Millisecond
	maxAttempts = 3
	batchSize   = 25
	debounce    = 200 * time.Millisecond
	workerCount = 2
	fetchCount  = 4
	channelSize = 8
	// Named durations to avoid magic numbers in timeouts/intervals.
	scanPollTimeout     = 2 * time.Minute
	scanPollInterval    = 500 * time.Millisecond
	serverPolicyUnknown = "unknown"
)

// RatingsCollector batches identifier submissions to the ratings API and maps them back to servers.
// It also applies local allowlist decisions immediately.
type RatingsCollector struct {
	ctx     context.Context
	client  api.RatingsClient
	storage *storage.Storage

	batchSize   int
	debounce    time.Duration
	workerCount int
	fetchCount  int

	mu          sync.Mutex
	seen        map[apigen.IdentifierKind]map[string]struct{}
	curBatch    []apigen.TargetIdentifier
	timer       *time.Timer
	idToServers map[string][]string

	serverPolicy map[string]string
	serverLinks  map[string]string
	serverRating map[string]*SecurityRating

	sendCh chan []apigen.TargetIdentifier
	wg     sync.WaitGroup

	// Optional notifications for UI stages.
	notifySubmitted  func(serverName string)
	notifyProcessing func(serverName string)
	notifyReceived   func(serverName string)
}

// NewRatingsCollector creates a new collector. Pass a nil client to operate offline.
func NewRatingsCollector(ctx context.Context, client api.RatingsClient, st *storage.Storage) *RatingsCollector { //nolint:ireturn
	if ctx == nil {
		ctx = context.Background()
	}
	rc := &RatingsCollector{
		ctx:          ctx,
		client:       client,
		storage:      st,
		batchSize:    batchSize,
		debounce:     debounce,
		workerCount:  workerCount,
		fetchCount:   fetchCount,
		seen:         make(map[apigen.IdentifierKind]map[string]struct{}),
		idToServers:  make(map[string][]string),
		serverPolicy: make(map[string]string),
		serverLinks:  make(map[string]string),
		serverRating: make(map[string]*SecurityRating),
		sendCh:       make(chan []apigen.TargetIdentifier, channelSize),
	}
	rc.startWorkers()
	return rc
}

// IsOffline reports whether the collector is operating without a remote client.
func (rc *RatingsCollector) IsOffline() bool {
	return rc == nil || rc.client == nil
}

// WithStageNotifiers sets optional callbacks for UI to reflect submission stages.
func (rc *RatingsCollector) WithStageNotifiers(submitted func(string), processing func(string), received func(string)) *RatingsCollector { //nolint:ireturn
	rc.notifySubmitted = submitted
	rc.notifyProcessing = processing
	rc.notifyReceived = received
	return rc
}

// startWorkers launches the batch delivery workers.
func (rc *RatingsCollector) startWorkers() {
	for range rc.workerCount {
		rc.wg.Add(1)
		go func() {
			defer rc.wg.Done()
			for batch := range rc.sendCh {
				rc.deliverBatch(batch)
			}
		}()
	}
}

// makeKey returns a stable map key for an identifier.
func makeKey(t apigen.TargetIdentifier) string { return string(t.Kind) + "|" + t.Value }

// Submit records identifiers for a server and schedules a batched flush.
func (rc *RatingsCollector) Submit(serverName string, serverConfig interface{}) {
	// Apply local allowlist immediately and skip remote lookup for those.
	if localAllowlisted(rc.storage, serverName, serverName) {
		rc.mu.Lock()
		rc.serverPolicy[serverName] = "allowed"
		rc.mu.Unlock()
		return
	}

	// If offline, surface unknown and return.
	if rc.client == nil {
		rc.mu.Lock()
		if _, ok := rc.serverPolicy[serverName]; !ok {
			rc.serverPolicy[serverName] = serverPolicyUnknown
		}
		rc.mu.Unlock()
		return
	}

	ids := NewIdentifierExtractor().ExtractIdentifiers(serverName, serverConfig)
	if len(ids) == 0 {
		rc.mu.Lock()
		if _, ok := rc.serverPolicy[serverName]; !ok {
			rc.serverPolicy[serverName] = serverPolicyUnknown
		}
		rc.mu.Unlock()
		return
	}

	rc.mu.Lock()
	for _, id := range ids {
		if id.Kind == "" || id.Value == "" {
			continue
		}
		if _, ok := rc.seen[id.Kind]; !ok {
			rc.seen[id.Kind] = make(map[string]struct{})
		}
		k := id.Value
		if _, ok := rc.seen[id.Kind][k]; ok {
			// Already recorded globally; still map to this server for fan-out.
			rc.idToServers[makeKey(id)] = append(rc.idToServers[makeKey(id)], serverName)
			continue
		}
		rc.seen[id.Kind][k] = struct{}{}
		rc.curBatch = append(rc.curBatch, id)
		rc.idToServers[makeKey(id)] = append(rc.idToServers[makeKey(id)], serverName)
	}
	// Notify submission stage for this server.
	if rc.notifySubmitted != nil {
		go rc.notifySubmitted(serverName)
	}

	if rc.timer == nil {
		rc.timer = time.AfterFunc(rc.debounce, func() { rc.flush() })
	} else {
		rc.timer.Reset(rc.debounce)
	}
	if len(rc.curBatch) >= rc.batchSize {
		rc.flushLocked()
	}
	rc.mu.Unlock()
}

// flush triggers a flush from the debounce callback.
func (rc *RatingsCollector) flush() {
	rc.mu.Lock()
	rc.flushLocked()
	rc.mu.Unlock()
}

// flushLocked moves the current batch to the send channel. Caller must hold rc.mu.
func (rc *RatingsCollector) flushLocked() {
	if len(rc.curBatch) == 0 {
		return
	}
	batch := make([]apigen.TargetIdentifier, len(rc.curBatch))
	copy(batch, rc.curBatch)
	rc.curBatch = rc.curBatch[:0]
	select {
	case rc.sendCh <- batch:
	default:
		logrus.Debug("ratings collector backpressure: dropping batch")
	}
}

// deliverBatch sends a batch with retries honoring Retry-After and 5xx backoff.
func (rc *RatingsCollector) deliverBatch(batch []apigen.TargetIdentifier) {
	if rc.client == nil || len(batch) == 0 {
		return
	}
	ctx := rc.ctx

	backoff := backoffBase
	for range maxAttempts {
		resp, accepted, err := rc.client.SubmitBatchRatings(ctx, apigen.BatchRatingRequest{Identifiers: batch})
		if err == nil {
			if accepted != nil {
				rc.onAccepted(batch, accepted.ScanId.String())
				return
			}
			rc.onImmediateResponse(batch, resp)
			return
		}

		if rc.handleRetryableError(err, &backoff) {
			continue
		}

		logrus.Debugf("batch submit failed, dropping: %v", err)
		return
	}
	logrus.Debug("batch submit: max attempts reached, dropping")
}

// onAccepted handles 202 Accepted: notify processing, mark pending, and poll async.
func (rc *RatingsCollector) onAccepted(batch []apigen.TargetIdentifier, scanID string) {
	rc.notifyProcessingForBatch(batch)
	rc.markServersPending(batch)
	go rc.pollAndApply(scanID)
}

// onImmediateResponse handles synchronous rating response and notifies receivers.
func (rc *RatingsCollector) onImmediateResponse(batch []apigen.TargetIdentifier, resp apigen.BatchRatingResponse) {
	rc.applyRatings(resp)
	rc.notifyReceivedForBatch(batch)
}

// notifyProcessingForBatch emits processing notifications for all servers in batch.
func (rc *RatingsCollector) notifyProcessingForBatch(batch []apigen.TargetIdentifier) {
	if rc.notifyProcessing == nil {
		return
	}
	for _, ids := range batch {
		servers := rc.idToServers[makeKey(ids)]
		for _, name := range servers {
			go rc.notifyProcessing(name)
		}
	}
}

// markServersPending marks servers related to the batch as pending.
func (rc *RatingsCollector) markServersPending(batch []apigen.TargetIdentifier) {
	rc.mu.Lock()
	for _, ids := range batch {
		servers := rc.idToServers[makeKey(ids)]
		for _, name := range servers {
			rc.serverPolicy[name] = "pending"
		}
	}
	rc.mu.Unlock()
}

// notifyReceivedForBatch emits received notifications for all servers in batch.
func (rc *RatingsCollector) notifyReceivedForBatch(batch []apigen.TargetIdentifier) {
	if rc.notifyReceived == nil {
		return
	}
	for _, ids := range batch {
		servers := rc.idToServers[makeKey(ids)]
		for _, name := range servers {
			go rc.notifyReceived(name)
		}
	}
}

// handleRetryableError returns true if the error was handled and the caller should retry.
func (rc *RatingsCollector) handleRetryableError(err error, backoff *time.Duration) bool { //nolint:ireturn
	var rl api.RateLimitedError
	if errors.As(err, &rl) {
		d := time.Duration(rl.RetryAfterSeconds) * time.Second
		if d <= 0 {
			d = *backoff
		}
		time.Sleep(d)
		return true
	}
	if re, ok := asRemote(err); ok && re.StatusCode >= 500 {
		time.Sleep(*backoff)
		*backoff *= 2
		return true
	}
	return false
}

func (rc *RatingsCollector) pollAndApply(scanID string) {
	ctx, cancel := context.WithTimeout(rc.ctx, scanPollTimeout)
	defer cancel()
	ratings, err := rc.client.WaitForScanCompletion(ctx, scanID, scanPollInterval)
	if err != nil {
		logrus.Debugf("polling scan %s failed: %v", scanID, err)
		return
	}
	// Convert returned ratings to link mapping by querying IDs from serverLinks
	// We don't have direct mapping here, but serverLinks are applied when fetching
	// batch links. For now, nothing to link; future improvement could map by identifiers.
	_ = ratings
	// Notify received for servers related to the identifiers.
	if rc.notifyReceived != nil {
		rc.mu.Lock()
		for k := range rc.idToServers {
			for _, name := range rc.idToServers[k] {
				go rc.notifyReceived(name)
			}
		}
		rc.mu.Unlock()
	}
}

// applyRatings integrates received ratings into server link mappings.
func (rc *RatingsCollector) applyRatings(resp apigen.BatchRatingResponse) {
	if len(resp.Ratings) == 0 {
		return
	}
	rc.mu.Lock()
	for _, item := range resp.Ratings {
		k := makeKey(item.Identifier)
		if servers, ok := rc.idToServers[k]; ok {
			for _, name := range servers {
				rc.serverLinks[name] = item.RatingUrl
			}
		}
	}
	rc.mu.Unlock()
}

// asRemote extracts api.RemoteError when possible.
func asRemote(err error) (api.RemoteError, bool) { //nolint:ireturn
	var re api.RemoteError
	if errors.As(err, &re) {
		return re, true
	}
	return api.RemoteError{}, false
}

// ApplyToSummary attaches local policies and any available ratings to the summary.
func (rc *RatingsCollector) ApplyToSummary(summary *ScanSummary) {
	if summary == nil {
		return
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	for i := range summary.Servers {
		s := &summary.Servers[i]
		if p, ok := rc.serverPolicy[s.Name]; ok {
			s.LocalPolicy = p
		}
		if r, ok := rc.serverRating[s.Name]; ok {
			s.Rating = r
		}
	}
}

// FlushAndStop drains pending identifiers and stops workers.
func (rc *RatingsCollector) FlushAndStop() {
	rc.mu.Lock()
	if rc.timer != nil {
		rc.timer.Stop()
		rc.timer = nil
	}
	rc.flushLocked()
	rc.mu.Unlock()
	close(rc.sendCh)
	rc.wg.Wait()
}

// localAllowlisted checks local allowlist using provided storage.
func localAllowlisted(st *storage.Storage, serverName, hash string) bool {
	if st == nil {
		return false
	}
	allowlist := st.Data.Allowlist["server"]
	for _, h := range allowlist {
		if h == hash {
			return true
		}
	}
	return false
}
