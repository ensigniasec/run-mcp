package scanner

import (
	"context"
	"sync"
	"testing"
	"time"

	api "github.com/ensigniasec/run-mcp/internal/api"
	apigen "github.com/ensigniasec/run-mcp/internal/api-gen"
	"github.com/google/uuid"
)

// dummyClient implements api.RatingsClient with no-ops for testing.
type dummyClient struct{}

func (dummyClient) GetRating(ctx context.Context, target api.RatingTarget) (api.RatingResult, error) {
	return api.RatingResult{}, nil
}

func (dummyClient) SubmitBatchRatings(ctx context.Context, req apigen.BatchRatingRequest) (apigen.BatchRatingResponse, *apigen.ScanStatus, error) {
	return apigen.BatchRatingResponse{}, nil, nil
}

func (dummyClient) GetScanStatus(ctx context.Context, scanID uuid.UUID) (apigen.ScanStatus, error) {
	return apigen.ScanStatus{}, nil
}

func (dummyClient) WaitForScanCompletion(ctx context.Context, ref string, pollEvery time.Duration) ([]apigen.SecurityRating, error) {
	return nil, nil
}

// TestRatingsCollector_SendOnClosedChannel_Race exercises the race where a pending
// batch is flushed via SetClient after the send channel has been closed by
// FlushAndStop. It is skipped by default until the race is fixed.
func TestRatingsCollector_SendOnClosedChannel_Race(t *testing.T) {
	t.Skip("Known race reproducer: send on closed channel. Enable when fixed.")

	const iterations = 200
	for i := range iterations {
		rc := NewRatingsCollector(context.Background(), nil, nil)

		// Seed a pending batch while client is nil so flush is deferred.
		rc.mu.Lock()
		rc.curBatch = append(rc.curBatch, apigen.TargetIdentifier{Kind: apigen.Url, Value: "x"})
		rc.mu.Unlock()

		var wg sync.WaitGroup
		wg.Add(2)

		// Race SetClient (which triggers flushLocked) vs FlushAndStop (which closes sendCh).
		go func(j int) {
			defer wg.Done()
			// Small jitter to vary interleavings.
			time.Sleep(time.Duration(j%3) * time.Microsecond)
			rc.SetClient(dummyClient{})
		}(i)

		go func() {
			defer wg.Done()
			rc.FlushAndStop()
		}()

		wg.Wait()
	}
}
