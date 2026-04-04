// Package housekeeping runs periodic maintenance tasks:
//   - Rolls up raw snmp_metrics into hourly snmp_trends (safety net for
//     TimescaleDB continuous aggregate lag).
//   - Logs retention and flush statistics.
//
// TimescaleDB retention policies (added via add_retention_policy) handle
// chunk drops automatically; this worker only manages the trend rollup.
package housekeeping

import (
	"context"
	"time"

	"github.com/rs/zerolog"
)

// DB is the minimal interface required by the housekeeping worker.
// Implemented by *pgxpool.Pool or any compatible executor.
type DB interface {
	// Exec executes a query with the given arguments.
	Exec(ctx context.Context, sql string, args ...any) (interface{}, error)
}

// rollupSQL is an idempotent UPSERT that computes hourly Min/Max/Avg/Count
// from raw snmp_metrics and merges them into snmp_trends.
// ON CONFLICT handles re-runs gracefully (e.g. after a restart).
const rollupSQL = `
INSERT INTO snmp_trends (time_bucket, device_ip, oid, oid_name, val_min, val_max, val_avg, val_count)
SELECT
    date_trunc('hour', time)  AS time_bucket,
    device_ip,
    oid,
    MAX(oid_name)             AS oid_name,
    MIN(value_numeric)        AS val_min,
    MAX(value_numeric)        AS val_max,
    AVG(value_numeric)        AS val_avg,
    COUNT(*)                  AS val_count
FROM snmp_metrics
WHERE
    time >= $1
    AND time < $2
    AND value_numeric IS NOT NULL
GROUP BY date_trunc('hour', time), device_ip, oid
ON CONFLICT (time_bucket, device_ip, oid) DO UPDATE SET
    val_min   = LEAST(EXCLUDED.val_min,   snmp_trends.val_min),
    val_max   = GREATEST(EXCLUDED.val_max, snmp_trends.val_max),
    val_avg   = (
                    EXCLUDED.val_avg   * EXCLUDED.val_count +
                    snmp_trends.val_avg * snmp_trends.val_count
                ) / (EXCLUDED.val_count + snmp_trends.val_count),
    val_count = EXCLUDED.val_count + snmp_trends.val_count;
`

// Worker encapsulates the housekeeping goroutine.
type Worker struct {
	log      zerolog.Logger
	db       DB
	interval time.Duration // how often to run the rollup (default: 1 hour)
	lookback time.Duration // how far back to re-aggregate (default: 2 hours)
}

// NewWorker creates a housekeeping worker.
// interval: how often to run (e.g. 1*time.Hour).
// lookback: how far back the rollup window extends (e.g. 2*time.Hour) to
// compensate for any lag in the continuous aggregate.
func NewWorker(log zerolog.Logger, db DB, interval, lookback time.Duration) *Worker {
	if interval <= 0 {
		interval = 1 * time.Hour
	}
	if lookback <= 0 {
		lookback = 2 * time.Hour
	}
	return &Worker{
		log:      log.With().Str("component", "housekeeping").Logger(),
		db:       db,
		interval: interval,
		lookback: lookback,
	}
}

// Run starts the housekeeping ticker loop.  Blocks until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	w.log.Info().
		Dur("interval", w.interval).
		Dur("lookback", w.lookback).
		Msg("housekeeping worker started")

	// Run immediately on startup, then on each tick.
	w.runOnce(ctx)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.log.Info().Msg("housekeeping worker stopped")
			return
		case <-ticker.C:
			w.runOnce(ctx)
		}
	}
}

// runOnce executes a single trend rollup covering the lookback window.
func (w *Worker) runOnce(ctx context.Context) {
	now := time.Now().UTC().Truncate(time.Hour)
	from := now.Add(-w.lookback)

	start := time.Now()
	_, err := w.db.Exec(ctx, rollupSQL, from, now)
	elapsed := time.Since(start)

	if err != nil {
		w.log.Error().Err(err).
			Time("from", from).
			Time("to", now).
			Dur("took", elapsed).
			Msg("trend rollup failed")
		return
	}

	w.log.Info().
		Time("from", from).
		Time("to", now).
		Dur("took", elapsed).
		Msg("trend rollup completed")
}
