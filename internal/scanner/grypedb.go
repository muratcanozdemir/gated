package scanner

import (
	"context"
	"log/slog"
	"os/exec"
	"time"
)

// grype checks for a newer vulnerability database when it starts and, if
// there is one, downloads and imports it before it scans: on a daily
// database that is about once a day, and it took 80 s in the test ride.
// The scan, and the package manager whose output gated holds for its
// verdict, wait all that time.
//
// So gated refreshes the database itself, in the background (KeepDBFresh),
// and once a refresh has succeeded, scans run with auto-update off and use
// the database that is there. Until then (the first start, or while grype
// cannot reach its server) scans update as before, so a missing database
// is still fetched.
const dbUpdateTimeout = 10 * time.Minute

// KeepDBFresh refreshes grype's database now and then every interval, until
// ctx is done. Run it in its own goroutine.
func (o *Orchestrator) KeepDBFresh(ctx context.Context, interval time.Duration) {
	for {
		o.updateDB(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (o *Orchestrator) updateDB(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, dbUpdateTimeout)
	defer cancel()
	start := time.Now()
	out, err := exec.CommandContext(ctx, o.tools.Grype, "db", "update").CombinedOutput()
	if err != nil {
		slog.Warn("grype database refresh failed; scans update it themselves meanwhile",
			"err", err, "output", string(out))
		return
	}
	o.dbFresh.Store(true)
	slog.Info("grype database refreshed", "took", time.Since(start).Round(time.Millisecond))
}

// grypeEnv is the environment scans run grype with: no update check once the
// background refresh keeps the database current.
func (o *Orchestrator) grypeEnv() []string {
	if o.dbFresh.Load() {
		return []string{"GRYPE_DB_AUTO_UPDATE=false"}
	}
	return nil
}
