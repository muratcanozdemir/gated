//go:build darwin

package watcher

/*
#cgo LDFLAGS: -framework CoreServices

#include <CoreServices/CoreServices.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>

// Bridge callback: FSEvents fires this, which calls into Go.
extern void goFSEventCallback(size_t numEvents, char **paths, unsigned int *flags);

static void
fsevents_callback(
	ConstFSEventStreamRef streamRef,
	void *info,
	size_t numEvents,
	void *eventPaths,
	const FSEventStreamEventFlags eventFlags[],
	const FSEventStreamEventId eventIds[])
{
	goFSEventCallback(numEvents, (char **)eventPaths, (unsigned int *)eventFlags);
}

// create_stream sets up an FSEventStream for the given paths.
// Returns the stream ref, or NULL on failure.
static FSEventStreamRef
create_stream(CFArrayRef pathsToWatch, FSEventStreamEventId sinceWhen, CFTimeInterval latency)
{
	FSEventStreamContext ctx = {0, NULL, NULL, NULL, NULL};

	FSEventStreamRef stream = FSEventStreamCreate(
		kCFAllocatorDefault,
		&fsevents_callback,
		&ctx,
		pathsToWatch,
		sinceWhen,
		latency,
		kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer
	);

	return stream;
}

// schedule_stream assigns a dispatch queue and starts the stream.
// Uses FSEventStreamSetDispatchQueue (macOS 10.6+, non-deprecated)
// instead of FSEventStreamScheduleWithRunLoop (deprecated macOS 13.0).
static int
schedule_stream(FSEventStreamRef stream)
{
	dispatch_queue_t q = dispatch_queue_create("com.gated.fsevents", DISPATCH_QUEUE_SERIAL);
	FSEventStreamSetDispatchQueue(stream, q);
	return FSEventStreamStart(stream);
}
*/
import "C"

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/internal/gate-daemon/internal/config"
	"github.com/internal/gate-daemon/internal/quarantine"
)

// globalDarwin holds the singleton state for the FSEvents callback.
// FSEvents uses a C callback that can't carry Go context, so we use
// a package-level variable. Only one DarwinWatcher per process.
var globalDarwin struct {
	mu      sync.Mutex
	watcher *DarwinWatcher
}

type DarwinWatcher struct {
	paths      []config.WatchPath
	qEngine    *quarantine.Engine
	decisionFn DecisionFunc
	warnOnly   bool
	done       chan struct{}
}

func New(wcfg Config) (Watcher, error) {
	qEngine := quarantine.NewEngine(wcfg.DecisionFn, wcfg.WarnOnly)

	w := &DarwinWatcher{
		paths:      wcfg.Paths,
		qEngine:    qEngine,
		decisionFn: wcfg.DecisionFn,
		warnOnly:   wcfg.WarnOnly,
		done:       make(chan struct{}),
	}

	globalDarwin.mu.Lock()
	globalDarwin.watcher = w
	globalDarwin.mu.Unlock()

	return w, nil
}

func (w *DarwinWatcher) Run() error {
	// Build CFArray of paths to watch.
	cPaths := make([]unsafe.Pointer, len(w.paths))
	for i, wp := range w.paths {
		cs := C.CFStringCreateWithCString(C.kCFAllocatorDefault,
			C.CString(wp.Path), C.kCFStringEncodingUTF8)
		cPaths[i] = unsafe.Pointer(cs)
	}

	pathArray := C.CFArrayCreate(
		C.kCFAllocatorDefault,
		(*unsafe.Pointer)(unsafe.Pointer(&cPaths[0])),
		C.CFIndex(len(cPaths)),
		&C.kCFTypeArrayCallBacks,
	)
	defer C.CFRelease(C.CFTypeRef(pathArray))

	// Create the FSEvents stream.
	// Latency of 0.1s: events are batched for at most 100ms.
	stream := C.create_stream(
		pathArray,
		C.FSEventStreamEventId(C.kFSEventStreamEventIdSinceNow),
		C.CFTimeInterval(0.1),
	)
	if stream == nil {
		return fmt.Errorf("FSEventStreamCreate failed")
	}

	// Schedule on a GCD serial queue and start (non-deprecated API).
	if C.schedule_stream(stream) == 0 {
		return fmt.Errorf("FSEventStreamStart failed")
	}

	slog.Info("darwin watcher started",
		"paths", len(w.paths),
		"mode", "fsevents+quarantine",
	)

	for _, wp := range w.paths {
		slog.Info("watching", "path", wp.Path, "ecosystem", wp.Ecosystem)
	}

	// Events are delivered on the GCD dispatch queue created in schedule_stream.
	// Block until shutdown signal.
	<-w.done

	C.FSEventStreamStop(stream)
	C.FSEventStreamInvalidate(stream)
	C.FSEventStreamRelease(stream)
	return nil
}

func (w *DarwinWatcher) Close() error {
	close(w.done)
	return nil
}

func (w *DarwinWatcher) Mode() string { return "fsevents+quarantine" }

func (w *DarwinWatcher) resolveEcosystem(path string) string {
	for _, wp := range w.paths {
		if strings.HasPrefix(path, wp.Path) {
			return wp.Ecosystem
		}
	}
	return ""
}

// handleFSEvent processes a single file event from FSEvents.
func (w *DarwinWatcher) handleFSEvent(path string, flags uint32) {
	// Skip quarantine directories to avoid recursive loops.
	if quarantine.IsQuarantinePath(path) {
		return
	}

	// Skip directories — we only care about files.
	// kFSEventStreamEventFlagItemIsDir = 0x00020000
	if flags&0x00020000 != 0 {
		return
	}

	// We care about file creation and modification.
	// kFSEventStreamEventFlagItemCreated   = 0x00000100
	// kFSEventStreamEventFlagItemModified  = 0x00001000
	// kFSEventStreamEventFlagItemRenamed   = 0x00000800
	created := flags&0x00000100 != 0
	modified := flags&0x00001000 != 0

	if !created && !modified {
		return
	}

	// Skip metadata files.
	if isMetadataFile(path) {
		return
	}

	ecosystem := w.resolveEcosystem(path)
	if ecosystem == "" {
		return
	}

	// Only process artifact files (wheels, jars, crates, zips, tarballs).
	if !isArtifactFile(path) {
		return
	}

	slog.Debug("fsevents", "path", path, "ecosystem", ecosystem, "created", created, "modified", modified)

	// Quarantine in a goroutine so the callback returns fast.
	go w.qEngine.HandleNewArtifact(path, ecosystem)
}

// isArtifactFile returns true for file extensions we should gate.
func isArtifactFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".whl", ".tar", ".gz", ".zip", ".jar", ".crate", ".tgz", ".egg":
		return true
	}
	// Handle .tar.gz (double extension).
	if strings.HasSuffix(strings.ToLower(path), ".tar.gz") {
		return true
	}
	return false
}

// isMetadataFile filters out non-artifact files.
func isMetadataFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(base)

	switch {
	case lower == "go.sum", lower == "go.mod":
		return true
	case lower == "package-lock.json", lower == "yarn.lock":
		return true
	case lower == "cargo.lock", lower == "cargo.toml":
		return true
	case lower == "requirements.txt", lower == "pyproject.toml":
		return true
	case strings.HasSuffix(lower, ".pom"), strings.HasSuffix(lower, ".xml"):
		return true
	case strings.HasPrefix(lower, "."):
		return true
	}
	return false
}

//export goFSEventCallback
func goFSEventCallback(numEvents C.size_t, paths **C.char, flags *C.uint) {
	globalDarwin.mu.Lock()
	w := globalDarwin.watcher
	globalDarwin.mu.Unlock()

	if w == nil {
		return
	}

	n := int(numEvents)
	// Convert C arrays to Go slices.
	pathSlice := unsafe.Slice(paths, n)
	flagSlice := unsafe.Slice(flags, n)

	for i := 0; i < n; i++ {
		path := C.GoString(pathSlice[i])
		flag := uint32(flagSlice[i])
		w.handleFSEvent(path, flag)
	}
}
