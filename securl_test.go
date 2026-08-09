package securl

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"securl.click/securl/internal/store"
	"securl.click/securl/internal/store/memory"
)

func setApplicationTestEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("HOST", "127.0.0.1")
	t.Setenv("IP", "invalid")
	t.Setenv("PORT", "1")
	t.Setenv("SECURL_PUBLIC_ORIGINS", "https://securl.example")
	t.Setenv("SECURL_STORE_BACKEND", "memory")
	t.Setenv("SECURL_FRONTEND_MODE", "external")
	t.Setenv("SECURL_CORS_ALLOWED_ORIGINS", "https://app.example")
	t.Setenv("SECURL_SAFE_BROWSING_ENABLED", "false")
	t.Setenv("SECURL_CAPTCHA_PROVIDER", "none")
	t.Setenv("SECURL_CREATE_CAPTCHA_REQUIRED", "false")
}

func unixSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "securl-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return filepath.Join(directory, "s.sock")
}

type trackingRepository struct {
	store.Repository
	closed    atomic.Bool
	closeDone chan struct{}
	closeOnce sync.Once
}

func newTrackingRepository() *trackingRepository {
	return &trackingRepository{
		Repository: memory.New(),
		closeDone:  make(chan struct{}),
	}
}

func (repository *trackingRepository) Close() {
	repository.closeOnce.Do(func() {
		repository.closed.Store(true)
		repository.Repository.Close()
		close(repository.closeDone)
	})
}

type blockingPingRepository struct {
	*trackingRepository
	pingStarted chan struct{}
	releasePing chan struct{}
	pingDone    chan struct{}
}

func (repository *blockingPingRepository) Ping(context.Context) error {
	close(repository.pingStarted)
	<-repository.releasePing
	close(repository.pingDone)
	return nil
}

type blockingCloseRepository struct {
	store.Repository
	closeStarted chan struct{}
	releaseClose chan struct{}
	closeDone    chan struct{}
}

func (repository *blockingCloseRepository) Close() {
	close(repository.closeStarted)
	<-repository.releaseClose
	repository.Repository.Close()
	close(repository.closeDone)
}

func TestHandlerTrackerSealWaitsForStartedHandlersAndRejectsLateRequests(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	tracker := newHandlerTracker(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
	}))
	firstDone := make(chan struct{})
	go func() {
		tracker.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		close(firstDone)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first handler did not start")
	}
	tracker.Seal()
	waitDone := make(chan struct{})
	go func() {
		tracker.Wait()
		close(waitDone)
	}()
	lateResponse := httptest.NewRecorder()
	tracker.ServeHTTP(lateResponse, httptest.NewRequest(http.MethodGet, "/", nil))
	if lateResponse.Code != http.StatusServiceUnavailable || calls.Load() != 1 {
		t.Fatalf("late status=%d calls=%d", lateResponse.Code, calls.Load())
	}
	select {
	case <-waitDone:
		t.Fatal("Wait returned before the started handler finished")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first handler did not finish")
	}
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after handler completion")
	}
}

func TestApplicationServesOnProvidedListener(t *testing.T) {
	setApplicationTestEnvironment(t)
	logger := zerolog.Nop()
	application, err := New(&logger)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- application.Serve(ctx, listener) }()

	if application.ListenAddress() == listener.Addr().String() {
		t.Fatal("test requires configured and provided listener addresses to differ")
	}
	healthContext, cancelHealth := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelHealth()
	if err := CheckHealth(
		healthContext, listener.Addr().Network(), listener.Addr().String(),
	); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("application did not shut down")
	}
}

func TestApplicationServesAndChecksHealthOverUnixSocket(t *testing.T) {
	setApplicationTestEnvironment(t)
	socketPath := unixSocketPath(t)
	t.Setenv("SECURL_HTTP_ADDR", "unix:"+socketPath)
	logger := zerolog.Nop()
	application, err := New(&logger)
	if err != nil {
		t.Fatal(err)
	}
	if application.ListenNetwork() != "unix" || application.ListenAddress() != socketPath {
		t.Fatalf("network=%q address=%q", application.ListenNetwork(), application.ListenAddress())
	}
	listener, err := net.Listen(application.ListenNetwork(), application.ListenAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- application.Serve(ctx, listener) }()

	healthContext, cancelHealth := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelHealth()
	if err := CheckHealth(
		healthContext, listener.Addr().Network(), listener.Addr().String(),
	); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("application did not shut down")
	}
}

func TestHealthCheckURLUsesReachableLoopbackAddress(t *testing.T) {
	tests := []struct {
		address  string
		expected string
	}{
		{address: ":8080", expected: "http://127.0.0.1:8080/readyz"},
		{address: "0.0.0.0:8081", expected: "http://127.0.0.1:8081/readyz"},
		{address: "[::]:8082", expected: "http://[::1]:8082/readyz"},
		{address: "127.0.0.2:8083", expected: "http://127.0.0.2:8083/readyz"},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			target, err := healthCheckURL(test.address)
			if err != nil {
				t.Fatal(err)
			}
			if target != test.expected {
				t.Fatalf("target=%q expected=%q", target, test.expected)
			}
		})
	}
}

func TestCheckHealthRequiresReadyResponse(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/readyz" {
					t.Fatalf("path=%q", request.URL.Path)
				}
				writer.WriteHeader(status)
			}))
			defer server.Close()
			err := CheckHealth(context.Background(), "tcp", strings.TrimPrefix(server.URL, "http://"))
			if status == http.StatusOK && err != nil {
				t.Fatal(err)
			}
			if status != http.StatusOK && err == nil {
				t.Fatal("unready response passed health check")
			}
		})
	}
}

func TestApplicationClosesRepositoryAfterSafeShutdown(t *testing.T) {
	setApplicationTestEnvironment(t)
	repository := newTrackingRepository()
	logger := zerolog.Nop()
	application, err := New(&logger)
	if err != nil {
		t.Fatal(err)
	}
	application.openRepository = func(context.Context) (store.Repository, error) {
		return repository, nil
	}
	application.shutdownTimeout = time.Second
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- application.Serve(ctx, listener) }()
	healthContext, cancelHealth := context.WithTimeout(context.Background(), time.Second)
	if err := CheckHealth(healthContext, listener.Addr().Network(), listener.Addr().String()); err != nil {
		cancelHealth()
		cancel()
		t.Fatal(err)
	}
	cancelHealth()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("application did not shut down")
	}
	if !repository.closed.Load() {
		t.Fatal("repository remained open after safe shutdown")
	}
}

func TestApplicationLeavesRepositoryOpenWhenHandlerOutlivesForcedShutdown(t *testing.T) {
	setApplicationTestEnvironment(t)
	repository := &blockingPingRepository{
		trackingRepository: newTrackingRepository(),
		pingStarted:        make(chan struct{}),
		releasePing:        make(chan struct{}),
		pingDone:           make(chan struct{}),
	}
	released := false
	defer func() {
		if !released {
			close(repository.releasePing)
		}
	}()
	logger := zerolog.Nop()
	application, err := New(&logger)
	if err != nil {
		t.Fatal(err)
	}
	application.openRepository = func(context.Context) (store.Repository, error) {
		return repository, nil
	}
	application.shutdownTimeout = 50 * time.Millisecond
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- application.Serve(ctx, listener) }()
	requestDone := make(chan error, 1)
	go func() {
		response, err := http.Get("http://" + listener.Addr().String() + "/readyz")
		if response != nil {
			response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-repository.pingStarted:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("readiness handler did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shutdown error=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("forced shutdown did not return")
	}
	if repository.closed.Load() {
		t.Fatal("repository closed while handler was still running")
	}
	select {
	case <-repository.pingDone:
		t.Fatal("forced connection close unexpectedly joined the handler")
	default:
	}
	close(repository.releasePing)
	released = true
	select {
	case <-repository.pingDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish after release")
	}
	select {
	case <-requestDone:
	case <-time.After(2 * time.Second):
		t.Fatal("client request did not finish")
	}
	select {
	case <-repository.closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("repository was not closed after handler completion")
	}
}

func TestApplicationBoundsBlockingRepositoryClose(t *testing.T) {
	setApplicationTestEnvironment(t)
	repository := &blockingCloseRepository{
		Repository:   memory.New(),
		closeStarted: make(chan struct{}),
		releaseClose: make(chan struct{}),
		closeDone:    make(chan struct{}),
	}
	released := false
	defer func() {
		if !released {
			close(repository.releaseClose)
		}
	}()
	logger := zerolog.Nop()
	application, err := New(&logger)
	if err != nil {
		t.Fatal(err)
	}
	application.openRepository = func(context.Context) (store.Repository, error) {
		return repository, nil
	}
	application.shutdownTimeout = 50 * time.Millisecond
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- application.Serve(ctx, listener) }()
	healthContext, cancelHealth := context.WithTimeout(context.Background(), time.Second)
	if err := CheckHealth(healthContext, listener.Addr().Network(), listener.Addr().String()); err != nil {
		cancelHealth()
		cancel()
		t.Fatal(err)
	}
	cancelHealth()
	started := time.Now()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shutdown error=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocking repository close was not bounded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("repository close exceeded shutdown bound: %s", elapsed)
	}
	select {
	case <-repository.closeStarted:
	default:
		t.Fatal("repository close was not attempted on safe shutdown")
	}
	close(repository.releaseClose)
	released = true
	select {
	case <-repository.closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("repository close did not finish after release")
	}
}

func TestShutdownApplicationBoundsCleanupWorkerWait(t *testing.T) {
	repository := newTrackingRepository()
	server := &http.Server{}
	handlers := newHandlerTracker(http.NotFoundHandler())
	workerDone := make(chan struct{})
	cancelCalled := false
	started := time.Now()
	err := shutdownApplication(
		server, handlers, func() { cancelCalled = true }, workerDone, repository, 25*time.Millisecond,
	)
	if !cancelCalled {
		t.Fatal("cleanup worker was not canceled")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown error=%v", err)
	}
	if repository.closed.Load() {
		t.Fatal("repository closed while cleanup worker was still running")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("worker wait was not bounded: %s", elapsed)
	}
	close(workerDone)
	select {
	case <-repository.closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("repository was not closed after worker completion")
	}
}
