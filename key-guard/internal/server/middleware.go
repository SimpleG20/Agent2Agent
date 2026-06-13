package server

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// contextKey is a private type for context keys to avoid collisions.
type contextKey string

const requestIDKey contextKey = "request_id"

// withRequestID stores the request ID in the context.
func withRequestID(ctx context.Context, reqID string) context.Context {
	return context.WithValue(ctx, requestIDKey, reqID)
}

// getRequestID retrieves the request ID from the context.
func getRequestID(ctx context.Context) string {
	if reqID, ok := ctx.Value(requestIDKey).(string); ok {
		return reqID
	}
	return ""
}

var (
	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "keyguard_request_duration_seconds",
		Help:    "Duration of HTTP requests in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path", "status"})

	requestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "keyguard_requests_total",
		Help: "Total number of HTTP requests",
	}, []string{"method", "path", "status"})

	signTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "keyguard_sign_requests_total",
		Help: "Total number of sign requests by outcome",
	}, []string{"outcome"})

	activeRequests = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "keyguard_active_requests",
		Help: "Number of active HTTP requests",
	})
)

// RequestIDMiddleware injects or reads a request ID from the context.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = uuid.New().String()
		}
		w.Header().Set("X-Request-ID", reqID)
		next.ServeHTTP(w, r.WithContext(withRequestID(r.Context(), reqID)))
	})
}

// LoggingMiddleware logs each request with duration.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		duration := time.Since(start)
		reqID := getRequestID(r.Context())
		if reqID == "" {
			reqID = "-"
		}
		log.Printf("[%s] %s %s %d %s",
			reqID, r.Method, r.URL.Path, ww.Status(), duration)
	})
}

// MetricsMiddleware records Prometheus metrics for each request.
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activeRequests.Inc()
		defer activeRequests.Dec()

		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		status := http.StatusText(ww.Status())
		requestDuration.WithLabelValues(r.Method, r.URL.Path, status).Observe(
			time.Since(time.Now()).Seconds())
		requestTotal.WithLabelValues(r.Method, r.URL.Path, status).Inc()
	})
}

// RecoveryMiddleware catches panics and returns a 500 error.
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("PANIC: %v", rec)
				reqID := getRequestID(r.Context())
				writeError(w, http.StatusInternalServerError, "internal_error", reqID)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
