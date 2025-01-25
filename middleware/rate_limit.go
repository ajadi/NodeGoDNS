package middleware

import (
    "net/http"
    "time"

    "golang.org/x/time/rate"
    "github.com/sirupsen/logrus"
)

// RateLimiterMiddleware enforces a simple rate limit of 100 requests per minute.
func RateLimiterMiddleware(next http.Handler) http.Handler {
    limiter := rate.NewLimiter(rate.Every(time.Minute/100), 100)
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if err := limiter.Wait(r.Context()); err != nil {
            logrus.WithFields(logrus.Fields{"error": err, "ip": r.RemoteAddr}).
                Warn("Rate limit exceeded")
            http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
            return
        }
        next.ServeHTTP(w, r)
    })
}
