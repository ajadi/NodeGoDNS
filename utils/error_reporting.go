package utils

import (
    "time"

    "github.com/getsentry/sentry-go"
    "github.com/sirupsen/logrus"
)

// InitializeSentry sets up Sentry if SENTRY_DSN is provided via env.
func InitializeSentry(dsn string) {
    if dsn == "" {
        logrus.Warn("SENTRY_DSN is empty; Sentry not initialized.")
        return
    }
    err := sentry.Init(sentry.ClientOptions{Dsn: dsn})
    if err != nil {
        logrus.Fatalf("sentry.Init error: %s", err)
    }
}

// CaptureError reports an error to Sentry.
func CaptureError(err error) {
    if err == nil {
        return
    }
    sentry.CaptureException(err)
    sentry.Flush(2 * time.Second)
}
