package tests

import (
    "database/sql"
    "os"
    "testing"

    "github.com/ajadi/NodeGoDNS/auth"
    _ "github.com/lib/pq"
)

// TestAuthService checks basic registration and authentication.
func TestAuthService(t *testing.T) {
    db, err := sql.Open("postgres", "user=postgres password=postgres dbname=nodegodns_test sslmode=disable")
    if err != nil {
        t.Fatalf("Failed to connect to test DB: %v", err)
    }
    defer db.Close()

    _, _ = db.Exec("DELETE FROM users")

    svc := auth.NewAuthService(db, "testsecret")

    err = svc.RegisterUser("testuser", "testpassword")
    if err != nil {
        t.Fatalf("Error registering user: %v", err)
    }

    ok, err := svc.Authenticate("testuser", "testpassword")
    if err != nil {
        t.Fatalf("Error authenticating user: %v", err)
    }
    if !ok {
        t.Error("Expected user to be authenticated")
    }

    ok, err = svc.Authenticate("testuser", "wrongpass")
    if err != nil {
        t.Fatalf("Error authenticating user: %v", err)
    }
    if ok {
        t.Error("User should NOT authenticate with wrong password")
    }

    token, err := svc.GenerateToken("testuser")
    if err != nil {
        t.Fatalf("Error generating token: %v", err)
    }
    if token == "" {
        t.Error("Token should not be empty")
    }
}

func TestMain(m *testing.M) {
    code := m.Run()
    os.Exit(code)
}
