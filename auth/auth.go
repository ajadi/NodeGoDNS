package auth

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "time"

    "github.com/golang-jwt/jwt/v4"
    "github.com/sirupsen/logrus"
    "golang.org/x/crypto/bcrypt"
    _ "github.com/lib/pq"
)

// AuthService manages user registration and JWT-based auth.
type AuthService struct {
    db        *sql.DB
    jwtSecret []byte
    tokenTTL  time.Duration
}

// User is a local struct for reading user data from DB.
type User struct {
    ID       int
    Username string
    Password string // hashed
}

// NewAuthService creates a new AuthService with a given JWT secret.
func NewAuthService(db *sql.DB, secret string) *AuthService {
    return &AuthService{
        db:        db,
        jwtSecret: []byte(secret),
        tokenTTL:  time.Hour,
    }
}

// RegisterUser inserts a user into DB if not exists.
func (a *AuthService) RegisterUser(username, password string) error {
    var exists bool
    err := a.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", username).Scan(&exists)
    if err != nil {
        return fmt.Errorf("error checking if user exists: %w", err)
    }
    if exists {
        return fmt.Errorf("user already exists")
    }
    hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return fmt.Errorf("error hashing password: %w", err)
    }
    _, err = a.db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", username, string(hashed))
    if err != nil {
        return fmt.Errorf("error inserting user: %w", err)
    }
    logrus.WithFields(logrus.Fields{"username": username}).Info("New user registered")
    return nil
}

// Authenticate checks username+password against DB.
func (a *AuthService) Authenticate(username, password string) (bool, error) {
    var user User
    err := a.db.QueryRow("SELECT id, username, password FROM users WHERE username=$1", username).
        Scan(&user.ID, &user.Username, &user.Password)
    if err != nil {
        if err == sql.ErrNoRows {
            return false, nil
        }
        return false, fmt.Errorf("error querying user: %w", err)
    }
    if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
        return false, nil
    }
    return true, nil
}

// GenerateToken creates a JWT token for a valid user.
func (a *AuthService) GenerateToken(username string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "username": username,
        "exp":      time.Now().Add(a.tokenTTL).Unix(),
    })
    return token.SignedString(a.jwtSecret)
}

// Middleware checks for JWT in the Authorization header: "Bearer <token>"
func (a *AuthService) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authentication required", http.StatusUnauthorized)
            return
        }
        var tokenString string
        fmt.Sscanf(authHeader, "Bearer %s", &tokenString)

        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method")
            }
            return a.jwtSecret, nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }
        if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
            ctx := context.WithValue(r.Context(), "username", claims["username"])
            next.ServeHTTP(w, r.WithContext(ctx))
            return
        }
        http.Error(w, "Invalid token", http.StatusUnauthorized)
    })
}

// HandleLogin processes HTTP POST /login for user authentication.
func (a *AuthService) HandleLogin(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    var creds struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Warn("Invalid login data")
        http.Error(w, "Invalid data", http.StatusBadRequest)
        return
    }
    authenticated, err := a.Authenticate(creds.Username, creds.Password)
    if err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Error("Error authenticating user")
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    if !authenticated {
        logrus.WithFields(logrus.Fields{"username": creds.Username}).Warn("Invalid credentials")
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }
    token, err := a.GenerateToken(creds.Username)
    if err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Error("Error generating JWT token")
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }
    _ = json.NewEncoder(w).Encode(map[string]string{
        "token": token,
    })
}
