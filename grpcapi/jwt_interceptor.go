package grpcapi

import (
    "context"
    "fmt"
    "strings"

    "github.com/golang-jwt/jwt/v4"
    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/metadata"
    "google.golang.org/grpc/status"
)

// JWTInterceptor is a gRPC unary interceptor that validates JWT tokens in "Authorization: Bearer <token>" format.
func JWTInterceptor(jwtSecret []byte) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        md, ok := metadata.FromIncomingContext(ctx)
        if !ok {
            return nil, status.Errorf(codes.Unauthenticated, "metadata not provided")
        }

        authHeaders := md["authorization"]
        if len(authHeaders) == 0 {
            return nil, status.Errorf(codes.Unauthenticated, "authorization token not provided")
        }

        tokenString := ""
        for _, header := range authHeaders {
            if strings.HasPrefix(header, "Bearer ") {
                tokenString = strings.TrimPrefix(header, "Bearer ")
                break
            }
        }

        if tokenString == "" {
            return nil, status.Errorf(codes.Unauthenticated, "authorization token not provided")
        }

        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }
            return jwtSecret, nil
        })
        if err != nil || !token.Valid {
            return nil, status.Errorf(codes.Unauthenticated, "invalid authorization token")
        }

        return handler(ctx, req)
    }
}
