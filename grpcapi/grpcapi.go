package grpcapi

import (
    "context"
    "crypto/rsa"
    "fmt"
    "net"
    "strings"
    "sync"
    "time"

    "github.com/golang-jwt/jwt/v4"
    "github.com/sirupsen/logrus"

    "github.com/ajadi/NodeGoDNS/backup"
    "github.com/ajadi/NodeGoDNS/grpcapi/proto"
    "github.com/ajadi/NodeGoDNS/models"

    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/metadata"
    "google.golang.org/grpc/status"
)

// ZoneSyncServer implements the gRPC zone synchronization service.
type ZoneSyncServer struct {
    proto.UnimplementedZoneSyncServiceServer
    Zones        map[string]models.Zone
    ZonesMutex   *sync.RWMutex
    BackupSvc    *backup.BackupService
    SaveZones    func() error
    NotifyUpdate func(action, zoneName string)
    JWTSecret    []byte
}

// NewZoneSyncServer creates a gRPC zone sync server with references to global data.
func NewZoneSyncServer(
    zones map[string]models.Zone,
    zonesMutex *sync.RWMutex,
    backupSvc *backup.BackupService,
    saveZones func() error,
    notifyUpdate func(action, zoneName string),
    jwtSecret []byte,
) *ZoneSyncServer {
    return &ZoneSyncServer{
        Zones:         zones,
        ZonesMutex:    zonesMutex,
        BackupSvc:     backupSvc,
        SaveZones:     saveZones,
        NotifyUpdate:  notifyUpdate,
        JWTSecret:     jwtSecret,
    }
}

// SyncZones handles the gRPC request to sync zones from a client.
func (s *ZoneSyncServer) SyncZones(ctx context.Context, req *proto.SyncZonesRequest) (*proto.SyncZonesResponse, error) {
    // Authenticate with JWT
    if err := s.authenticate(ctx); err != nil {
        return &proto.SyncZonesResponse{
            Success: false,
            Message: err.Error(),
        }, err
    }

    // Update zones
    s.ZonesMutex.Lock()
    defer s.ZonesMutex.Unlock()

    for zoneName, zoneData := range req.Zones {
        existingZone, exists := s.Zones[zoneName]
        if exists {
            zoneData.Soa.Serial = existingZone.SOA.Serial + 1
        } else {
            if zoneData.Soa.Serial == 0 {
                zoneData.Soa.Serial = uint32(time.Now().Unix())
            }
        }

        s.Zones[zoneName] = models.Zone{
            SOA:    models.SOA(zoneData.Soa),
            NS:     zoneData.Ns,
            A:      zoneData.A,
            AAAA:   zoneData.Aaaa,
            MX:     convertProtoMX(zoneData.Mx),
            TXT:    zoneData.Txt,
            CNAME:  zoneData.Cname,
            SRV:    convertProtoSRV(zoneData.Srv),
            PTR:    zoneData.Ptr,
            DNSKEY: existingZone.DNSKEY, // Preserve existing DNSKEY
            RRSIG:  []*models.RRSIG{},
        }
        s.NotifyUpdate("Updated", zoneName)
    }

    // Save zones
    if err := s.SaveZones(); err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).
            Error("Error saving zones after gRPC synchronization")
        return &proto.SyncZonesResponse{Success: false, Message: "Error saving zones"},
            status.Error(codes.Internal, "Error saving zones")
    }

    // Backup
    if err := s.BackupSvc.PerformBackup("config/dns_config.json", "keys/zsk.pem", "keys/ksk.pem"); err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).
            Error("Error performing backup after gRPC synchronization")
        return &proto.SyncZonesResponse{Success: false, Message: "Error performing backup"},
            status.Error(codes.Internal, "Error performing backup")
    }

    logrus.Info("Zones successfully synchronized via gRPC (NodeGoDNS)")
    return &proto.SyncZonesResponse{
        Success: true,
        Message: "Zones synchronized successfully",
    }, nil
}

func (s *ZoneSyncServer) authenticate(ctx context.Context) error {
    md, ok := metadata.FromIncomingContext(ctx)
    if !ok {
        return fmt.Errorf("metadata not provided")
    }
    authHeaders := md["authorization"]
    if len(authHeaders) == 0 {
        return fmt.Errorf("authorization token not provided")
    }

    tokenString := ""
    for _, header := range authHeaders {
        if strings.HasPrefix(header, "Bearer ") {
            tokenString = strings.TrimPrefix(header, "Bearer ")
            break
        }
    }
    if tokenString == "" {
        return fmt.Errorf("authorization token not provided")
    }

    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return s.JWTSecret, nil
    })
    if err != nil || !token.Valid {
        return fmt.Errorf("invalid authorization token")
    }
    return nil
}

func convertProtoMX(protoMX []*proto.MX) []models.MX {
    var mx []models.MX
    for _, p := range protoMX {
        mx = append(mx, models.MX{
            Priority: p.Priority,
            Target:   p.Target,
        })
    }
    return mx
}
func convertProtoSRV(protoSRV []*proto.SRV) []models.SRV {
    var srv []models.SRV
    for _, p := range protoSRV {
        srv = append(srv, models.SRV{
            Priority: p.Priority,
            Weight:   p.Weight,
            Port:     p.Port,
            Target:   p.Target,
        })
    }
    return srv
}

// StartGRPCServer starts the gRPC server with TLS and a JWT interceptor.
func StartGRPCServer(addr, certFile, keyFile string, server *ZoneSyncServer) (*grpc.Server, error) {
    creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
    if err != nil {
        return nil, fmt.Errorf("failed to load TLS certificates: %w", err)
    }

    grpcServer := grpc.NewServer(
        grpc.Creds(creds),
        grpc.UnaryInterceptor(JWTInterceptor(server.JWTSecret)),
    )
    proto.RegisterZoneSyncServiceServer(grpcServer, server)

    lis, err := net.Listen("tcp", addr)
    if err != nil {
        return nil, fmt.Errorf("failed to listen on address %s: %w", addr, err)
    }

    go func() {
        logrus.WithFields(logrus.Fields{"addr": addr}).Info("gRPC server started (NodeGoDNS)")
        if err := grpcServer.Serve(lis); err != nil {
            logrus.WithFields(logrus.Fields{"error": err, "addr": addr}).
                Fatal("gRPC server error")
        }
    }()

    return grpcServer, nil
}
