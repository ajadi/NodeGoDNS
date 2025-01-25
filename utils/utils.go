package utils

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"
    "strings"
    "sync"

    "github.com/sirupsen/logrus"
    "github.com/ajadi/NodeGoDNS/models"
)

// GenerateRSAKey creates an RSA private key of the given bit size.
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
    return rsa.GenerateKey(rand.Reader, bits)
}

// SavePrivateKey writes an RSA private key to a PEM file.
func SavePrivateKey(path string, key *rsa.PrivateKey) error {
    keyFile, err := os.Create(path)
    if err != nil {
        return err
    }
    defer keyFile.Close()

    keyBytes := x509.MarshalPKCS1PrivateKey(key)
    pemBlock := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: keyBytes,
    }
    return pem.Encode(keyFile, pemBlock)
}

// LoadPrivateKey loads an RSA private key from a PEM file.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(data)
    if block == nil || block.Type != "RSA PRIVATE KEY" {
        return nil, fmt.Errorf("failed to decode PEM block containing private key")
    }
    key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    return key, nil
}

// PublicKey returns the base64-encoded public key part of an RSA key.
func PublicKey(pub *rsa.PublicKey) string {
    pubASN1, err := x509.MarshalPKIXPublicKey(pub)
    if err != nil {
        return ""
    }
    return base64.StdEncoding.EncodeToString(pubASN1)
}

// LoadZones loads all zones from JSON files in zonesDir.
func LoadZones(zones map[string]models.Zone, mutex *sync.RWMutex, zonesDir string) error {
    files, err := ioutil.ReadDir(zonesDir)
    if err != nil {
        return err
    }

    for _, file := range files {
        if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
            continue
        }
        path := filepath.Join(zonesDir, file.Name())
        data, err := ioutil.ReadFile(path)
        if err != nil {
            logrus.WithFields(logrus.Fields{"error": err, "file": path}).
                Error("Failed to read zone file")
            continue
        }
        var zone models.Zone
        if err := json.Unmarshal(data, &zone); err != nil {
            logrus.WithFields(logrus.Fields{"error": err, "file": path}).
                Error("Failed to unmarshal zone file")
            continue
        }
        zoneName := strings.TrimSuffix(file.Name(), ".json")
        mutex.Lock()
        zones[zoneName] = zone
        mutex.Unlock()

        logrus.WithFields(logrus.Fields{"zone": zoneName, "file": path}).
            Info("Zone loaded successfully")
    }
    return nil
}

// SaveZones saves all zones to JSON files in zonesDir.
func SaveZones(zones map[string]models.Zone, mutex *sync.RWMutex, zonesDir string) error {
    mutex.RLock()
    defer mutex.RUnlock()

    for zoneName, zone := range zones {
        path := filepath.Join(zonesDir, zoneName+".json")
        data, err := json.MarshalIndent(zone, "", "  ")
        if err != nil {
            logrus.WithFields(logrus.Fields{"error": err, "zone": zoneName}).
                Error("Failed to marshal zone data")
            continue
        }
        if err := ioutil.WriteFile(path, data, 0644); err != nil {
            logrus.WithFields(logrus.Fields{"error": err, "file": path}).
                Error("Failed to write zone file")
            continue
        }
        logrus.WithFields(logrus.Fields{"zone": zoneName, "file": path}).
            Info("Zone saved successfully")
    }
    return nil
}

// IsSubDomain checks if domain is a subdomain of zone.
func IsSubDomain(zone, domain string) bool {
    return strings.HasSuffix(domain, zone)
}

// UpdateSerial increments the zone's SOA serial.
func UpdateSerial(zone *models.Zone) {
    zone.SOA.Serial++
}
