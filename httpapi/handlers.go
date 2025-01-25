package httpapi

import (
    "encoding/json"
    "fmt"
    "net/http"
    "sync"
    "time"

    "github.com/go-playground/validator/v10"
    "github.com/sirupsen/logrus"
    "github.com/ajadi/NodeGoDNS/backup"
    "github.com/ajadi/NodeGoDNS/models"
    "github.com/ajadi/NodeGoDNS/utils"
)

// HTTPAPI holds references to zones, backup, SSE, etc.
type HTTPAPI struct {
    Zones        map[string]models.Zone
    ZonesMutex   *sync.RWMutex
    BackupSvc    *backup.BackupService
    SaveZones    func() error
    NotifyUpdate func(action, zoneName string)
    SSEHub       *SSEHub
    Validate     *validator.Validate
}

// NewHTTPAPI constructs an HTTP API for NodeGoDNS.
func NewHTTPAPI(
    zones map[string]models.Zone,
    zonesMutex *sync.RWMutex,
    backupSvc *backup.BackupService,
    saveZones func() error,
    notifyUpdate func(action, zoneName string),
) *HTTPAPI {
    validate := validator.New()
    validate.RegisterValidation("hostname", func(fl validator.FieldLevel) bool {
        name := fl.Field().String()
        // Could do a more advanced check, for now just length
        return len(name) > 0
    })

    hub := NewSSEHub()
    go hub.Run()

    return &HTTPAPI{
        Zones:        zones,
        ZonesMutex:   zonesMutex,
        BackupSvc:    backupSvc,
        SaveZones:    saveZones,
        NotifyUpdate: notifyUpdate,
        SSEHub:       hub,
        Validate:     validate,
    }
}

// HandleZones routes GET/POST/PUT/DELETE requests for zone management.
func (api *HTTPAPI) HandleZones(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        api.GetZones(w, r)
    case http.MethodPost:
        api.CreateZone(w, r)
    case http.MethodPut:
        api.UpdateZone(w, r)
    case http.MethodDelete:
        api.DeleteZone(w, r)
    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

// GetZones returns a JSON map of all zones.
func (api *HTTPAPI) GetZones(w http.ResponseWriter, r *http.Request) {
    api.ZonesMutex.RLock()
    defer api.ZonesMutex.RUnlock()

    response, err := json.MarshalIndent(api.Zones, "", "  ")
    if err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Error("Error serializing zones")
        http.Error(w, "Error serializing zones", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    _, _ = w.Write(response)
}

// CreateZone creates a new zone from JSON body, name=? query param.
func (api *HTTPAPI) CreateZone(w http.ResponseWriter, r *http.Request) {
    var newZone models.Zone
    if err := json.NewDecoder(r.Body).Decode(&newZone); err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Warn("Invalid data in zone creation request")
        http.Error(w, "Invalid data", http.StatusBadRequest)
        return
    }

    // Validate
    if err := api.Validate.Struct(newZone); err != nil {
        validationErrors := err.(validator.ValidationErrors)
        errorsMap := make(map[string]string)
        for _, fieldErr := range validationErrors {
            errorsMap[fieldErr.Field()] = fieldErr.Tag()
        }
        resp, _ := json.Marshal(map[string]interface{}{
            "error":   "Invalid data",
            "details": errorsMap,
        })
        logrus.WithFields(logrus.Fields{"details": errorsMap}).
            Warn("Validation error during zone creation")
        http.Error(w, string(resp), http.StatusBadRequest)
        return
    }

    zoneName := r.URL.Query().Get("name")
    if zoneName == "" {
        logrus.Warn("Zone name not provided during creation")
        http.Error(w, "Zone name not provided", http.StatusBadRequest)
        return
    }

    api.ZonesMutex.Lock()
    defer api.ZonesMutex.Unlock()

    if _, exists := api.Zones[zoneName]; exists {
        logrus.WithFields(logrus.Fields{"zone": zoneName}).Warn("Attempt to create an existing zone")
        http.Error(w, "Zone already exists", http.StatusConflict)
        return
    }

    if newZone.SOA.Serial == 0 {
        newZone.SOA.Serial = uint32(time.Now().Unix())
    }

    api.Zones[zoneName] = newZone
    if err := api.SaveZones(); err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Error("Error saving zones")
        http.Error(w, "Error saving zones", http.StatusInternalServerError)
        return
    }

    if err := api.BackupSvc.PerformBackup("config/dns_config.json", "keys/zsk.pem", "keys/ksk.pem"); err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Error("Error performing backup after zone creation")
        http.Error(w, "Error performing backup", http.StatusInternalServerError)
        return
    }

    api.NotifyUpdate("Created", zoneName)
    api.SSEHub.Broadcast(fmt.Sprintf("Created: %s", zoneName))

    logrus.WithFields(logrus.Fields{"zone": zoneName}).Info("Zone created successfully (NodeGoDNS)")
    w.WriteHeader(http.StatusCreated)
}

// UpdateZone updates an existing zone by ?name query param.
func (api *HTTPAPI) UpdateZone(w http.ResponseWriter, r *http.Request) {
    var updatedZone models.Zone
    if err := json.NewDecoder(r.Body).Decode(&updatedZone); err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Warn("Invalid data in zone update request")
        http.Error(w, "Invalid data", http.StatusBadRequest)
        return
    }

    if err := api.Validate.Struct(updatedZone); err != nil {
        validationErrors := err.(validator.ValidationErrors)
        errorsMap := make(map[string]string)
        for _, fieldErr := range validationErrors {
            errorsMap[fieldErr.Field()] = fieldErr.Tag()
        }
        resp, _ := json.Marshal(map[string]interface{}{
            "error":   "Invalid data",
            "details": errorsMap,
        })
        logrus.WithFields(logrus.Fields{"details": errorsMap}).Warn("Validation error during zone update")
        http.Error(w, string(resp), http.StatusBadRequest)
        return
    }

    zoneName := r.URL.Query().Get("name")
    if zoneName == "" {
        logrus.Warn("Zone name not provided during update")
        http.Error(w, "Zone name not provided", http.StatusBadRequest)
        return
    }

    api.ZonesMutex.Lock()
    defer api.ZonesMutex.Unlock()

    if _, exists := api.Zones[zoneName]; !exists {
        logrus.WithFields(logrus.Fields{"zone": zoneName}).Warn("Attempt to update a non-existent zone")
        http.Error(w, "Zone not found", http.StatusNotFound)
        return
    }

    updatedZone.SOA.Serial = api.Zones[zoneName].SOA.Serial + 1
    api.Zones[zoneName] = updatedZone

    if err := api.SaveZones(); err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Error("Error saving zones")
        http.Error(w, "Error saving zones", http.StatusInternalServerError)
        return
    }

    if err := api.BackupSvc.PerformBackup("config/dns_config.json", "keys/zsk.pem", "keys/ksk.pem"); err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Error("Error performing backup after zone update")
        http.Error(w, "Error performing backup", http.StatusInternalServerError)
        return
    }

    api.NotifyUpdate("Updated", zoneName)
    api.SSEHub.Broadcast(fmt.Sprintf("Updated: %s", zoneName))

    logrus.WithFields(logrus.Fields{"zone": zoneName}).Info("Zone updated successfully (NodeGoDNS)")
    w.WriteHeader(http.StatusOK)
}

// DeleteZone removes an existing zone by ?name query param.
func (api *HTTPAPI) DeleteZone(w http.ResponseWriter, r *http.Request) {
    zoneName := r.URL.Query().Get("name")
    if zoneName == "" {
        logrus.Warn("Zone name not provided during deletion")
        http.Error(w, "Zone name not provided", http.StatusBadRequest)
        return
    }

    api.ZonesMutex.Lock()
    defer api.ZonesMutex.Unlock()

    if _, exists := api.Zones[zoneName]; !exists {
        logrus.WithFields(logrus.Fields{"zone": zoneName}).Warn("Attempt to delete a non-existent zone")
        http.Error(w, "Zone not found", http.StatusNotFound)
        return
    }

    delete(api.Zones, zoneName)
    if err := api.SaveZones(); err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Error("Error saving zones")
        http.Error(w, "Error saving zones", http.StatusInternalServerError)
        return
    }

    if err := api.BackupSvc.PerformBackup("config/dns_config.json", "keys/zsk.pem", "keys/ksk.pem"); err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Error("Error performing backup after zone deletion")
        http.Error(w, "Error performing backup", http.StatusInternalServerError)
        return
    }

    api.NotifyUpdate("Deleted", zoneName)
    api.SSEHub.Broadcast(fmt.Sprintf("Deleted: %s", zoneName))

    logrus.WithFields(logrus.Fields{"zone": zoneName}).Info("Zone deleted successfully (NodeGoDNS)")
    w.WriteHeader(http.StatusOK)
}

// HandleBackup processes backup (POST) or restore-latest (DELETE).
func (api *HTTPAPI) HandleBackup(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodPost:
        // Perform a new backup
        if err := api.BackupSvc.PerformBackup("config/dns_config.json", "keys/zsk.pem", "keys/ksk.pem"); err != nil {
            logrus.WithFields(logrus.Fields{"error": err}).Error("Error performing backup")
            http.Error(w, "Error performing backup", http.StatusInternalServerError)
            return
        }
        logrus.Info("Backup performed successfully (NodeGoDNS)")
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte("Backup performed successfully"))

    case http.MethodDelete:
        // Restore from the latest backup
        backupName, err := api.BackupSvc.GetLatestBackup("dns_config_")
        if err != nil {
            logrus.WithFields(logrus.Fields{"error": err}).Error("Error retrieving the latest backup")
            http.Error(w, "Error restoring from backup", http.StatusInternalServerError)
            return
        }

        if err := api.BackupSvc.PerformRestore("config/dns_config.json", "keys/zsk.pem", "keys/ksk.pem", backupName); err != nil {
            logrus.WithFields(logrus.Fields{"backup": backupName, "error": err}).
                Error("Error restoring from backup")
            http.Error(w, "Error restoring from backup", http.StatusInternalServerError)
            return
        }

        logrus.Info("Restore from backup performed successfully (NodeGoDNS)")
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte("Restore from backup performed successfully"))

    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

// HandleRestoreSpecificBackup restores from ?backup=<name>
func (api *HTTPAPI) HandleRestoreSpecificBackup(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    backupName := r.URL.Query().Get("backup")
    if backupName == "" {
        logrus.Warn("Backup name not provided for restoration")
        http.Error(w, "Backup name not provided", http.StatusBadRequest)
        return
    }

    if err := api.BackupSvc.PerformRestore("config/dns_config.json", "keys/zsk.pem", "keys/ksk.pem", backupName); err != nil {
        logrus.WithFields(logrus.Fields{"backup": backupName, "error": err}).
            Error("Error restoring from specific backup")
        http.Error(w, "Error restoring from backup", http.StatusInternalServerError)
        return
    }

    logrus.WithFields(logrus.Fields{"backup": backupName}).
        Info("Restoration from specific backup performed successfully (NodeGoDNS)")
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte("Restoration from specific backup performed successfully"))
}
