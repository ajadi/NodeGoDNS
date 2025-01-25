package backup

import (
    "fmt"
    "io"
    "io/ioutil"
    "os"
    "path/filepath"
    "sort"
    "strings"
    "time"

    "github.com/sirupsen/logrus"
)

// BackupService manages backups of zones and keys.
type BackupService struct {
    BackupDir      string
    ZonesBackupDir string
    KeysBackupDir  string
    MaxBackups     int
}

// NewBackupService initializes a BackupService with specified directories.
func NewBackupService(backupDir, zonesBackupDir, keysBackupDir string, maxBackups int) *BackupService {
    return &BackupService{
        BackupDir:      backupDir,
        ZonesBackupDir: zonesBackupDir,
        KeysBackupDir:  keysBackupDir,
        MaxBackups:     maxBackups,
    }
}

// PerformBackup copies the zone config and key files, then rotates old backups.
func (b *BackupService) PerformBackup(configFile, zskFile, kskFile string) error {
    timestamp := time.Now().Format("20060102T150405")
    backupName := fmt.Sprintf("backup_%s", timestamp)

    dirs := []string{b.ZonesBackupDir, b.KeysBackupDir}
    for _, dir := range dirs {
        if err := os.MkdirAll(dir, 0755); err != nil {
            logrus.WithFields(logrus.Fields{"error": err, "dir": dir}).
                Error("Failed to create backup directory")
            return err
        }
    }

    backupZonesPath := filepath.Join(b.ZonesBackupDir, fmt.Sprintf("dns_config_%s.json", timestamp))
    if err := copyFile(configFile, backupZonesPath); err != nil {
        logrus.WithFields(logrus.Fields{"source": configFile, "dest": backupZonesPath, "error": err}).
            Error("Error backing up zone configuration")
        return err
    }

    backupZSKPath := filepath.Join(b.KeysBackupDir, fmt.Sprintf("zsk_%s.pem", timestamp))
    if err := copyFile(zskFile, backupZSKPath); err != nil {
        logrus.WithFields(logrus.Fields{"source": zskFile, "dest": backupZSKPath, "error": err}).
            Error("Error backing up ZSK")
        return err
    }

    backupKSKPath := filepath.Join(b.KeysBackupDir, fmt.Sprintf("ksk_%s.pem", timestamp))
    if err := copyFile(kskFile, backupKSKPath); err != nil {
        logrus.WithFields(logrus.Fields{"source": kskFile, "dest": backupKSKPath, "error": err}).
            Error("Error backing up KSK")
        return err
    }

    // Rotate old backups
    if err := b.rotateBackups(b.ZonesBackupDir, "dns_config_", b.MaxBackups); err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Error("Error rotating zone backups")
    }
    if err := b.rotateBackups(b.KeysBackupDir, "zsk_", b.MaxBackups); err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Error("Error rotating ZSK backups")
    }
    if err := b.rotateBackups(b.KeysBackupDir, "ksk_", b.MaxBackups); err != nil {
        logrus.WithFields(logrus.Fields{"error": err}).Error("Error rotating KSK backups")
    }

    logrus.WithFields(logrus.Fields{"backup_name": backupName}).
        Info("Backup completed successfully")
    return nil
}

// PerformRestore restores config and keys from a given backup name.
func (b *BackupService) PerformRestore(configFile, zskFile, kskFile, backupName string) error {
    zonesBackupFile := filepath.Join(b.ZonesBackupDir, backupName)
    zskBackupFile := filepath.Join(b.KeysBackupDir, fmt.Sprintf("zsk_%s.pem", strings.TrimPrefix(backupName, "dns_config_")))
    kskBackupFile := filepath.Join(b.KeysBackupDir, fmt.Sprintf("ksk_%s.pem", strings.TrimPrefix(backupName, "dns_config_")))

    files := []string{zonesBackupFile, zskBackupFile, kskBackupFile}
    for _, file := range files {
        if _, err := os.Stat(file); os.IsNotExist(err) {
            logrus.WithFields(logrus.Fields{"file": file, "error": err}).
                Warn("Specified backup does not exist")
            return err
        }
    }

    if err := copyFile(zonesBackupFile, configFile); err != nil {
        logrus.WithFields(logrus.Fields{"source": zonesBackupFile, "dest": configFile, "error": err}).
            Error("Error restoring zone configuration from backup")
        return err
    }
    if err := copyFile(zskBackupFile, zskFile); err != nil {
        logrus.WithFields(logrus.Fields{"source": zskBackupFile, "dest": zskFile, "error": err}).
            Error("Error restoring ZSK from backup")
        return err
    }
    if err := copyFile(kskBackupFile, kskFile); err != nil {
        logrus.WithFields(logrus.Fields{"source": kskBackupFile, "dest": kskFile, "error": err}).
            Error("Error restoring KSK from backup")
        return err
    }

    logrus.WithFields(logrus.Fields{"backup": backupName}).
        Info("Restore from backup completed successfully")
    return nil
}

// GetLatestBackup finds the newest backup with prefix e.g. "dns_config_".
func (b *BackupService) GetLatestBackup(prefix string) (string, error) {
    files, err := ioutil.ReadDir(b.ZonesBackupDir)
    if err != nil {
        return "", err
    }
    var backups []os.FileInfo
    for _, file := range files {
        if strings.HasPrefix(file.Name(), prefix) {
            backups = append(backups, file)
        }
    }
    if len(backups) == 0 {
        return "", fmt.Errorf("no available backups with prefix %s", prefix)
    }
    sort.Slice(backups, func(i, j int) bool {
        return backups[i].ModTime().After(backups[j].ModTime())
    })
    return backups[0].Name(), nil
}

// rotateBackups removes old backups exceeding the limit.
func (b *BackupService) rotateBackups(dir, prefix string, max int) error {
    files, err := ioutil.ReadDir(dir)
    if err != nil {
        return err
    }
    var backups []os.FileInfo
    for _, file := range files {
        if strings.HasPrefix(file.Name(), prefix) {
            backups = append(backups, file)
        }
    }
    sort.Slice(backups, func(i, j int) bool {
        return backups[i].ModTime().After(backups[j].ModTime())
    })

    for i, file := range backups {
        if i >= max {
            err := os.Remove(filepath.Join(dir, file.Name()))
            if err != nil {
                logrus.WithFields(logrus.Fields{"file": file.Name(), "error": err}).
                    Error("Error removing old backup")
            } else {
                logrus.WithFields(logrus.Fields{"file": file.Name()}).
                    Info("Old backup removed")
            }
        }
    }
    return nil
}

// copyFile is a helper to copy src to dest.
func copyFile(src, dest string) error {
    sourceFile, err := os.Open(src)
    if err != nil {
        return err
    }
    defer sourceFile.Close()

    destFile, err := os.Create(dest)
    if err != nil {
        return err
    }
    defer destFile.Close()

    if _, err = io.Copy(destFile, sourceFile); err != nil {
        return err
    }
    fi, err := os.Stat(src)
    if err != nil {
        return err
    }
    return os.Chmod(dest, fi.Mode())
}
