package admin

import (
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/pkg/backup"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
)

// AdminRunColdBackup enqueues a cold backup task manually.
func AdminRunColdBackup(c *gin.Context) (any, error) {
	dep := dependency.FromContext(c)
	// create task
	t, err := backup.NewColdBackupTask(c)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeInternalSetting, "Failed to create cold backup task", err)
	}
	if err := dep.IoIntenseQueue(c).QueueTask(c, t); err != nil {
		return nil, serializer.NewError(serializer.CodeInternalSetting, "Failed to queue cold backup task", err)
	}
	return gin.H{"ok": true}, nil
}

