package s3server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ServeHTTP dispatches S3-compatible requests similar to WebDAV's single entry.
// It keeps behavior minimal and mirrors what WebDAV supports in this repo.
func ServeHTTP(c *gin.Context) {
	bucket := c.Param("bucket")
	key := c.Param("key")

	switch c.Request.Method {
	case http.MethodGet:
		if bucket == "" {
			handleListBuckets(c)
			return
		}
		if key == "" || key == "/" {
			// List or ListParts (multipart)
			if _, ok := c.GetQuery("uploadId"); ok {
				handleListParts(c)
				return
			}
			handleListObjectsV2(c)
			return
		}
		handleGetObject(c)
		return

	case http.MethodHead:
		if key == "" || key == "/" {
			handleHeadBucket(c)
			return
		}
		handleHeadObject(c)
		return

	case http.MethodPut:
		// Initiate multipart if ?uploads is present (some clients use PUT)
		if _, ok := c.GetQuery("uploads"); ok {
			handleInitiateMultipart(c)
			return
		}
		// UploadPart if uploadId & partNumber present
		if _, ok := c.GetQuery("uploadId"); ok {
			if _, ok2 := c.GetQuery("partNumber"); ok2 {
				handleUploadPart(c)
				return
			}
		}
		handlePutObject(c)
		return

	case http.MethodDelete:
		// AbortMultipartUpload
		if _, ok := c.GetQuery("uploadId"); ok {
			handleAbortMultipart(c)
			return
		}
		handleDeleteObject(c)
		return

	case http.MethodPost:
		// Initiate multipart (?uploads) or Complete (with uploadId)
		if _, ok := c.GetQuery("uploads"); ok {
			handleInitiateMultipart(c)
			return
		}
		if _, ok := c.GetQuery("uploadId"); ok {
			handleCompleteMultipart(c)
			return
		}
		c.Status(http.StatusNotImplemented)
		return
	}

	// Method not supported
	c.Status(http.StatusMethodNotAllowed)
}
