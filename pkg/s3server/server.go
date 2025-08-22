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
		handlePutObject(c)
		return

	case http.MethodDelete:
		handleDeleteObject(c)
		return

	case http.MethodPost:
		// Multipart and advanced ops are not supported in minimal S3 server.
		c.Status(http.StatusNotImplemented)
		return
	}

	// Method not supported
	c.Status(http.StatusMethodNotAllowed)
}
