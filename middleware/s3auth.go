package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/s3server"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/pkg/util"
	"github.com/gin-gonic/gin"
)

// S3Auth authenticates S3 requests via SigV4 (header or presigned). Falls back to BasicAuth for compatibility.
func S3Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		dep := dependency.FromContext(c)
		userClient := dep.UserClient()
		l := dep.Logger()

		// Try SigV4 first
		var params *s3server.SigV4Params
		authz := c.GetHeader("Authorization")
		if strings.HasPrefix(authz, s3server.SigAlgorithm) {
			p, _ := s3server.ParseAuthorization(authz)
			params = p
		}
		if params == nil && c.Query("X-Amz-Algorithm") == s3server.SigAlgorithm {
			params = s3server.ParsePresigned(c.Request.URL.Query())
		}

		var expectedUser *ent.User
		var err error
		if params != nil {
			l.Debug("S3Auth: SigV4 detected. Bucket=%q AccessKey=%q SignedHeaders=%v", c.Param("bucket"), params.AccessKey, params.SignedHeaders)
			// AccessKeyId is email
			var bucketName *string
			if b := c.Param("bucket"); b != "" {
				bucketName = &b
			}
			var accs []*ent.DavAccount
			expectedUser, accs, err = userClient.GetActiveByDavS3Access(c, params.AccessKey, bucketName)
			if err != nil {
				l.Debug("S3Auth: user lookup failed for AccessKey=%q: %v", params.AccessKey, err)
				c.Status(http.StatusForbidden)
				c.Abort()
				return
			}
			if len(accs) == 0 {
				l.Debug("S3Auth: user lookup or DAV accounts missing for AccessKey=%q: %v", params.AccessKey, err)
				c.Status(http.StatusForbidden)
				c.Abort()
				return
			}
			bucket := c.Param("bucket")
			secrets := make([]string, 0)
			if bucket != "" {
				for _, a := range accs {
					if a.Name == bucket {
						secrets = append(secrets, a.Password)
						break
					}
				}
			} else {
				for _, a := range accs {
					secrets = append(secrets, a.Password)
				}
			}
			ok := false
			now := time.Now().UTC()
			for _, s := range secrets {
				if s3server.VerifySigV4(c.Request, params, s, now) {
					ok = true
					break
				}
			}
			if !ok {
				l.Debug("S3Auth: SigV4 verification failed for user=%q bucket=%q uri=%q", expectedUser.Email, bucket, c.Request.URL.String())
				c.Status(http.StatusForbidden)
				c.Abort()
				return
			}
		} else {
			l.Debug("S3Auth: falling back to BasicAuth for %q", c.Request.URL.String())
			// Fallback BasicAuth
			username, password, ok := c.Request.BasicAuth()
			if !ok {
				if c.Request.Method == http.MethodOptions {
					c.Next()
					return
				}
				c.Header("WWW-Authenticate", `Basic realm="cloudreve-s3"`)
				c.Status(http.StatusUnauthorized)
				c.Abort()
				return
			}
			expectedUser, err = userClient.GetActiveByDavAccount(c, username, password)
			if err != nil {
				l.Debug("S3Auth: BasicAuth failed for username=%q: %v", username, err)
				c.Status(http.StatusUnauthorized)
				c.Abort()
				return
			}
		}

		// Permission gate
		group, err := expectedUser.Edges.GroupOrErr()
		if err != nil {
			c.Status(http.StatusInternalServerError)
			c.Abort()
			return
		}
		if !group.Permissions.Enabled(int(types.GroupPermissionWebDAV)) {
			l.Debug("S3Auth: user %q lacks WebDAV permission.", expectedUser.Email)
			c.Status(http.StatusForbidden)
			c.Abort()
			return
		}

		// Read-only block on write methods
		if c.Param("bucket") != "" && (c.Request.Method == http.MethodDelete || c.Request.Method == http.MethodPut) {
			accs, _ := expectedUser.Edges.DavAccountsOrErr()
			for _, a := range accs {
				if a.Name == c.Param("bucket") && a.Options.Enabled(int(types.DavAccountReadOnly)) {
					l.Debug("S3Auth: write denied due to read-only account for user %q bucket=%q", expectedUser.Email, c.Param("bucket"))
					c.Status(http.StatusForbidden)
					c.Abort()
					return
				}
			}
		}

		util.WithValue(c, inventory.UserCtx{}, expectedUser)
		c.Next()
	}
}

// S3Error writes an S3-styled error in JSON envelope for now (MVP placeholder).
// Handlers should call this for structured errors if needed.
func S3Error(c *gin.Context, status int, code, message string, err error) {
	if err != nil {
		c.JSON(status, serializer.ErrWithDetails(c, serializer.CodeInternalSetting, message, err))
		return
	}
	c.String(status, message)
}
