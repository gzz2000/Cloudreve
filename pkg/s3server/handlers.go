package s3server

import (
	"encoding/xml"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager/entitysource"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/request"
	"github.com/gin-gonic/gin"
)

// handleListBuckets returns DAV accounts as S3 buckets for the authenticated user.
func handleListBuckets(c *gin.Context) {
	dep := dependency.FromContext(c)
	l := dep.Logger()
	user := inventory.UserFromContext(c)
	if user == nil || user.ID == 0 {
		c.Status(http.StatusUnauthorized)
		return
	}

	// Fetch all dav accounts for user
	davAccountClient := dep.DavAccountClient()
	l.Debug("S3 ListBuckets: user=%q uid=%d", user.Email, user.ID)
	res, err := davAccountClient.List(c, &inventory.ListDavAccountArgs{PaginationArgs: &inventory.PaginationArgs{UseCursorPagination: true, PageSize: 100}, UserID: user.ID})
	if err != nil {
		l.Debug("S3 ListBuckets: list dav accounts failed: %v", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	owner := Owner{ID: "", DisplayName: user.Email}
	result := ListAllMyBucketsResult{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/", Owner: owner}
	result.Buckets.Bucket = make([]Bucket, 0, len(res.Accounts))
	for _, a := range res.Accounts {
		result.Buckets.Bucket = append(result.Buckets.Bucket, Bucket{Name: a.Name, CreationDate: a.CreatedAt})
	}
	l.Debug("S3 ListBuckets: returning %d buckets", len(result.Buckets.Bucket))

	c.Header("Content-Type", "application/xml")
	_ = xml.NewEncoder(c.Writer).Encode(result)
}

// handleHeadBucket returns 200 if bucket exists for current user.
func handleHeadBucket(c *gin.Context) {
	_, _, _, err := getAccountContext(c)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.Status(http.StatusOK)
}

// handleListObjectsV2 lists objects/prefixes under a bucket.
func handleListObjectsV2(c *gin.Context) {
	acc, base, fm, err := getAccountContext(c)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}

	prefix := c.Query("prefix")
	delimiter := c.DefaultQuery("delimiter", "/")
	contToken := c.Query("continuation-token")
	maxKeys := 1000
	if mk := c.Query("max-keys"); mk != "" {
		if v, e := strconv.Atoi(mk); e == nil && v > 0 && v <= 1000 {
			maxKeys = v
		}
	}

	listUri := base
	if prefix != "" {
		listUri = listUri.JoinRaw(prefix)
	}

	file, real, err := fm.SharedAddressTranslation(c, listUri)
	if err != nil && !ent.IsNotFound(err) {
		c.Status(http.StatusInternalServerError)
		return
	}

	res := ListObjectsV2Result{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/", Name: BucketSlug(acc.Name), Prefix: prefix, MaxKeys: maxKeys}
	res.Contents = make([]Content, 0)
	res.CommonPrefixes = make([]Prefix, 0)

	if file != nil && file.Type() == types.FileTypeFile {
		etag, _ := etagForFile(c, fm, file)
		res.KeyCount = 1
		res.Contents = append(res.Contents, Content{
			Key:          strings.TrimPrefix(real.Rebase(file.Uri(false), base).PathTrimmed(), "/"),
			LastModified: file.UpdatedAt(),
			ETag:         etag,
			Size:         file.Size(),
			StorageClass: "STANDARD",
		})
		c.Header("Content-Type", "application/xml")
		_ = xml.NewEncoder(c.Writer).Encode(res)
		return
	}

	if file != nil && file.Type() == types.FileTypeFolder {
		_, listRes, err := fm.List(c, real, &manager.ListArgs{PageSize: maxKeys, PageToken: contToken})
		if err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		for _, f := range listRes.Files {
			if f.Type() == types.FileTypeFolder {
				p := strings.TrimPrefix(real.Rebase(f.Uri(false), base).PathTrimmed(), "/") + "/"
				if delimiter == "/" {
					res.CommonPrefixes = append(res.CommonPrefixes, Prefix{Prefix: p})
				}
				continue
			}
			etag, _ := etagForFile(c, fm, f)
			key := strings.TrimPrefix(real.Rebase(f.Uri(false), base).PathTrimmed(), "/")
			res.Contents = append(res.Contents, Content{Key: key, LastModified: f.UpdatedAt(), ETag: etag, Size: f.Size(), StorageClass: "STANDARD"})
		}
		res.KeyCount = len(res.Contents)
		if listRes.Pagination != nil && listRes.Pagination.NextPageToken != "" {
			res.IsTruncated = true
			res.NextContinuationToken = listRes.Pagination.NextPageToken
		}
	}

	c.Header("Content-Type", "application/xml")
	_ = xml.NewEncoder(c.Writer).Encode(res)
}

// handleGetObject streams object content.
func handleGetObject(c *gin.Context) {
	_, base, fm, err := getAccountContext(c)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	defer fm.Recycle()

	key := strings.TrimPrefix(c.Param("key"), "/")
	uri := base.JoinRaw(key)

	target, _, err := fm.SharedAddressTranslation(c, uri)
	if err != nil {
		if ent.IsNotFound(err) {
			c.Status(http.StatusNotFound)
			return
		}
		c.Status(http.StatusInternalServerError)
		return
	}

	if target == nil || target.Type() != types.FileTypeFile {
		c.Status(http.StatusNotFound)
		return
	}

	es, err := fm.GetEntitySource(c, target.PrimaryEntityID())
	if err != nil {
		if ent.IsNotFound(err) {
			c.Status(http.StatusNotFound)
			return
		}
		c.Status(http.StatusInternalServerError)
		return
	}
	defer es.Close()

	// Set S3-compatible headers that callers expect
	c.Header("Last-Modified", target.UpdatedAt().UTC().Format(http.TimeFormat))

	user := inventory.UserFromContext(c)
	es.Apply(entitysource.WithSpeedLimit(int64(user.Edges.Group.SpeedLimit)))
	// Always serve/proxy internally for S3 semantics.
	es.Serve(c.Writer, c.Request)
}

// handleHeadObject returns headers of object.
func handleHeadObject(c *gin.Context) {
	_, base, fm, err := getAccountContext(c)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	defer fm.Recycle()

	key := strings.TrimPrefix(c.Param("key"), "/")
	uri := base.JoinRaw(key)

	target, _, err := fm.SharedAddressTranslation(c, uri)
	if err != nil {
		if ent.IsNotFound(err) {
			c.Status(http.StatusNotFound)
			return
		}
		c.Status(http.StatusInternalServerError)
		return
	}

	if target == nil || target.Type() != types.FileTypeFile {
		c.Status(http.StatusNotFound)
		return
	}

	// Ensure Last-Modified header is set for AWS CLI expectations
	c.Header("Last-Modified", target.UpdatedAt().UTC().Format(http.TimeFormat))

	es, err := fm.GetEntitySource(c, target.PrimaryEntityID())
	if err != nil {
		if ent.IsNotFound(err) {
			c.Status(http.StatusNotFound)
			return
		}
		c.Status(http.StatusInternalServerError)
		return
	}
	defer es.Close()

	// EntitySource handles HEAD appropriately (headers only).
	es.Serve(c.Writer, c.Request)
}

// handlePutObject uploads or overwrites a single object.
func handlePutObject(c *gin.Context) {
	// Reject multipart/advanced via POST emulation headers
	if c.GetHeader("x-amz-copy-source") != "" || c.GetHeader("x-amz-meta-uuid") != "" {
		c.Status(http.StatusNotImplemented)
		return
	}

	_, base, _fm, err := getAccountContext(c)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	defer _fm.Recycle()

	key := strings.TrimPrefix(c.Param("key"), "/")
	uri := base.JoinRaw(key)

	// Prepare request body and length
	var rc request.LimitReaderCloser
	var fileSize int64
	if isAWSStreamingPayload(nil, c.Request.Header.Get) {
		// Use decoded content length and strip aws-chunked frames
		decoded := c.Request.Header.Get("X-Amz-Decoded-Content-Length")
		if decoded == "" {
			c.Status(http.StatusBadRequest)
			return
		}
		// Parse length
		var perr error
		fileSize, perr = strconv.ParseInt(decoded, 10, 64)
		if perr != nil || fileSize < 0 {
			c.Status(http.StatusBadRequest)
			return
		}
		rc = request.NewLimitlessReaderCloser(newAWSChunkedReader(c.Request.Body))
	} else {
		var err error
		rc, fileSize, err = request.SniffContentLength(c.Request)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
	}

	fileData := &fs.UploadRequest{
		Props: &fs.UploadProps{
			Uri:  uri,
			Size: fileSize,
		},
		File: rc,
		Mode: fs.ModeOverwrite,
	}

	// Perform update/create
	m := manager.NewFileManager(dependency.FromContext(c), inventory.UserFromContext(c))
	defer m.Recycle()

	res, err := m.Update(c, fileData)
	if err != nil {
		if ent.IsNotFound(err) {
			c.Status(http.StatusNotFound)
			return
		}
		c.Status(http.StatusInternalServerError)
		return
	}

	etag, _ := etagForFile(c, m, res)
	c.Header("ETag", etag)
	c.Status(http.StatusOK)
}

// handleDeleteObject deletes an object.
func handleDeleteObject(c *gin.Context) {
	_, base, fm, err := getAccountContext(c)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	defer fm.Recycle()

	key := strings.TrimPrefix(c.Param("key"), "/")
	uri := base.JoinRaw(key)

	if err := fm.Delete(c, []*fs.URI{uri}); err != nil {
		if ent.IsNotFound(err) {
			c.Status(http.StatusNotFound)
			return
		}
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Status(http.StatusNoContent)
}

// handlePostObject handles unsupported operations like multipart upload.
func handlePostObject(c *gin.Context) {
	// Minimal S3 server does not support POST-based multipart or form uploads yet.
	c.Status(http.StatusNotImplemented)
}

// Helpers
func getAccountContext(c *gin.Context) (*ent.DavAccount, *fs.URI, manager.FileManager, error) {
	dep := dependency.FromContext(c)
	user := inventory.UserFromContext(c)
	if user == nil || user.ID == 0 {
		return nil, nil, nil, errors.New("unauthorized")
	}
	bucket := c.Param("bucket")
	davAccountClient := dep.DavAccountClient()
	res, err := davAccountClient.List(c, &inventory.ListDavAccountArgs{PaginationArgs: &inventory.PaginationArgs{UseCursorPagination: true, PageSize: 100}, UserID: user.ID})
	if err != nil {
		return nil, nil, nil, err
	}
	var target *ent.DavAccount
	for _, a := range res.Accounts {
		if a.Name == bucket {
			target = a
			break
		}
	}
	if target == nil {
		return nil, nil, nil, errors.New("bucket not found")
	}
	base, err := fs.NewUriFromString(target.URI)
	if err != nil {
		return nil, nil, nil, err
	}
	fm := manager.NewFileManager(dep, user)
	return target, base, fm, nil
}

func getAccountContextForBucket(c *gin.Context, bucket string) (*ent.DavAccount, *fs.URI, manager.FileManager, error) {
	dep := dependency.FromContext(c)
	user := inventory.UserFromContext(c)
	if user == nil || user.ID == 0 {
		return nil, nil, nil, errors.New("unauthorized")
	}
	davAccountClient := dep.DavAccountClient()
	res, err := davAccountClient.List(c, &inventory.ListDavAccountArgs{PaginationArgs: &inventory.PaginationArgs{UseCursorPagination: true, PageSize: 100}, UserID: user.ID})
	if err != nil {
		return nil, nil, nil, err
	}
	var target *ent.DavAccount
	for _, a := range res.Accounts {
		if BucketSlug(a.Name) == bucket {
			target = a
			break
		}
	}
	if target == nil {
		return nil, nil, nil, errors.New("bucket not found")
	}
	base, err := fs.NewUriFromString(target.URI)
	if err != nil {
		return nil, nil, nil, err
	}
	fm := manager.NewFileManager(dep, user)
	return target, base, fm, nil
}

func etagForFile(c *gin.Context, fm manager.FileManager, f fs.File) (string, error) {
	h := dependency.FromContext(c).HashIDEncoder()
	return `"` + hashid.EncodeEntityID(h, f.PrimaryEntityID()) + `"`, nil
}
