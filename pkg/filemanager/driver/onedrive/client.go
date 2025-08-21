package onedrive

import (
	"encoding/json"
	"context"
	"errors"
	"io"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/pkg/credmanager"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"

	"github.com/cloudreve/Cloudreve/v4/pkg/request"
)

var (
	// ErrAuthEndpoint 无法解析授权端点地址
	ErrAuthEndpoint = errors.New("failed to parse endpoint url")
	// ErrInvalidRefreshToken 上传策略无有效的RefreshToken
	ErrInvalidRefreshToken = errors.New("no valid refresh token in this policy")
	// ErrDeleteFile 无法删除文件
	ErrDeleteFile = errors.New("cannot delete file")
	// ErrClientCanceled 客户端取消操作
	ErrClientCanceled = errors.New("client canceled")
	// Desired thumb size not available
	ErrThumbSizeNotFound = errors.New("thumb size not found")
)

type Client interface {
	ListChildren(ctx context.Context, path string) ([]FileInfo, error)
	Meta(ctx context.Context, id string, path string) (*FileInfo, error)
	CreateUploadSession(ctx context.Context, dst string, opts ...Option) (string, error)
	GetSiteIDByURL(ctx context.Context, siteUrl string) (string, error)
	GetUploadSessionStatus(ctx context.Context, uploadURL string) (*UploadSessionResponse, error)
	Upload(ctx context.Context, file *fs.UploadRequest) error
	SimpleUpload(ctx context.Context, dst string, body io.Reader, size int64, opts ...Option) (*UploadResult, error)
	DeleteUploadSession(ctx context.Context, uploadURL string) error
	BatchDelete(ctx context.Context, dst []string) ([]string, error)
	GetThumbURL(ctx context.Context, dst string) (string, error)
	OAuthURL(ctx context.Context, scopes []string) string
	ObtainToken(ctx context.Context, opts ...Option) (*Credential, error)
	GetDriveQuota(ctx context.Context) (*DriveQuota, error)
}

// client OneDrive客户端
type client struct {
	endpoints  *endpoints
	policy     *ent.StoragePolicy
	credential credmanager.Credential

	httpClient request.Client
	cred       credmanager.CredManager
	l          logging.Logger
	settings   setting.Provider

	chunkSize int64
	// override credential key used with CredManager
	credentialKey string
}

// endpoints OneDrive客户端相关设置
type endpoints struct {
	oAuthEndpoints *oauthEndpoint
	endpointURL    string // 接口请求的基URL
	driverResource string // 要使用的驱动器
}

// NewClient 根据存储策略获取新的client
func NewClient(policy *ent.StoragePolicy, httpClient request.Client, cred credmanager.CredManager,
	l logging.Logger, settings setting.Provider, chunkSize int64) Client {
	return NewClientWithCredentialKey(policy, httpClient, cred, l, settings, chunkSize, "")
}

// NewClientWithCredentialKey creates a client with a custom credential key.
func NewClientWithCredentialKey(policy *ent.StoragePolicy, httpClient request.Client, cred credmanager.CredManager,
	l logging.Logger, settings setting.Provider, chunkSize int64, credentialKey string) Client {
	client := &client{
		endpoints: &endpoints{
			endpointURL:    policy.Server,
			driverResource: policy.Settings.OdDriver,
		},
		policy:     policy,
		httpClient: httpClient,
		cred:       cred,
		l:          l,
		settings:   settings,
		chunkSize:  chunkSize,
		credentialKey: credentialKey,
	}

	if client.endpoints.driverResource == "" {
		client.endpoints.driverResource = "me/drive"
	}

	oauthBase := getOAuthEndpoint(policy.Server)
	client.endpoints.oAuthEndpoints = oauthBase

	return client
}

// DriveQuota summarizes OneDrive quota numbers.
type DriveQuota struct {
	Total     int64 `json:"total"`
	Used      int64 `json:"used"`
	Remaining int64 `json:"remaining"`
}

// GetDriveQuota returns current drive quota info for the configured driver resource.
func (client *client) GetDriveQuota(ctx context.Context) (*DriveQuota, error) {
	// Ensure credential is valid
	if err := client.UpdateCredential(ctx); err != nil {
		return nil, err
	}

	// Build URL to "me/drive" (driverResource) without appending extra segments
	requestURL := client.getRequestURL("", WithDriverResource(true))
	res, err := client.requestWithStr(ctx, "GET", requestURL, "", 200)
	if err != nil {
		return nil, err
	}

	// Minimal struct for decoding quota
	var payload struct {
		Quota struct {
			Total     int64 `json:"total"`
			Used      int64 `json:"used"`
			Remaining int64 `json:"remaining"`
		} `json:"quota"`
	}
	if decodeErr := json.Unmarshal([]byte(res), &payload); decodeErr != nil {
		return nil, decodeErr
	}
	return &DriveQuota{Total: payload.Quota.Total, Used: payload.Quota.Used, Remaining: payload.Quota.Remaining}, nil
}
