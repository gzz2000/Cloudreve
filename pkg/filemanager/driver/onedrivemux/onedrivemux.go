package onedrivemux

import (
  "context"
  "fmt"
  "os"
  "time"

  "github.com/cloudreve/Cloudreve/v4/ent"
  "github.com/cloudreve/Cloudreve/v4/pkg/boolset"
  "github.com/cloudreve/Cloudreve/v4/pkg/conf"
  "github.com/cloudreve/Cloudreve/v4/pkg/credmanager"
  "github.com/cloudreve/Cloudreve/v4/application/dependency"
  "github.com/cloudreve/Cloudreve/v4/pkg/filemanager/driver"
  "github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
  "github.com/cloudreve/Cloudreve/v4/pkg/logging"
  "github.com/cloudreve/Cloudreve/v4/pkg/filemanager/driver/onedrive"
  "github.com/cloudreve/Cloudreve/v4/pkg/cluster/routes"
  "github.com/cloudreve/Cloudreve/v4/inventory/types"
  "github.com/cloudreve/Cloudreve/v4/pkg/setting"
  "strings"
  request "github.com/cloudreve/Cloudreve/v4/pkg/request"
)

type Driver struct {
	policy   *ent.StoragePolicy
	settings setting.Provider
	config   conf.ConfigProvider
	l        logging.Logger
	cred     credmanager.CredManager
}

var features = &boolset.BooleanSet{}

func init() {
	boolset.Sets(map[driver.HandlerCapability]bool{
		driver.HandlerCapabilityUploadSentinelRequired: true,
	}, features)
}

func New(_ context.Context, policy *ent.StoragePolicy, settings setting.Provider,
  config conf.ConfigProvider, l logging.Logger, cred credmanager.CredManager) (*Driver, error) {
	return &Driver{
		policy:   policy,
		settings: settings,
		config:   config,
		l:        l,
		cred:     cred,
	}, nil
}

func (d *Driver) Put(ctx context.Context, file *fs.UploadRequest) error {
  subID, inner := parseMuxPath(file.Props.SavePath)
  if subID < 0 || inner == "" {
    return fmt.Errorf("onedrivemux: invalid SavePath, missing acc/{id} prefix")
  }
  _, c, err := d.resolveSubClient(ctx, subID)
  if err != nil {
    return err
  }
  // Temporarily switch SavePath to inner path for OneDrive client
  orig := file.Props.SavePath
  file.Props.SavePath = inner
  defer func() { file.Props.SavePath = orig }()
  return c.Upload(ctx, file)
}

func (d *Driver) Delete(ctx context.Context, files ...string) ([]string, error) {
  // Group by subaccount
  type group struct{ inner []string }
  groups := make(map[int64]*group)
  failed := make([]string, 0)
  for _, f := range files {
    sid, inner := parseMuxPath(f)
    if sid < 0 || inner == "" {
      failed = append(failed, f)
      continue
    }
    if _, ok := groups[sid]; !ok {
      groups[sid] = &group{inner: make([]string, 0)}
    }
    groups[sid].inner = append(groups[sid].inner, inner)
  }

  for sid, g := range groups {
    _, c, err := d.resolveSubClient(ctx, sid)
    if err != nil {
      // all in group fail
      for _, inner := range g.inner {
        failed = append(failed, fmt.Sprintf("acc/%d/%s", sid, inner))
      }
      continue
    }
    notDeleted, err := c.BatchDelete(ctx, g.inner)
    if err != nil {
      for _, nd := range notDeleted {
        failed = append(failed, fmt.Sprintf("acc/%d/%s", sid, nd))
      }
    }
    // refresh quota for this subaccount regardless of partial failure
    _ = d.refreshQuota(ctx, sid, c)
  }
  if len(failed) > 0 {
    return failed, onedrive.ErrDeleteFile
  }
  return nil, nil
}

func (d *Driver) Open(ctx context.Context, path string) (*os.File, error) { return nil, fmt.Errorf("onedrivemux.Open not implemented") }

func (d *Driver) LocalPath(ctx context.Context, path string) string {
	return ""
}

func (d *Driver) Thumb(ctx context.Context, expire *time.Time, ext string, e fs.Entity) (string, error) {
  subID, inner := parseMuxPath(e.Source())
  if subID < 0 {
    return "", fmt.Errorf("invalid mux path")
  }
  _, c, err := d.resolveSubClient(ctx, subID)
  if err != nil {
    return "", err
  }
  url, err := c.GetThumbURL(ctx, inner)
  if err != nil {
    return "", err
  }
  return url, nil
}

func (d *Driver) Source(ctx context.Context, e fs.Entity, args *driver.GetSourceArgs) (string, error) {
  subID, inner := parseMuxPath(e.Source())
  if subID < 0 {
    return "", fmt.Errorf("invalid mux path")
  }
  _, c, err := d.resolveSubClient(ctx, subID)
  if err != nil {
    return "", err
  }
  info, err := c.Meta(ctx, "", inner)
  if err != nil {
    return "", err
  }
  return info.DownloadURL, nil
}

func (d *Driver) Token(ctx context.Context, uploadSession *fs.UploadSession, file *fs.UploadRequest) (*fs.UploadCredential, error) {
  subID, inner := parseMuxPath(file.Props.SavePath)
  if subID < 0 {
    // DBFS must determine subaccount and set SavePath prefix before entity creation
    return nil, fmt.Errorf("onedrivemux: invalid SavePath, missing acc/{id} prefix")
  }

  p, c, err := d.resolveSubClient(ctx, subID)
  if err != nil {
    return nil, err
  }

  // Generate callback same as onedrive
  siteURL := d.settings.SiteURL(setting.UseFirstSiteUrl(ctx))
  uploadSession.Callback = routes.MasterSlaveCallbackUrl(siteURL, types.PolicyTypeOd, uploadSession.Props.UploadSessionID, uploadSession.CallbackSecret).String()

  // Create upload session
  uploadURL, err := c.CreateUploadSession(ctx, inner, onedrive.WithConflictBehavior("fail"))
  if err != nil {
    return nil, err
  }

  chunkSize := p.Settings.ChunkSize
  if chunkSize == 0 {
    chunkSize = 50 << 20 // 50MB default
  }
  uploadSession.ChunkSize = chunkSize
  uploadSession.UploadURL = uploadURL
  return &fs.UploadCredential{
    ChunkSize:  chunkSize,
    UploadURLs: []string{uploadURL},
  }, nil
}

func (d *Driver) CancelToken(ctx context.Context, uploadSession *fs.UploadSession) error {
  subID, _ := parseMuxPath(uploadSession.Props.SavePath)
  if subID < 0 {
    // Best effort: nothing to cancel without a valid session URL
    return nil
  }
  _, c, err := d.resolveSubClient(ctx, subID)
  if err != nil {
    return err
  }
  return c.DeleteUploadSession(ctx, uploadSession.UploadURL)
}

func (d *Driver) CompleteUpload(ctx context.Context, session *fs.UploadSession) error {
  subID, inner := parseMuxPath(session.Props.SavePath)
  if subID < 0 {
    return fmt.Errorf("invalid mux path")
  }
  p, c, err := d.resolveSubClient(ctx, subID)
  if err != nil {
    return err
  }

  if session.SentinelTaskID == 0 {
    return nil
  }

  res, err := c.Meta(ctx, "", inner)
  if err != nil {
    return fmt.Errorf("failed to get uploaded file size: %w", err)
  }

  isSharePoint := strings.Contains(p.Settings.OdDriver, "sharepoint.com") || strings.Contains(p.Settings.OdDriver, "sharepoint.cn")
  sizeMismatch := res.Size != session.Props.Size
  if isSharePoint && sizeMismatch && (res.Size > session.Props.Size) && (res.Size-session.Props.Size <= 1048576) {
    sizeMismatch = false
  }
  if sizeMismatch {
    return fmt.Errorf("file size not match, expected: %d, actual: %d", session.Props.Size, res.Size)
  }
  // Refresh quota of subaccount after completing upload
  if err := d.refreshQuota(ctx, subID, c); err != nil {
    d.l.Warning("onedrivemux: failed to refresh quota for sub %d: %s", subID, err)
  }
  return nil
}

func (d *Driver) List(ctx context.Context, base string, onProgress driver.ListProgressFunc, recursive bool) ([]fs.PhysicalObject, error) {
  return nil, fmt.Errorf("onedrivemux.List not implemented")
}

func (d *Driver) Capabilities() *driver.Capabilities {
	return &driver.Capabilities{
		StaticFeatures:         features,
		ThumbSupportedExts:     d.policy.Settings.ThumbExts,
		ThumbSupportAllExts:    d.policy.Settings.ThumbSupportAllExts,
		ThumbMaxSize:           d.policy.Settings.ThumbMaxSize,
		ThumbProxy:             d.policy.Settings.ThumbGeneratorProxy,
		MediaMetaProxy:         d.policy.Settings.MediaMetaGeneratorProxy,
		BrowserRelayedDownload: d.policy.Settings.StreamSaver,
	}
}

func (d *Driver) MediaMeta(ctx context.Context, path, ext string) ([]driver.MediaMeta, error) {
  return nil, fmt.Errorf("onedrivemux.MediaMeta not implemented")
}

// Helpers
func parseMuxPath(path string) (int64, string) {
  // Expect acc/{id}/rest/of/path
  s := strings.TrimLeft(path, "/")
  if !strings.HasPrefix(s, "acc/") {
    return -1, ""
  }
  s = strings.TrimPrefix(s, "acc/")
  parts := strings.SplitN(s, "/", 2)
  if len(parts) == 0 {
    return -1, ""
  }
  // parse id
  var id int64 = -1
  // simple Atoi without error return -> -1 on failure
  for _, ch := range parts[0] {
    if ch < '0' || ch > '9' {
      return -1, ""
    }
    if id < 0 {
      id = 0
    }
    id = id*10 + int64(ch-'0')
  }
  rest := ""
  if len(parts) == 2 {
    rest = parts[1]
  }
  return id, rest
}

func (d *Driver) resolveSubClient(ctx context.Context, subID int64) (*ent.StoragePolicy, onedrive.Client, error) {
  if d.policy.Settings == nil {
    return nil, nil, fmt.Errorf("missing settings")
  }
  var found *ent.StoragePolicy
  var odDriver string
  for _, acc := range d.policy.Settings.OdMuxAccounts {
    if acc.ID == subID {
      if acc.Disabled {
        return nil, nil, fmt.Errorf("subaccount disabled")
      }
      p := *d.policy
      // isolate settings copy
      if p.Settings != nil {
        s := *p.Settings
        if acc.OdDriver != "" {
          s.OdDriver = acc.OdDriver
        }
        p.Settings = &s
      }
      found = &p
      odDriver = p.Settings.OdDriver
      break
    }
  }
  if found == nil {
    return nil, nil, fmt.Errorf("subaccount not found")
  }
  // Ensure mux credential exists in CredManager; if not, seed it using stored refresh token
  seeded := false
  if _, err := d.cred.Obtain(ctx, onedrive.OdMuxCredentialKey(d.policy.ID, subID)); err != nil {
    // Try to seed from settings
    if d.policy.Settings != nil {
      for _, acc := range d.policy.Settings.OdMuxAccounts {
        if acc.ID == subID && acc.RefreshToken != "" && !acc.Disabled {
          seed := onedrive.OdMuxCredential{PolicyID: d.policy.ID, SubID: subID, RefreshToken: acc.RefreshToken, ExpiresIn: 0}
          if err := d.cred.Upsert(ctx, seed); err != nil {
            d.l.Warning("onedrivemux: failed to seed credential for sub %d: %s", subID, err)
          } else {
            seeded = true
          }
          break
        }
      }
    }
    if !seeded {
      d.l.Warning("onedrivemux: no credential found for sub %d and cannot seed; operations may fail", subID)
    }
  }
  // Build OneDrive client with mux credential key
  c := onedrive.NewClientWithCredentialKey(found, requestClient(d), d.cred, d.l, d.settings, chunkSize(found), onedrive.OdMuxCredentialKey(d.policy.ID, subID))
  _ = odDriver // reserved
  return found, c, nil
}

// chooseSubAccount selects the subaccount with lowest remaining that can fit size+1MiB
func chooseSubAccount(policy *ent.StoragePolicy, size int64) (int64, error) {
  const safetyMargin int64 = 1 << 20
  if policy == nil || policy.Settings == nil {
    return -1, fmt.Errorf("onedrivemux: no settings to select subaccount")
  }
  var chosenID int64 = -1
  var chosenRemaining int64 = 1<<62
  for _, acc := range policy.Settings.OdMuxAccounts {
    if acc.Disabled {
      continue
    }
    if acc.Remaining >= (size + safetyMargin) {
      if acc.Remaining < chosenRemaining {
        chosenRemaining = acc.Remaining
        chosenID = acc.ID
      }
    }
  }
  if chosenID < 0 {
    return -1, fmt.Errorf("onedrivemux: no subaccount has enough free space")
  }
  return chosenID, nil
}

func requestClient(d *Driver) request.Client { return request.NewClient(d.config, request.WithLogger(d.l)) }

func chunkSize(p *ent.StoragePolicy) int64 {
  if p.Settings != nil && p.Settings.ChunkSize > 0 {
    return p.Settings.ChunkSize
  }
  return 50 << 20
}

// refreshQuota queries OneDrive quota and persists it into mux policy settings for subID.
func (d *Driver) refreshQuota(ctx context.Context, subID int64, c onedrive.Client) error {
  quota, err := c.GetDriveQuota(ctx)
  if err != nil {
    return err
  }
  dep := dependency.FromContext(ctx)
  spc := dep.StoragePolicyClient()
  pol, err := spc.GetPolicyByID(ctx, d.policy.ID)
  if err != nil {
    return err
  }
  if pol.Settings == nil {
    pol.Settings = &types.PolicySetting{}
  }
  updated := false
  now := time.Now().Unix()
  for i := range pol.Settings.OdMuxAccounts {
    if pol.Settings.OdMuxAccounts[i].ID == subID {
      pol.Settings.OdMuxAccounts[i].Total = quota.Total
      pol.Settings.OdMuxAccounts[i].Used = quota.Used
      pol.Settings.OdMuxAccounts[i].Remaining = quota.Remaining
      pol.Settings.OdMuxAccounts[i].UpdatedAtUnix = now
      pol.Settings.OdMuxAccounts[i].LastSyncUnix = now
      updated = true
      break
    }
  }
  if !updated {
    return fmt.Errorf("onedrivemux: subaccount %d not found when refreshing quota", subID)
  }
  _, err = spc.Upsert(ctx, pol)
  return err
}
