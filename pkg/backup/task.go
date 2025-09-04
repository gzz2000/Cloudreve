package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/backup/webdav"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/crontab"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/queue"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	"github.com/cloudreve/Cloudreve/v4/pkg/util"
)

type (
	// ColdBackupTask is a placeholder for the cold backup workflow. Implementation will follow in phases.
	ColdBackupTask struct {
		*queue.DBTask

		progress queue.Progresses
	}

	// ColdBackupTaskState holds resumable state for the task (watermarks, counters, etc.)
	ColdBackupTaskState struct {
		// next_to_upload_blob_id watermark persisted in settings; also buffered here for progress.
		LastBlobID     int   `json:"last_blob_id,omitempty"`
		UploadedFiles  int   `json:"uploaded_files,omitempty"`
		UploadedBytes  int64 `json:"uploaded_bytes,omitempty"`
		RemainingFiles int   `json:"remaining_files,omitempty"`
		RemainingBytes int64 `json:"remaining_bytes,omitempty"`
		DBBackupDone   bool  `json:"db_backup_done,omitempty"`
		UploadedList   []struct {
			ID   int   `json:"id"`
			Size int64 `json:"size"`
		} `json:"uploaded_list,omitempty"`
	}
)

func init() {
	queue.RegisterResumableTaskFactory(queue.ColdBackupTaskType, NewColdBackupTaskFromModel)
	crontab.Register(setting.CronTypeColdBackup, func(ctx context.Context) {
		dep := dependency.FromContext(ctx)
		l := dep.Logger()
		cfg := dep.SettingProvider().ColdBackup(ctx)
		if cfg == nil || !cfg.Enabled {
			return
		}

		t, err := NewColdBackupTask(ctx)
		if err != nil {
			l.Error("Failed to create cold backup task: %s", err)
			return
		}
		if err := dep.IoIntenseQueue(ctx).QueueTask(ctx, t); err != nil {
			l.Error("Failed to queue cold backup task: %s", err)
		}
	})
}

// NewColdBackupTaskFromModel reconstructs a task from ent model.
func NewColdBackupTaskFromModel(model *ent.Task) queue.Task {
	return &ColdBackupTask{DBTask: &queue.DBTask{Task: model}}
}

// NewColdBackupTask creates a new cold backup task instance.
func NewColdBackupTask(ctx context.Context) (queue.Task, error) {
	state := &ColdBackupTaskState{}
	stateBytes, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	return &ColdBackupTask{
		DBTask: &queue.DBTask{
			Task: &ent.Task{
				Type:          queue.ColdBackupTaskType,
				CorrelationID: logging.CorrelationID(ctx),
				PrivateState:  string(stateBytes),
				PublicState: &types.TaskPublicState{
					ResumeTime: time.Now().Unix() - 1,
				},
			},
			DirectOwner: inventory.UserFromContext(ctx),
		},
		progress: make(queue.Progresses),
	}, nil
}

// Do executes one iteration of the cold backup task. Placeholder for future implementation.
func (t *ColdBackupTask) Do(ctx context.Context) (task.Status, error) {
	dep := dependency.FromContext(ctx)
	cfg := dep.SettingProvider().ColdBackup(ctx)
	// Force-refresh NextBlobID from DB to avoid stale KV cache causing watermark rollback on retries.
	if raw, err := dep.SettingClient().Get(ctx, "cold_backup_config"); err == nil && raw != "" {
		var loaded setting.ColdBackupConfig
		if jsonErr := json.Unmarshal([]byte(raw), &loaded); jsonErr == nil {
			if loaded.NextBlobID > 0 {
				cfg.NextBlobID = loaded.NextBlobID
			}
		}
	}
	if cfg == nil || !cfg.Enabled {
		return task.StatusCompleted, nil
	}

	// Validate config minimally
	if cfg.WebDAVURL == "" || cfg.RemoteRoot == "" || cfg.EncryptKey == "" {
		return task.StatusError, fmt.Errorf("cold backup config incomplete")
	}
	key, err := parseKey(cfg.EncryptKey)
	if err != nil {
		return task.StatusError, fmt.Errorf("invalid encrypt key: %w", err)
	}

	// Prepare WebDAV client
	wd := &webdavClient{BaseURL: cfg.WebDAVURL, Username: cfg.WebDAVUsername, Password: cfg.WebDAVPassword, Headers: cfg.WebDAVHeaders, InsecureSkipTLS: cfg.WebDAVInsecureTLS}
	wd.MaxRetries = 5

	root := strings.TrimRight(cfg.RemoteRoot, "/")
	if root == "" {
		root = "/cloudreve-backups"
	}

	// Watermark and selection
	nextID := cfg.NextBlobID
	if nextID <= 0 {
		nextID = 1
	}
	client := dep.DBClient()
	filesLimit := cfg.FilesPerRun
	bytesLimit := cfg.BytesPerRun
	var uploadedFiles int
	var uploadedBytes int64
	// collect uploaded entities for summary
	var uploadedList []struct {
		ID   int
		Size int64
	}

	// File manager for streaming entity sources
	user := inventory.UserFromContext(ctx)
	fm := manager.NewFileManager(dep, user)

	// iterate entities by ascending ID until limits
	candidateID := nextID
	var firstErr error
	for uploadedFiles < filesLimit && uploadedBytes < bytesLimit && firstErr == nil {
		// fetch a page of entities
		batch, err := client.Entity.Query().
			Where(
				entity.IDGTE(candidateID),
				entity.TypeEQ(int(types.EntityTypeVersion)),
			).
			Order(ent.Asc(entity.FieldID)).
			Limit(200).
			All(ctx)
		if err != nil {
			firstErr = fmt.Errorf("failed to query entities: %w", err)
			break
		}
		if len(batch) == 0 {
			break
		}
		for _, e := range batch {
			if uploadedFiles >= filesLimit || uploadedBytes >= bytesLimit || firstErr != nil {
				break
			}
			// upload entity e.ID in segments
			if err := wd.EnsureDir(ctx, path.Join(root, "blobs", strconv.Itoa(e.ID))); err != nil {
				firstErr = fmt.Errorf("ensure dir failed for entity %d: %w", e.ID, err)
				break
			}
			es, err := fm.GetEntitySource(ctx, e.ID)
			if err != nil {
				firstErr = fmt.Errorf("failed to get entity source for %d: %w", e.ID, err)
				break
			}
			// segment loop
			total := e.Size
			segSize := cfg.SegmentSize
			if segSize <= 0 {
				segSize = 1 << 30 // 1 GiB default
			}
			segments := int((total + segSize - 1) / segSize)
			// init progress for this entity, support resuming by checking existing segments
			t.Lock()
			t.progress["upload"] = &queue.Progress{Total: total}
			t.Unlock()

			// decide starting segment by listing remote dir
			remoteDir := path.Join(root, "blobs", strconv.Itoa(e.ID))
			existing := map[string]int64{}
			if list, err := wd.ListDir(ctx, remoteDir); err == nil {
				existing = list
			}
			start := 0
			var preBytes int64
			for i := 0; i < segments; i++ {
				name := fmt.Sprintf("%d.p%04d.enc", e.ID, i+1)
				expected := segSize
				if rem := total - int64(i)*segSize; rem < segSize {
					expected = rem
				}
				if sz, ok := existing[name]; ok && sz == expected {
					start = i + 1
					preBytes += expected
				} else {
					break
				}
			}
			// safety: strip the last completed segment to avoid accepting a pre-created but corrupted object
			if start > 0 {
				lastIndex := start - 1
				lastExpected := segSize
				if rem := total - int64(lastIndex)*segSize; rem < segSize {
					lastExpected = rem
				}
				preBytes -= lastExpected
				if preBytes < 0 {
					preBytes = 0
				}
				start = lastIndex
			}
			// seed progress with already present bytes
			t.Lock()
			if p := t.progress["upload"]; p != nil {
				p.Current = preBytes
			}
			t.Unlock()

			for i := start; i < segments; i++ {
				offset := int64(i) * segSize
				length := segSize
				if remaining := total - offset; remaining < segSize {
					length = remaining
				}
				name := fmt.Sprintf("%d.p%04d.enc", e.ID, i+1)
				remote := path.Join(root, "blobs", strconv.Itoa(e.ID), name)
				maxAttempts := 6
				backoff := time.Second
				for attempt := 1; attempt <= maxAttempts; attempt++ {
					// seek and build reader per attempt
					if _, err := es.Seek(offset, io.SeekStart); err != nil {
						firstErr = fmt.Errorf("seek failed for entity %d: %w", e.ID, err)
						break
					}
					limited := io.LimitReader(es, length)
					iv, _ := deriveIV(key, []byte(fmt.Sprintf("%d:%d", e.ID, i)))
					encReader, err := newCTRReader(limited, key, iv)
					if err != nil {
						firstErr = fmt.Errorf("encrypt reader failed for entity %d: %w", e.ID, err)
						break
					}

					// prime a small head to avoid 0-byte first read mismatches
					headSize := int64(32 * 1024)
					if length < headSize {
						headSize = length
					}
					var headBuf bytes.Buffer
					if headSize > 0 {
						if _, err := io.CopyN(&headBuf, encReader, headSize); err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
							firstErr = fmt.Errorf("prime read failed for entity %d: %w", e.ID, err)
							break
						}
					}
					body := io.MultiReader(bytes.NewReader(headBuf.Bytes()), encReader)
					attemptRead := int64(0)
					progressReader := util.NewCallbackReader(body, func(n int64) {
						attemptRead += n
						if p := t.progress["upload"]; p != nil {
							p.Current += n
						}
					})

					if err := wd.Put(ctx, remote, progressReader, length); err != nil {
						// rollback progress added in this failed attempt
						if p := t.progress["upload"]; p != nil && attemptRead > 0 {
							p.Current -= attemptRead
							if p.Current < 0 {
								p.Current = 0
							}
						}
						if attempt == maxAttempts {
							firstErr = fmt.Errorf("upload failed for %s after %d attempts: %w", remote, attempt, err)
							break
						}
						select {
						case <-time.After(backoff):
							if backoff < 10*time.Second {
								backoff *= 2
							}
							continue
						case <-ctx.Done():
							firstErr = ctx.Err()
							break
						}
					}

					// success
					break
				}
				if firstErr != nil {
					break
				}
				uploadedBytes += length
			}
			// if any segment failed, stop and report error without advancing watermark
			if firstErr != nil {
				break
			}
			uploadedFiles++
			candidateID = e.ID + 1
			// persist watermark after each entity; this must succeed
			cfg.NextBlobID = candidateID
			if err := persistColdBackupConfig(ctx, dep, cfg); err != nil {
				firstErr = fmt.Errorf("failed to persist cold backup config after entity %d: %w", e.ID, err)
				break
			}
			// record uploaded entity in state
			// append to existing state stored in t.Task.PrivateState (best-effort)
			// we'll overwrite later with the final state as well
			// note: we don't re-marshal every time to avoid overhead; collect into local slice
			uploadedList = append(uploadedList, struct {
				ID   int
				Size int64
			}{ID: e.ID, Size: e.Size})
		}
		if len(batch) > 0 {
			candidateID = batch[len(batch)-1].ID + 1
		}
	}

	// optional DB backup (only when no prior error)
	var dbDone bool
	if firstErr == nil && cfg.IncludeDB {
		db := dep.ConfigProvider().Database()
		if db.Type == conf.SQLiteDB || db.Type == conf.SQLite3DB || strings.EqualFold(string(db.Type), "sqlite") || strings.EqualFold(string(db.Type), "sqlite3") {
			if err := wd.EnsureDir(ctx, path.Join(root, "db", time.Now().Format("2006-01-02"))); err == nil {
				if err := backupSQLite(ctx, wd, root, key, db.DBFile, cfg.SegmentSize); err != nil {
					firstErr = fmt.Errorf("db backup failed: %w", err)
				} else {
					dbDone = true
				}
			} else {
				firstErr = fmt.Errorf("ensure db dir failed: %w", err)
			}
		}
	}

	// Estimate remaining backlog
	remainingFiles, _ := client.Entity.Query().Where(entity.IDGTE(cfg.NextBlobID), entity.TypeEQ(int(types.EntityTypeVersion))).Count(ctx)
	var sumRes []struct {
		Sum int64 `json:"sum"`
	}
	_ = client.Entity.Query().Where(entity.IDGTE(cfg.NextBlobID), entity.TypeEQ(int(types.EntityTypeVersion))).Select().Aggregate(ent.Sum(entity.FieldSize)).Scan(ctx, &sumRes)
	remainingBytes := int64(0)
	if len(sumRes) > 0 {
		remainingBytes = sumRes[0].Sum
	}

	// Save state for summarize
	state := &ColdBackupTaskState{
		LastBlobID:     cfg.NextBlobID,
		UploadedFiles:  uploadedFiles,
		UploadedBytes:  uploadedBytes,
		RemainingFiles: remainingFiles,
		RemainingBytes: remainingBytes,
		DBBackupDone:   dbDone,
		UploadedList: func() []struct {
			ID   int   `json:"id"`
			Size int64 `json:"size"`
		} {
			res := make([]struct {
				ID   int   `json:"id"`
				Size int64 `json:"size"`
			}, 0, len(uploadedList))
			for _, it := range uploadedList {
				res = append(res, struct {
					ID   int   `json:"id"`
					Size int64 `json:"size"`
				}{ID: it.ID, Size: it.Size})
			}
			return res
		}(),
	}
	if b, err := json.Marshal(state); err == nil {
		t.Task.PrivateState = string(b)
	}

	if firstErr != nil {
		return task.StatusError, firstErr
	}
	return task.StatusCompleted, nil
}

// webdavClient is a thin alias to avoid import cycle with package name.
type webdavClient = webdav.Client

func persistColdBackupConfig(ctx context.Context, dep dependency.Dep, cfg *setting.ColdBackupConfig) error {
	js, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return dep.SettingClient().Set(ctx, map[string]string{"cold_backup_config": string(js)})
}

func backupSQLite(ctx context.Context, wd *webdavClient, root string, key []byte, dbFile string, segSize int64) error {
	fi, err := os.Stat(util.RelativePath(dbFile))
	if err != nil {
		return err
	}
	p := util.RelativePath(dbFile)
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	if segSize <= 0 {
		segSize = 1 << 30
	}
	date := time.Now().Format("2006-01-02")
	base := path.Join(root, "db", date)
	unix := strconv.FormatInt(time.Now().Unix(), 10)
	var offset int64
	index := 1
	for offset < fi.Size() {
		length := segSize
		if fi.Size()-offset < segSize {
			length = fi.Size() - offset
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return err
		}
		limited := io.LimitReader(f, length)
		iv, _ := deriveIV(key, []byte(fmt.Sprintf("db:%s:%d", unix, index)))
		r, err := newCTRReader(limited, key, iv)
		if err != nil {
			return err
		}
		name := fmt.Sprintf("%s-cloudreve.db.p%04d.enc", unix, index)
		remote := path.Join(base, name)
		if err := wd.Put(ctx, remote, r, length); err != nil {
			return err
		}
		offset += length
		index++
	}
	return nil
}

// Summarize exposes a simple summary for admin UI.
func (t *ColdBackupTask) Summarize(hasher hashid.Encoder) *queue.Summary {
	state := &ColdBackupTaskState{}
	if err := json.Unmarshal([]byte(t.State()), state); err != nil {
		// ignore
	}
	return &queue.Summary{
		Phase: "completed",
		Props: map[string]any{
			"uploaded_files":  state.UploadedFiles,
			"uploaded_bytes":  state.UploadedBytes,
			"remaining_files": state.RemainingFiles,
			"remaining_bytes": state.RemainingBytes,
			"db_backup_done":  state.DBBackupDone,
			"last_blob_id":    state.LastBlobID,
			"uploaded_list":   state.UploadedList,
		},
	}
}

// Progress returns current progress for the task.
func (t *ColdBackupTask) Progress(ctx context.Context) queue.Progresses {
	t.Lock()
	defer t.Unlock()
	return t.progress
}
