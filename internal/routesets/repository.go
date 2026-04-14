package routesets

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/localdisk"
	mongostore "gw-ipinfo-nginx/internal/mongo"
	"gw-ipinfo-nginx/internal/storage"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	CollectionManifests = "route_sets_manifests"
	activeManifestID    = "active"
)

type Manifest struct {
	ID          string    `json:"id" bson:"_id"`
	Version     string    `json:"version" bson:"version"`
	Fingerprint string    `json:"fingerprint" bson:"fingerprint"`
	UpdatedAt   time.Time `json:"updated_at" bson:"updated_at"`
	WriterInstanceID string `json:"writer_instance_id" bson:"writer_instance_id"`
	WriterStartedAt  time.Time `json:"writer_started_at" bson:"writer_started_at"`
	Enabled     bool      `json:"enabled" bson:"enabled"`
	Payload     []byte    `json:"payload" bson:"payload"`
	Source      string    `json:"source" bson:"source"`
}

type Repository struct {
	controller *storage.Controller
	logger     *slog.Logger
	instanceID string
	instanceStartedAt time.Time
}

func NewRepository(controller *storage.Controller, logger *slog.Logger, instanceID string, instanceStartedAt time.Time) *Repository {
	repo := &Repository{
		controller: controller,
		logger:     logger,
		instanceID: strings.TrimSpace(instanceID),
		instanceStartedAt: instanceStartedAt.UTC(),
	}
	if controller != nil {
		controller.RegisterReplayer(repo)
	}
	return repo
}

func (r *Repository) Name() string { return "route_sets_manifest" }

func (r *Repository) ReplaceLatest(ctx context.Context, compiled *Compiled, source string) (Manifest, error) {
	manifest, err := newManifest(compiled, source, r.instanceID, r.instanceStartedAt)
	if err != nil {
		return Manifest{}, err
	}
	if err := r.replaceLocal(ctx, manifest); err != nil {
		return Manifest{}, err
	}
	if client := r.mongoClient(); client != nil {
		if err := r.replaceMongo(ctx, client, manifest); err == nil {
			_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketRouteSetsManifestDirty, activeManifestID)
			return manifest, nil
		} else {
			r.controller.HandleMongoError(err)
			return manifest, err
		}
	}
	return manifest, nil
}

func (r *Repository) LoadLatest(ctx context.Context) (*Compiled, Manifest, bool, error) {
	if r.mongoAuthoritative() {
		client := r.mongoClient()
		manifest, found, err := r.loadMongo(ctx, client)
		if err != nil {
			r.controller.HandleMongoError(err)
		} else {
			if !found {
				return nil, Manifest{}, false, nil
			}
			compiled, decodeErr := decodeManifest(manifest)
			return compiled, manifest, true, decodeErr
		}
	}

	localManifest, localFound, localErr := r.loadLocal(ctx)
	if localErr != nil {
		return nil, Manifest{}, false, localErr
	}
	if localFound {
		compiled, err := decodeManifest(localManifest)
		return compiled, localManifest, true, err
	}
	return nil, Manifest{}, false, nil
}

func (r *Repository) Replay(ctx context.Context, client *mongostore.Client, batchSize int) (int, error) {
	manifest, found, err := r.loadLocal(ctx)
	if err != nil || !found {
		return 0, err
	}
	if err := r.replaceMongo(ctx, client, manifest); err != nil {
		return 0, err
	}
	_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketRouteSetsManifestDirty, activeManifestID)
	return 1, nil
}

func (r *Repository) mongoClient() *mongostore.Client {
	if r == nil || r.controller == nil || r.controller.Mode() == storage.ModeLocal {
		return nil
	}
	return r.controller.Client()
}

func (r *Repository) replaceLocal(ctx context.Context, manifest Manifest) error {
	current, found, err := r.loadLocal(ctx)
	if err != nil {
		return err
	}
	if found && staleManifestWrite(current, manifest) {
		return nil
	}
	return r.controller.Local().PutJSONDirty(ctx, localdisk.BucketRouteSetsManifest, localdisk.BucketRouteSetsManifestDirty, activeManifestID, manifest)
}

func (r *Repository) loadLocal(ctx context.Context) (Manifest, bool, error) {
	var manifest Manifest
	if err := r.controller.Local().GetJSON(ctx, localdisk.BucketRouteSetsManifest, activeManifestID, &manifest); err != nil {
		if errors.Is(err, localdisk.ErrNotFound) {
			return Manifest{}, false, nil
		}
		return Manifest{}, false, err
	}
	return manifest, true, nil
}

func (r *Repository) replaceMongo(ctx context.Context, client *mongostore.Client, manifest Manifest) error {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()
	current, found, err := r.loadMongo(ctx, client)
	if err != nil {
		return err
	}
	if found && staleManifestWrite(current, manifest) {
		return nil
	}
	_, err := client.Database().Collection(CollectionManifests).ReplaceOne(
		child,
		bson.M{"_id": activeManifestID},
		manifest,
		options.Replace().SetUpsert(true),
	)
	return err
}

func (r *Repository) loadMongo(ctx context.Context, client *mongostore.Client) (Manifest, bool, error) {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	var manifest Manifest
	err := client.Database().Collection(CollectionManifests).FindOne(child, bson.M{"_id": activeManifestID}).Decode(&manifest)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return Manifest{}, false, nil
		}
		return Manifest{}, false, err
	}
	return manifest, true, nil
}

func newManifest(compiled *Compiled, source string, instanceID string, instanceStartedAt time.Time) (Manifest, error) {
	if compiled == nil {
		compiled = &Compiled{}
	}
	payload, err := json.Marshal(compiled)
	if err != nil {
		return Manifest{}, fmt.Errorf("marshal route_sets manifest: %w", err)
	}
	now := time.Now().UTC()
	hash := sha1.Sum(payload)
	return Manifest{
		ID:          activeManifestID,
		Version:     now.Format(time.RFC3339Nano),
		Fingerprint: hex.EncodeToString(hash[:]),
		UpdatedAt:   now,
		WriterInstanceID: strings.TrimSpace(instanceID),
		WriterStartedAt:  instanceStartedAt.UTC(),
		Enabled:     compiled.IsEnabled(),
		Payload:     payload,
		Source:      strings.TrimSpace(source),
	}, nil
}

func staleManifestWrite(current, incoming Manifest) bool {
	if writerWriteIsStale(current.WriterStartedAt, current.UpdatedAt, incoming.WriterStartedAt, incoming.UpdatedAt) {
		return true
	}
	return false
}

func writerWriteIsStale(currentStartedAt, currentUpdatedAt, incomingStartedAt, incomingUpdatedAt time.Time) bool {
	currentStartedAt = currentStartedAt.UTC()
	currentUpdatedAt = currentUpdatedAt.UTC()
	incomingStartedAt = incomingStartedAt.UTC()
	incomingUpdatedAt = incomingUpdatedAt.UTC()

	if !currentStartedAt.IsZero() {
		if incomingStartedAt.IsZero() {
			return true
		}
		if incomingStartedAt.Before(currentStartedAt) {
			return true
		}
		if incomingStartedAt.After(currentStartedAt) {
			return false
		}
	}
	if !currentUpdatedAt.IsZero() && !incomingUpdatedAt.IsZero() && incomingUpdatedAt.Before(currentUpdatedAt) {
		return true
	}
	return false
}

func decodeManifest(manifest Manifest) (*Compiled, error) {
	if len(manifest.Payload) == 0 {
		return &Compiled{}, nil
	}
	var compiled Compiled
	if err := json.Unmarshal(manifest.Payload, &compiled); err != nil {
		return nil, fmt.Errorf("unmarshal route_sets manifest: %w", err)
	}
	if compiled.BypassRulesByHost == nil {
		compiled.BypassRulesByHost = make(map[string][]CompiledRule)
	}
	if compiled.V3RulesByHost == nil {
		compiled.V3RulesByHost = make(map[string][]CompiledRule)
	}
	if compiled.SourceRulesByHost == nil {
		compiled.SourceRulesByHost = make(map[string][]CompiledRule)
	}
	if compiled.TargetHostIndex == nil {
		compiled.TargetHostIndex = make(map[string]TargetBinding)
	}
	if compiled.AllowedHosts == nil {
		compiled.AllowedHosts = make(map[string]struct{})
	}
	if compiled.RulesByID == nil {
		compiled.RulesByID = make(map[string]CompiledRule)
	}
	return &compiled, nil
}

func (r *Repository) mongoAuthoritative() bool {
	return r != nil && r.controller != nil && r.controller.Client() != nil && r.controller.Mode() != storage.ModeLocal
}
