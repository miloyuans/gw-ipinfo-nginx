package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/localdisk"
	mongostore "gw-ipinfo-nginx/internal/mongo"
	"gw-ipinfo-nginx/internal/storage"
	v4model "gw-ipinfo-nginx/internal/v4/model"

	bolt "go.etcd.io/bbolt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const lastGoodSnapshotID = "last_good"

type eventMarker struct {
	UpdatedAt   time.Time `json:"updated_at"`
	LastEventID string    `json:"last_event_id"`
	SilentUntil time.Time `json:"silent_until"`
}

type SnapshotRepository struct {
	controller *storage.Controller
	logger     *slog.Logger
}

type RuntimeStateRepository struct {
	controller *storage.Controller
}

type EventRepository struct {
	controller *storage.Controller
	logger     *slog.Logger
}

func NewSnapshotRepository(controller *storage.Controller, logger *slog.Logger) *SnapshotRepository {
	repo := &SnapshotRepository{controller: controller, logger: logger}
	if controller != nil {
		controller.RegisterReplayer(repo)
	}
	return repo
}

func NewRuntimeStateRepository(controller *storage.Controller) *RuntimeStateRepository {
	repo := &RuntimeStateRepository{controller: controller}
	if controller != nil {
		controller.RegisterReplayer(repo)
	}
	return repo
}

func NewEventRepository(controller *storage.Controller, logger *slog.Logger) *EventRepository {
	repo := &EventRepository{controller: controller, logger: logger}
	if controller != nil {
		controller.RegisterReplayer(repo)
	}
	return repo
}

func (r *SnapshotRepository) Name() string     { return "v4_snapshots" }
func (r *RuntimeStateRepository) Name() string { return "v4_runtime_states" }
func (r *EventRepository) Name() string        { return "v4_events" }

func (r *SnapshotRepository) LoadLatest(ctx context.Context) (v4model.Snapshot, []v4model.SnapshotHost, bool, error) {
	if r.mongoAuthoritative() {
		client := r.controller.Client()
		snapshot, hosts, found, err := r.loadLatestMongo(ctx, client)
		if err != nil {
			r.controller.HandleMongoError(err)
		} else {
			if !found {
				return v4model.Snapshot{}, nil, false, nil
			}
			if valid, validationErr := r.validateLoadedSnapshot("mongo", snapshot, hosts); valid {
				return snapshot, hosts, true, nil
			} else if validationErr != nil {
				r.logSnapshotInvalid("mongo", snapshot, validationErr)
			}
			return v4model.Snapshot{}, nil, false, nil
		}
	}
	localSnapshot, localHosts, localFound, localErr := r.loadLatestLocal(ctx)
	if localErr != nil {
		return v4model.Snapshot{}, nil, false, localErr
	}
	if valid, validationErr := r.validateLoadedSnapshot("localdisk", localSnapshot, localHosts); !valid {
		if validationErr != nil {
			r.logSnapshotInvalid("localdisk", localSnapshot, validationErr)
		}
		return v4model.Snapshot{}, nil, false, nil
	}
	return localSnapshot, localHosts, localFound, nil
}

func (r *SnapshotRepository) LoadSyncState(ctx context.Context) (v4model.SyncState, bool, error) {
	if r.mongoAuthoritative() {
		client := r.controller.Client()
		state, found, err := r.loadSyncStateMongo(ctx, client)
		if err != nil {
			r.controller.HandleMongoError(err)
		} else {
			if !found {
				return v4model.SyncState{}, false, nil
			}
			return state, true, nil
		}
	}
	localState, localFound, localErr := r.loadSyncStateLocal(ctx)
	if localErr != nil {
		return v4model.SyncState{}, false, localErr
	}
	return localState, localFound, nil
}

func (r *SnapshotRepository) ReplaceLastGood(ctx context.Context, snapshot v4model.Snapshot, hosts []v4model.SnapshotHost) error {
	snapshot.ID = lastGoodSnapshotID
	stampedHosts := stampSnapshotHosts(snapshot, hosts)
	if err := r.replaceLocal(ctx, snapshot, stampedHosts); err != nil {
		return err
	}
	if client := r.controller.Client(); client != nil && r.controller.Mode() != storage.ModeLocal {
		if err := r.replaceMongo(ctx, client, snapshot, stampedHosts); err == nil {
			_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketV4SnapshotsDirty, lastGoodSnapshotID)
			for _, host := range stampedHosts {
				_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketV4SnapshotHostsDirty, host.Host)
			}
			return nil
		} else {
			r.controller.HandleMongoError(err)
			return err
		}
	}
	return nil
}

func (r *SnapshotRepository) UpsertSyncState(ctx context.Context, state v4model.SyncState) error {
	state.ID = v4model.SyncStateID
	if err := r.controller.Local().PutJSON(ctx, localdisk.BucketMetadata, "v4_sync_state", state); err != nil {
		return err
	}
	if client := r.controller.Client(); client != nil && r.controller.Mode() != storage.ModeLocal {
		if err := r.upsertSyncStateMongo(ctx, client, state); err == nil {
			return nil
		} else {
			r.controller.HandleMongoError(err)
			return err
		}
	}
	return nil
}

func (r *SnapshotRepository) Replay(ctx context.Context, client *mongostore.Client, batchSize int) (int, error) {
	snapshot, hosts, found, err := r.loadLatestLocal(ctx)
	if err != nil || !found {
		return 0, err
	}
	stampedHosts := stampSnapshotHosts(snapshot, hosts)
	if err := r.replaceMongo(ctx, client, snapshot, stampedHosts); err != nil {
		return 0, err
	}
	_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketV4SnapshotsDirty, lastGoodSnapshotID)
	for _, host := range stampedHosts {
		_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketV4SnapshotHostsDirty, host.Host)
	}
	return len(stampedHosts) + 1, nil
}

func (r *RuntimeStateRepository) Get(ctx context.Context, host string) (v4model.HostRuntimeState, bool, error) {
	if r.mongoAuthoritative() {
		client := r.controller.Client()
		state, found, err := r.getMongo(ctx, client, host)
		if err == nil {
			return state, found, nil
		}
		r.controller.HandleMongoError(err)
	}
	return r.getLocal(ctx, host)
}

func (r *RuntimeStateRepository) Upsert(ctx context.Context, state v4model.HostRuntimeState) error {
	if current, found, err := r.currentAuthoritativeState(ctx, state.Host); err != nil {
		return err
	} else if found && staleRuntimeStateWrite(current, state) {
		return nil
	}
	if err := r.controller.Local().PutJSONDirty(ctx, localdisk.BucketV4RuntimeStates, localdisk.BucketV4RuntimeStatesDirty, state.Host, state); err != nil {
		return err
	}
	if client := r.controller.Client(); client != nil && r.controller.Mode() != storage.ModeLocal {
		if err := r.upsertMongo(ctx, client, state); err == nil {
			_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketV4RuntimeStatesDirty, state.Host)
			return nil
		} else {
			r.controller.HandleMongoError(err)
		}
	}
	return nil
}

func (r *RuntimeStateRepository) List(ctx context.Context) ([]v4model.HostRuntimeState, error) {
	if r.mongoAuthoritative() {
		client := r.controller.Client()
		result, err := r.listMongo(ctx, client)
		if err == nil {
			return result, nil
		}
		r.controller.HandleMongoError(err)
	}
	states := map[string]v4model.HostRuntimeState{}
	err := r.controller.Local().ForEachJSON(ctx, localdisk.BucketV4RuntimeStates, func(key string, raw []byte) error {
		var state v4model.HostRuntimeState
		if err := json.Unmarshal(raw, &state); err != nil {
			return nil
		}
		states[state.Host] = state
		return nil
	})
	if err != nil {
		return nil, err
	}
	result := make([]v4model.HostRuntimeState, 0, len(states))
	for _, state := range states {
		result = append(result, state)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Host < result[j].Host })
	return result, nil
}

func (r *RuntimeStateRepository) Replay(ctx context.Context, client *mongostore.Client, batchSize int) (int, error) {
	keys, err := r.controller.Local().DirtyKeys(ctx, localdisk.BucketV4RuntimeStatesDirty, batchSize)
	if err != nil {
		return 0, err
	}
	replayed := 0
	for _, key := range keys {
		state, found, err := r.getLocal(ctx, key)
		if err != nil {
			return replayed, err
		}
		if !found {
			_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketV4RuntimeStatesDirty, key)
			continue
		}
		if err := r.upsertMongo(ctx, client, state); err != nil {
			return replayed, err
		}
		_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketV4RuntimeStatesDirty, key)
		replayed++
	}
	return replayed, nil
}

func (r *EventRepository) Emit(ctx context.Context, event v4model.Event) (v4model.Event, error) {
	event = stampEvent(event)
	if err := r.persistLocalEvent(ctx, event, true); err != nil {
		return v4model.Event{}, err
	}
	if client := r.controller.Client(); client != nil && r.controller.Mode() != storage.ModeLocal {
		if err := r.upsertMongoEvent(ctx, client, event); err == nil {
			_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketV4EventsDirty, event.ID)
			return event, nil
		} else {
			r.controller.HandleMongoError(err)
		}
	}
	return event, nil
}

func (r *EventRepository) ListRecent(ctx context.Context, limit int) ([]v4model.Event, error) {
	if r.mongoAuthoritative() {
		client := r.controller.Client()
		events, err := r.listRecentMongo(ctx, client, limit)
		if err == nil {
			return events, nil
		}
		r.controller.HandleMongoError(err)
	}
	return r.listRecentLocal(ctx, limit)
}

func (r *EventRepository) Replay(ctx context.Context, client *mongostore.Client, batchSize int) (int, error) {
	keys, err := r.controller.Local().DirtyKeys(ctx, localdisk.BucketV4EventsDirty, batchSize)
	if err != nil {
		return 0, err
	}
	replayed := 0
	for _, key := range keys {
		var event v4model.Event
		if err := r.controller.Local().GetJSON(ctx, localdisk.BucketV4Events, key, &event); err != nil {
			if errors.Is(err, localdisk.ErrNotFound) {
				_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketV4EventsDirty, key)
				continue
			}
			return replayed, err
		}
		if err := r.upsertMongoEvent(ctx, client, event); err != nil {
			return replayed, err
		}
		_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketV4EventsDirty, key)
		replayed++
	}
	return replayed, nil
}

func (r *SnapshotRepository) loadLatestLocal(ctx context.Context) (v4model.Snapshot, []v4model.SnapshotHost, bool, error) {
	var snapshot v4model.Snapshot
	if err := r.controller.Local().GetJSON(ctx, localdisk.BucketV4Snapshots, lastGoodSnapshotID, &snapshot); err != nil {
		if errors.Is(err, localdisk.ErrNotFound) {
			return v4model.Snapshot{}, nil, false, nil
		}
		return v4model.Snapshot{}, nil, false, err
	}
	hostsMap := make(map[string]v4model.SnapshotHost)
	if err := r.controller.Local().ForEachJSON(ctx, localdisk.BucketV4SnapshotHosts, func(key string, raw []byte) error {
		var host v4model.SnapshotHost
		if err := json.Unmarshal(raw, &host); err != nil {
			return nil
		}
		hostsMap[host.Host] = host
		return nil
	}); err != nil {
		return v4model.Snapshot{}, nil, false, err
	}
	hosts := selectSnapshotHosts(snapshot, hostsMap)
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	return snapshot, hosts, true, nil
}

func selectSnapshotHosts(snapshot v4model.Snapshot, hostsMap map[string]v4model.SnapshotHost) []v4model.SnapshotHost {
	if len(hostsMap) == 0 {
		return nil
	}
	version := strings.TrimSpace(snapshot.Version)
	if version == "" {
		return nil
	}
	hosts := make([]v4model.SnapshotHost, 0, len(hostsMap))
	for _, host := range hostsMap {
		if strings.TrimSpace(host.SnapshotID) == version {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func (r *SnapshotRepository) loadSyncStateLocal(ctx context.Context) (v4model.SyncState, bool, error) {
	var state v4model.SyncState
	if err := r.controller.Local().GetJSON(ctx, localdisk.BucketMetadata, "v4_sync_state", &state); err != nil {
		if errors.Is(err, localdisk.ErrNotFound) {
			return v4model.SyncState{}, false, nil
		}
		return v4model.SyncState{}, false, err
	}
	return state, true, nil
}

func (r *SnapshotRepository) replaceLocal(ctx context.Context, snapshot v4model.Snapshot, hosts []v4model.SnapshotHost) error {
	current, _, found, err := r.loadLatestLocal(ctx)
	if err != nil {
		return err
	}
	if found && staleSnapshotWrite(current, snapshot) {
		return nil
	}
	return r.controller.Local().Update(ctx, func(tx *bolt.Tx) error {
		snapshots := tx.Bucket([]byte(localdisk.BucketV4Snapshots))
		snapshotDirty := tx.Bucket([]byte(localdisk.BucketV4SnapshotsDirty))
		hostBucket := tx.Bucket([]byte(localdisk.BucketV4SnapshotHosts))
		hostDirty := tx.Bucket([]byte(localdisk.BucketV4SnapshotHostsDirty))

		snapshotData, err := json.Marshal(snapshot)
		if err != nil {
			return err
		}
		now := []byte(time.Now().UTC().Format(time.RFC3339Nano))
		if err := snapshots.Put([]byte(lastGoodSnapshotID), snapshotData); err != nil {
			return err
		}
		if err := snapshotDirty.Put([]byte(lastGoodSnapshotID), now); err != nil {
			return err
		}

		cursor := hostBucket.Cursor()
		for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
			if err := hostBucket.Delete(key); err != nil {
				return err
			}
			if err := hostDirty.Delete(key); err != nil {
				return err
			}
		}

		for _, host := range hosts {
			raw, err := json.Marshal(host)
			if err != nil {
				return err
			}
			if err := hostBucket.Put([]byte(host.Host), raw); err != nil {
				return err
			}
			if err := hostDirty.Put([]byte(host.Host), now); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *SnapshotRepository) loadLatestMongo(ctx context.Context, client *mongostore.Client) (v4model.Snapshot, []v4model.SnapshotHost, bool, error) {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	var snapshot v4model.Snapshot
	err := client.Database().Collection(v4model.CollectionSnapshots).FindOne(child, bson.M{"_id": lastGoodSnapshotID}).Decode(&snapshot)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return v4model.Snapshot{}, nil, false, nil
		}
		return v4model.Snapshot{}, nil, false, err
	}
	hostCollection := client.Database().Collection(v4model.CollectionSnapshotHosts)
	hosts, err := r.findMongoSnapshotHosts(child, hostCollection, snapshot.Version)
	if err != nil {
		return v4model.Snapshot{}, nil, false, err
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	return snapshot, hosts, true, nil
}

func (r *SnapshotRepository) loadSyncStateMongo(ctx context.Context, client *mongostore.Client) (v4model.SyncState, bool, error) {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	var state v4model.SyncState
	err := client.Database().Collection(v4model.CollectionSnapshots).FindOne(child, bson.M{"_id": v4model.SyncStateID}).Decode(&state)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return v4model.SyncState{}, false, nil
		}
		return v4model.SyncState{}, false, err
	}
	return state, true, nil
}

func (r *SnapshotRepository) replaceMongo(ctx context.Context, client *mongostore.Client, snapshot v4model.Snapshot, hosts []v4model.SnapshotHost) error {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()
	current, _, found, err := r.loadLatestMongo(ctx, client)
	if err != nil {
		return err
	}
	if found && staleSnapshotWrite(current, snapshot) {
		return nil
	}
	db := client.Database()
	if _, err := db.Collection(v4model.CollectionSnapshots).ReplaceOne(
		child,
		bson.M{"_id": lastGoodSnapshotID},
		snapshot,
		options.Replace().SetUpsert(true),
	); err != nil {
		return err
	}
	hostCollection := db.Collection(v4model.CollectionSnapshotHosts)
	if len(hosts) == 0 {
		_, err := hostCollection.DeleteMany(child, bson.M{})
		return err
	}

	models := make([]mongo.WriteModel, 0, len(hosts))
	hostIDs := make([]string, 0, len(hosts))
	for _, host := range hosts {
		hostIDs = append(hostIDs, host.Host)
		models = append(models, mongo.NewReplaceOneModel().
			SetFilter(bson.M{"_id": host.Host}).
			SetReplacement(host).
			SetUpsert(true))
	}
	if len(models) > 0 {
		if _, err := hostCollection.BulkWrite(child, models, options.BulkWrite().SetOrdered(false)); err != nil {
			return err
		}
	}
	_, err = hostCollection.DeleteMany(child, bson.M{"_id": bson.M{"$nin": hostIDs}})
	if err != nil {
		return err
	}
	verifiedSnapshot, verifiedHosts, found, verifyErr := r.loadLatestMongo(ctx, client)
	if verifyErr != nil {
		return verifyErr
	}
	if !found {
		return errors.New("v4 snapshot verification failed: snapshot not found after mongo replace")
	}
	if valid, validationErr := r.validateLoadedSnapshot("mongo", verifiedSnapshot, verifiedHosts); !valid {
		if validationErr != nil {
			return validationErr
		}
		return errors.New("v4 snapshot verification failed: persisted mongo snapshot is inconsistent")
	}
	return nil
}

func (r *SnapshotRepository) upsertSyncStateMongo(ctx context.Context, client *mongostore.Client, state v4model.SyncState) error {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()
	current, found, err := r.loadSyncStateMongo(ctx, client)
	if err != nil {
		return err
	}
	if found && staleSyncStateWrite(current, state) {
		return nil
	}
	_, err = client.Database().Collection(v4model.CollectionSnapshots).ReplaceOne(
		child,
		bson.M{"_id": v4model.SyncStateID},
		state,
		options.Replace().SetUpsert(true),
	)
	return err
}

func (r *RuntimeStateRepository) getLocal(ctx context.Context, host string) (v4model.HostRuntimeState, bool, error) {
	var state v4model.HostRuntimeState
	if err := r.controller.Local().GetJSON(ctx, localdisk.BucketV4RuntimeStates, host, &state); err != nil {
		if errors.Is(err, localdisk.ErrNotFound) {
			return v4model.HostRuntimeState{}, false, nil
		}
		return v4model.HostRuntimeState{}, false, err
	}
	return state, true, nil
}

func (r *RuntimeStateRepository) getMongo(ctx context.Context, client *mongostore.Client, host string) (v4model.HostRuntimeState, bool, error) {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()
	var state v4model.HostRuntimeState
	err := client.Database().Collection(v4model.CollectionRuntimeStates).FindOne(child, bson.M{"_id": host}).Decode(&state)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return v4model.HostRuntimeState{}, false, nil
		}
		return v4model.HostRuntimeState{}, false, err
	}
	return state, true, nil
}

func (r *RuntimeStateRepository) listMongo(ctx context.Context, client *mongostore.Client) ([]v4model.HostRuntimeState, error) {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()
	cursor, err := client.Database().Collection(v4model.CollectionRuntimeStates).Find(child, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(child)
	states := make([]v4model.HostRuntimeState, 0)
	for cursor.Next(child) {
		var state v4model.HostRuntimeState
		if err := cursor.Decode(&state); err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	sort.Slice(states, func(i, j int) bool { return states[i].Host < states[j].Host })
	return states, cursor.Err()
}

func (r *RuntimeStateRepository) upsertMongo(ctx context.Context, client *mongostore.Client, state v4model.HostRuntimeState) error {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()
	current, found, err := r.getMongo(ctx, client, state.Host)
	if err != nil {
		return err
	}
	if found && staleRuntimeStateWrite(current, state) {
		return nil
	}
	_, err = client.Database().Collection(v4model.CollectionRuntimeStates).UpdateByID(child, state.Host, bson.M{"$set": state}, options.Update().SetUpsert(true))
	return err
}

func (r *EventRepository) ShouldNotify(ctx context.Context, event v4model.Event, dedupeWindow time.Duration) (bool, string, error) {
	if strings.TrimSpace(event.Fingerprint) == "" {
		return false, "empty_fingerprint", nil
	}
	now := time.Now().UTC()
	if r.mongoAuthoritative() {
		allowed, reason, err := r.shouldNotifyMongo(ctx, r.controller.Client(), event.Fingerprint, dedupeWindow, now)
		if err == nil {
			if !allowed {
				return false, reason, nil
			}
			localAllowed, localReason, localErr := r.shouldNotifyLocal(ctx, event.Fingerprint, dedupeWindow, now)
			if localErr == nil && !localAllowed {
				return false, localReason, nil
			}
			return true, "", nil
		}
		r.controller.HandleMongoError(err)
	}
	return r.shouldNotifyLocal(ctx, event.Fingerprint, dedupeWindow, now)
}

func (r *EventRepository) MarkNotificationSent(ctx context.Context, event v4model.Event) error {
	return r.updateNotification(ctx, event, notificationUpdate{
		status:            v4model.EventNotifySent,
		incrementAttempts: true,
		sent:              true,
	})
}

func (r *EventRepository) MarkNotificationFailed(ctx context.Context, event v4model.Event, notifyErr error) error {
	reason := ""
	if notifyErr != nil {
		reason = notifyErr.Error()
	}
	return r.updateNotification(ctx, event, notificationUpdate{
		status:            v4model.EventNotifyFailed,
		reason:            reason,
		incrementAttempts: true,
	})
}

func (r *EventRepository) MarkNotificationSuppressed(ctx context.Context, event v4model.Event, reason string) error {
	return r.updateNotification(ctx, event, notificationUpdate{
		status: v4model.EventNotifySuppressed,
		reason: strings.TrimSpace(reason),
	})
}

func (r *EventRepository) shouldNotifyLocal(ctx context.Context, fingerprint string, dedupeWindow time.Duration, now time.Time) (bool, string, error) {
	var marker eventMarker
	if err := r.controller.Local().GetJSON(ctx, localdisk.BucketMetadata, notificationMarkerKey(fingerprint), &marker); err != nil {
		if errors.Is(err, localdisk.ErrNotFound) {
			return true, "", nil
		}
		return false, "", err
	}
	return notificationMarkerAllows(marker, dedupeWindow, now)
}

func (r *EventRepository) shouldNotifyMongo(ctx context.Context, client *mongostore.Client, fingerprint string, dedupeWindow time.Duration, now time.Time) (bool, string, error) {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	conditions := make([]bson.M, 0, 2)
	conditions = append(conditions, bson.M{"notify_silent_until": bson.M{"$gt": now}})
	if dedupeWindow > 0 {
		conditions = append(conditions, bson.M{"notify_sent_at": bson.M{"$gte": now.Add(-dedupeWindow)}})
	}
	filter := bson.M{
		"fingerprint":    fingerprint,
		"notify_status":  v4model.EventNotifySent,
	}
	if len(conditions) == 1 {
		for key, value := range conditions[0] {
			filter[key] = value
		}
	} else {
		filter["$or"] = conditions
	}
	count, err := client.Database().Collection(v4model.CollectionEvents).CountDocuments(child, filter)
	if err != nil {
		return false, "", err
	}
	if count > 0 {
		return false, "recent_notification_sent", nil
	}
	return true, "", nil
}

func (r *EventRepository) upsertMongoEvent(ctx context.Context, client *mongostore.Client, event v4model.Event) error {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()
	_, err := client.Database().Collection(v4model.CollectionEvents).ReplaceOne(
		child,
		bson.M{"_id": event.ID},
		event,
		options.Replace().SetUpsert(true),
	)
	return err
}

type notificationUpdate struct {
	status            string
	reason            string
	incrementAttempts bool
	sent              bool
}

func (r *EventRepository) updateNotification(ctx context.Context, event v4model.Event, update notificationUpdate) error {
	event.ID = strings.TrimSpace(event.ID)
	if event.ID == "" {
		return errors.New("v4 event notification update requires event id")
	}
	if r.mongoAuthoritative() {
		if err := r.updateMongoNotification(ctx, r.controller.Client(), event, update); err == nil {
			if err := r.updateLocalNotification(ctx, event, update, false); err != nil {
				return err
			}
			if update.sent {
				return r.setLocalNotificationMarker(ctx, event)
			}
			return nil
		} else {
			r.controller.HandleMongoError(err)
		}
	}
	if err := r.updateLocalNotification(ctx, event, update, true); err != nil {
		return err
	}
	if update.sent {
		return r.setLocalNotificationMarker(ctx, event)
	}
	return nil
}

func (r *EventRepository) updateMongoNotification(ctx context.Context, client *mongostore.Client, event v4model.Event, update notificationUpdate) error {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()
	now := time.Now().UTC()
	set := bson.M{
		"notify_status":     update.status,
		"notify_reason":     strings.TrimSpace(update.reason),
		"notify_updated_at": now,
	}
	if update.sent {
		set["notify_sent_at"] = now
		set["notify_silent_until"] = event.SilentUntil.UTC()
	}
	changes := bson.M{"$set": set}
	if update.incrementAttempts {
		changes["$inc"] = bson.M{"notify_attempts": 1}
	}
	_, err := client.Database().Collection(v4model.CollectionEvents).UpdateByID(child, event.ID, changes)
	return err
}

func (r *EventRepository) updateLocalNotification(ctx context.Context, event v4model.Event, update notificationUpdate, dirty bool) error {
	current := event
	if err := r.controller.Local().GetJSON(ctx, localdisk.BucketV4Events, event.ID, &current); err != nil && !errors.Is(err, localdisk.ErrNotFound) {
		return err
	}
	current = applyNotificationUpdate(current, update, time.Now().UTC())
	return r.persistLocalEvent(ctx, current, dirty)
}

func (r *EventRepository) setLocalNotificationMarker(ctx context.Context, event v4model.Event) error {
	return r.controller.Local().PutJSON(ctx, localdisk.BucketMetadata, notificationMarkerKey(event.Fingerprint), eventMarker{
		UpdatedAt:   time.Now().UTC(),
		LastEventID: event.ID,
		SilentUntil: event.SilentUntil.UTC(),
	})
}

func (r *EventRepository) persistLocalEvent(ctx context.Context, event v4model.Event, dirty bool) error {
	if dirty {
		return r.controller.Local().PutJSONDirty(ctx, localdisk.BucketV4Events, localdisk.BucketV4EventsDirty, event.ID, event)
	}
	return r.controller.Local().PutJSON(ctx, localdisk.BucketV4Events, event.ID, event)
}

func applyNotificationUpdate(event v4model.Event, update notificationUpdate, now time.Time) v4model.Event {
	event.NotifyStatus = strings.TrimSpace(update.status)
	event.NotifyReason = strings.TrimSpace(update.reason)
	event.NotifyUpdatedAt = now
	if update.incrementAttempts {
		event.NotifyAttempts++
	}
	if update.sent {
		event.NotifySentAt = now
		event.NotifySilentUntil = event.SilentUntil.UTC()
	}
	event.UpdatedAt = now
	return event
}

func notificationMarkerAllows(marker eventMarker, dedupeWindow time.Duration, now time.Time) (bool, string, error) {
	if marker.SilentUntil.After(now) {
		return false, "recent_notification_sent", nil
	}
	if dedupeWindow > 0 && marker.UpdatedAt.After(now.Add(-dedupeWindow)) {
		return false, "recent_notification_sent", nil
	}
	return true, "", nil
}

func notificationMarkerKey(fingerprint string) string {
	return "v4_notify:" + strings.TrimSpace(fingerprint)
}

func (r *EventRepository) listRecentMongo(ctx context.Context, client *mongostore.Client, limit int) ([]v4model.Event, error) {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	if limit > 0 {
		opts.SetLimit(int64(limit))
	}
	cursor, err := client.Database().Collection(v4model.CollectionEvents).Find(child, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(child)
	events := make([]v4model.Event, 0)
	for cursor.Next(child) {
		var event v4model.Event
		if err := cursor.Decode(&event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, cursor.Err()
}

func (r *EventRepository) listRecentLocal(ctx context.Context, limit int) ([]v4model.Event, error) {
	events := make([]v4model.Event, 0)
	err := r.controller.Local().ForEachJSON(ctx, localdisk.BucketV4Events, func(key string, raw []byte) error {
		var event v4model.Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return nil
		}
		events = append(events, event)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(events, func(i, j int) bool { return events[i].CreatedAt.After(events[j].CreatedAt) })
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

func stampEvent(event v4model.Event) v4model.Event {
	now := time.Now().UTC()
	event.Fingerprint = strings.TrimSpace(event.Fingerprint)
	if event.ID == "" {
		fingerprint := event.Fingerprint
		if fingerprint == "" {
			fingerprint = strings.TrimSpace(event.Type)
		}
		if fingerprint == "" {
			fingerprint = "event"
		}
		event.ID = fmt.Sprintf("%s:%d", fingerprint, now.UnixNano())
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = now
	}
	event.UpdatedAt = now
	if event.SilentUntil.IsZero() {
		event.SilentUntil = now
	}
	return event
}

func (r *SnapshotRepository) mongoAuthoritative() bool {
	return r != nil && r.controller != nil && r.controller.Client() != nil && r.controller.Mode() != storage.ModeLocal
}

func (r *RuntimeStateRepository) mongoAuthoritative() bool {
	return r != nil && r.controller != nil && r.controller.Client() != nil && r.controller.Mode() != storage.ModeLocal
}

func (r *EventRepository) mongoAuthoritative() bool {
	return r != nil && r.controller != nil && r.controller.Client() != nil && r.controller.Mode() != storage.ModeLocal
}

func stampSnapshotHosts(snapshot v4model.Snapshot, hosts []v4model.SnapshotHost) []v4model.SnapshotHost {
	if len(hosts) == 0 {
		return nil
	}
	version := strings.TrimSpace(snapshot.Version)
	stamped := make([]v4model.SnapshotHost, 0, len(hosts))
	for _, host := range hosts {
		host.ID = strings.TrimSpace(host.Host)
		if host.ID == "" {
			host.ID = strings.TrimSpace(host.Host)
		}
		if version != "" {
			host.SnapshotID = version
		}
		host.UpdatedAt = host.UpdatedAt.UTC()
		stamped = append(stamped, host)
	}
	return stamped
}

func (r *RuntimeStateRepository) currentAuthoritativeState(ctx context.Context, host string) (v4model.HostRuntimeState, bool, error) {
	if r.mongoAuthoritative() {
		return r.getMongo(ctx, r.controller.Client(), host)
	}
	return r.getLocal(ctx, host)
}

func (r *SnapshotRepository) findMongoSnapshotHosts(ctx context.Context, hostCollection *mongo.Collection, version string) ([]v4model.SnapshotHost, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		return nil, nil
	}
	cursor, err := hostCollection.Find(ctx, bson.M{"snapshot_id": version})
	if err != nil {
		return nil, err
	}
	hosts := make([]v4model.SnapshotHost, 0)
	for cursor.Next(ctx) {
		var host v4model.SnapshotHost
		if err := cursor.Decode(&host); err != nil {
			_ = cursor.Close(ctx)
			return nil, err
		}
		hosts = append(hosts, host)
	}
	if err := cursor.Err(); err != nil {
		_ = cursor.Close(ctx)
		return nil, err
	}
	_ = cursor.Close(ctx)
	return hosts, nil
}

func (r *SnapshotRepository) validateLoadedSnapshot(source string, snapshot v4model.Snapshot, hosts []v4model.SnapshotHost) (bool, error) {
	if strings.TrimSpace(snapshot.ID) == "" && strings.TrimSpace(snapshot.Version) == "" && len(hosts) == 0 {
		return false, nil
	}
	if snapshot.HostCount > 0 && len(hosts) == 0 {
		return false, fmt.Errorf("v4 snapshot %s is missing hosts for version %s", source, strings.TrimSpace(snapshot.Version))
	}
	if snapshot.HostCount > 0 && len(hosts) != snapshot.HostCount {
		return false, fmt.Errorf("v4 snapshot %s host_count mismatch: snapshot=%d loaded=%d version=%s", source, snapshot.HostCount, len(hosts), strings.TrimSpace(snapshot.Version))
	}
	computed := snapshotHostFingerprint(hosts)
	if strings.TrimSpace(snapshot.Fingerprint) != "" && computed != strings.TrimSpace(snapshot.Fingerprint) {
		return false, fmt.Errorf("v4 snapshot %s fingerprint mismatch: snapshot=%s loaded=%s version=%s", source, strings.TrimSpace(snapshot.Fingerprint), computed, strings.TrimSpace(snapshot.Version))
	}
	return true, nil
}

func (r *SnapshotRepository) logSnapshotInvalid(source string, snapshot v4model.Snapshot, err error) {
	if r == nil || r.logger == nil || err == nil {
		return
	}
	r.logger.Warn("v4_snapshot_source_invalid",
		"event", "v4_snapshot_source_invalid",
		"source", source,
		"version", strings.TrimSpace(snapshot.Version),
		"fingerprint", strings.TrimSpace(snapshot.Fingerprint),
		"error", err,
	)
}

func snapshotHostFingerprint(hosts []v4model.SnapshotHost) string {
	return v4model.CanonicalSnapshotFingerprint(hosts)
}

func staleSnapshotWrite(current, incoming v4model.Snapshot) bool {
	return staleWriterWrite(current.WriterStartedAt, current.UpdatedAt, incoming.WriterStartedAt, incoming.UpdatedAt)
}

func staleSyncStateWrite(current, incoming v4model.SyncState) bool {
	return staleWriterWrite(current.WriterStartedAt, current.UpdatedAt, incoming.WriterStartedAt, incoming.UpdatedAt)
}

func staleRuntimeStateWrite(current, incoming v4model.HostRuntimeState) bool {
	return staleWriterWrite(current.WriterStartedAt, current.UpdatedAt, incoming.WriterStartedAt, incoming.UpdatedAt)
}

func staleWriterWrite(currentStartedAt, currentUpdatedAt, incomingStartedAt, incomingUpdatedAt time.Time) bool {
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
