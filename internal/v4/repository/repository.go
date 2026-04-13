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
	var (
		mongoSnapshot v4model.Snapshot
		mongoHosts    []v4model.SnapshotHost
		mongoFound    bool
	)
	if client := r.controller.Client(); client != nil && r.controller.Mode() != storage.ModeLocal {
		snapshot, hosts, found, err := r.loadLatestMongo(ctx, client)
		if err == nil {
			mongoSnapshot = snapshot
			mongoHosts = hosts
			mongoFound = found
		} else {
			r.controller.HandleMongoError(err)
		}
	}
	localSnapshot, localHosts, localFound, localErr := r.loadLatestLocal(ctx)
	if localErr != nil {
		if mongoFound {
			return mongoSnapshot, mongoHosts, true, nil
		}
		return v4model.Snapshot{}, nil, false, localErr
	}
	if mongoFound && localFound {
		if newerSnapshot(localSnapshot, mongoSnapshot) {
			return localSnapshot, localHosts, true, nil
		}
		return mongoSnapshot, mongoHosts, true, nil
	}
	if mongoFound {
		return mongoSnapshot, mongoHosts, true, nil
	}
	return localSnapshot, localHosts, localFound, nil
}

func (r *SnapshotRepository) LoadSyncState(ctx context.Context) (v4model.SyncState, bool, error) {
	var (
		mongoState v4model.SyncState
		mongoFound bool
	)
	if client := r.controller.Client(); client != nil && r.controller.Mode() != storage.ModeLocal {
		state, found, err := r.loadSyncStateMongo(ctx, client)
		if err == nil {
			mongoState = state
			mongoFound = found
		} else {
			r.controller.HandleMongoError(err)
		}
	}
	localState, localFound, localErr := r.loadSyncStateLocal(ctx)
	if localErr != nil {
		if mongoFound {
			return mongoState, true, nil
		}
		return v4model.SyncState{}, false, localErr
	}
	if mongoFound && localFound {
		if newerSyncState(localState, mongoState) {
			return localState, true, nil
		}
		return mongoState, true, nil
	}
	if mongoFound {
		return mongoState, true, nil
	}
	return localState, localFound, nil
}

func (r *SnapshotRepository) ReplaceLastGood(ctx context.Context, snapshot v4model.Snapshot, hosts []v4model.SnapshotHost) error {
	snapshot.ID = lastGoodSnapshotID
	if err := r.replaceLocal(ctx, snapshot, hosts); err != nil {
		return err
	}
	if client := r.controller.Client(); client != nil && r.controller.Mode() != storage.ModeLocal {
		if err := r.replaceMongo(ctx, client, snapshot, hosts); err == nil {
			_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketV4SnapshotsDirty, lastGoodSnapshotID)
			for _, host := range hosts {
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
	if err := r.replaceMongo(ctx, client, snapshot, hosts); err != nil {
		return 0, err
	}
	_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketV4SnapshotsDirty, lastGoodSnapshotID)
	for _, host := range hosts {
		_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketV4SnapshotHostsDirty, host.Host)
	}
	return len(hosts) + 1, nil
}

func (r *RuntimeStateRepository) Get(ctx context.Context, host string) (v4model.HostRuntimeState, bool, error) {
	if client := r.controller.Client(); client != nil && r.controller.Mode() != storage.ModeLocal {
		state, found, err := r.getMongo(ctx, client, host)
		if err == nil {
			return state, found, nil
		}
		r.controller.HandleMongoError(err)
	}
	return r.getLocal(ctx, host)
}

func (r *RuntimeStateRepository) Upsert(ctx context.Context, state v4model.HostRuntimeState) error {
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
	states := map[string]v4model.HostRuntimeState{}
	if client := r.controller.Client(); client != nil && r.controller.Mode() != storage.ModeLocal {
		result, err := r.listMongo(ctx, client)
		if err == nil {
			return result, nil
		}
		r.controller.HandleMongoError(err)
	}
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

func (r *EventRepository) Emit(ctx context.Context, event v4model.Event, dedupeWindow time.Duration) (bool, error) {
	now := time.Now().UTC()
	if event.ID == "" {
		event.ID = fmt.Sprintf("%s:%d", event.Fingerprint, now.UnixNano())
	}
	event.CreatedAt = now
	event.UpdatedAt = now
	if event.SilentUntil.IsZero() {
		event.SilentUntil = now
	}
	if client := r.controller.Client(); client != nil && r.controller.Mode() != storage.ModeLocal {
		inserted, err := r.emitMongo(ctx, client, event, dedupeWindow)
		if err == nil {
			if inserted {
				_ = r.persistLocalMirror(ctx, event)
			}
			return inserted, nil
		}
		r.controller.HandleMongoError(err)
	}
	return r.emitLocal(ctx, event, dedupeWindow)
}

func (r *EventRepository) ListRecent(ctx context.Context, limit int) ([]v4model.Event, error) {
	if client := r.controller.Client(); client != nil && r.controller.Mode() != storage.ModeLocal {
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
		if _, err := r.emitMongo(ctx, client, event, 0); err != nil {
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
	hosts := make([]v4model.SnapshotHost, 0, len(hostsMap))
	for _, host := range hostsMap {
		hosts = append(hosts, host)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	return snapshot, hosts, true, nil
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
	cursor, err := client.Database().Collection(v4model.CollectionSnapshotHosts).Find(child, bson.M{})
	if err != nil {
		return v4model.Snapshot{}, nil, false, err
	}
	defer cursor.Close(child)

	hosts := make([]v4model.SnapshotHost, 0)
	for cursor.Next(child) {
		var host v4model.SnapshotHost
		if err := cursor.Decode(&host); err != nil {
			return v4model.Snapshot{}, nil, false, err
		}
		hosts = append(hosts, host)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	return snapshot, hosts, true, cursor.Err()
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
	db := client.Database()
	if _, err := db.Collection(v4model.CollectionSnapshots).UpdateByID(child, lastGoodSnapshotID, bson.M{"$set": snapshot}, options.Update().SetUpsert(true)); err != nil {
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
	_, err := hostCollection.DeleteMany(child, bson.M{"_id": bson.M{"$nin": hostIDs}})
	return err
}

func (r *SnapshotRepository) upsertSyncStateMongo(ctx context.Context, client *mongostore.Client, state v4model.SyncState) error {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()
	_, err := client.Database().Collection(v4model.CollectionSnapshots).UpdateByID(
		child,
		v4model.SyncStateID,
		bson.M{"$set": state},
		options.Update().SetUpsert(true),
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
	_, err := client.Database().Collection(v4model.CollectionRuntimeStates).UpdateByID(child, state.Host, bson.M{"$set": state}, options.Update().SetUpsert(true))
	return err
}

func (r *EventRepository) emitLocal(ctx context.Context, event v4model.Event, dedupeWindow time.Duration) (bool, error) {
	now := time.Now().UTC()
	metaKey := "v4_event:" + event.Fingerprint
	var marker eventMarker
	if err := r.controller.Local().GetJSON(ctx, localdisk.BucketMetadata, metaKey, &marker); err == nil {
		if marker.SilentUntil.After(now) {
			return false, nil
		}
		if dedupeWindow > 0 && marker.UpdatedAt.After(now.Add(-dedupeWindow)) {
			return false, nil
		}
	} else if !errors.Is(err, localdisk.ErrNotFound) {
		return false, err
	}
	if err := r.controller.Local().PutJSONDirty(ctx, localdisk.BucketV4Events, localdisk.BucketV4EventsDirty, event.ID, event); err != nil {
		return false, err
	}
	if err := r.controller.Local().PutJSON(ctx, localdisk.BucketMetadata, metaKey, eventMarker{
		UpdatedAt:   now,
		LastEventID: event.ID,
		SilentUntil: event.SilentUntil,
	}); err != nil {
		return false, err
	}
	return true, nil
}

func (r *EventRepository) emitMongo(ctx context.Context, client *mongostore.Client, event v4model.Event, dedupeWindow time.Duration) (bool, error) {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()
	now := time.Now().UTC()
	existing := client.Database().Collection(v4model.CollectionEvents)
	conditions := make([]bson.M, 0, 2)
	if dedupeWindow > 0 {
		conditions = append(conditions, bson.M{"updated_at": bson.M{"$gte": now.Add(-dedupeWindow)}})
	}
	if !event.SilentUntil.IsZero() && event.SilentUntil.After(now) {
		conditions = append(conditions, bson.M{"silent_until": bson.M{"$gte": now}})
	}
	filter := bson.M{"fingerprint": event.Fingerprint}
	if len(conditions) == 0 {
		_, err := existing.InsertOne(child, event)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	if len(conditions) == 1 {
		for key, value := range conditions[0] {
			filter[key] = value
		}
	} else if len(conditions) > 1 {
		filter["$or"] = conditions
	}
	count, err := existing.CountDocuments(child, filter)
	if err != nil {
		return false, err
	}
	if count > 0 {
		return false, nil
	}
	_, err = existing.InsertOne(child, event)
	if err != nil {
		return false, err
	}
	return true, nil
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

func (r *EventRepository) persistLocalMirror(ctx context.Context, event v4model.Event) error {
	if err := r.controller.Local().PutJSON(ctx, localdisk.BucketV4Events, event.ID, event); err != nil {
		return err
	}
	return r.controller.Local().PutJSON(ctx, localdisk.BucketMetadata, "v4_event:"+event.Fingerprint, eventMarker{
		UpdatedAt:   event.UpdatedAt,
		LastEventID: event.ID,
		SilentUntil: event.SilentUntil,
	})
}

func newerSnapshot(left, right v4model.Snapshot) bool {
	leftUpdated := left.UpdatedAt.UTC()
	rightUpdated := right.UpdatedAt.UTC()
	if !leftUpdated.IsZero() && !rightUpdated.IsZero() {
		if leftUpdated.After(rightUpdated) {
			return true
		}
		if leftUpdated.Before(rightUpdated) {
			return false
		}
	}
	return strings.TrimSpace(left.Version) > strings.TrimSpace(right.Version)
}

func newerSyncState(left, right v4model.SyncState) bool {
	leftUpdated := maxTime(left.UpdatedAt, left.LastSuccessAt, left.LastSyncAt)
	rightUpdated := maxTime(right.UpdatedAt, right.LastSuccessAt, right.LastSyncAt)
	if !leftUpdated.IsZero() && !rightUpdated.IsZero() {
		if leftUpdated.After(rightUpdated) {
			return true
		}
		if leftUpdated.Before(rightUpdated) {
			return false
		}
	}
	return strings.TrimSpace(left.LastSnapshotVersion) > strings.TrimSpace(right.LastSnapshotVersion)
}

func maxTime(values ...time.Time) time.Time {
	latest := time.Time{}
	for _, value := range values {
		value = value.UTC()
		if value.After(latest) {
			latest = value
		}
	}
	return latest
}
