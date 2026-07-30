package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"cloud.google.com/go/firestore"
)

func runListenChecks(ctx context.Context, client *firestore.Client) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	coll := client.Collection("watched")
	if _, err := coll.Doc("a").Set(ctx, map[string]interface{}{"n": int64(1)}); err != nil {
		log.Fatalf("listen seed: %v", err)
	}

	// Query snapshots: initial state, then live add, update, delete.
	it := coll.Where("n", ">", int64(0)).Snapshots(ctx)
	defer it.Stop()

	snap, err := it.Next()
	if err != nil {
		log.Fatalf("first snapshot: %v", err)
	}
	if len(snap.Changes) != 1 || snap.Changes[0].Kind != firestore.DocumentAdded {
		log.Fatalf("first snapshot: unexpected changes %+v", snap.Changes)
	}
	fmt.Println("LISTEN ok: initial snapshot")

	if _, err := coll.Doc("b").Set(ctx, map[string]interface{}{"n": int64(2)}); err != nil {
		log.Fatalf("listen add: %v", err)
	}
	snap, err = it.Next()
	if err != nil {
		log.Fatalf("add snapshot: %v", err)
	}
	if len(snap.Changes) != 1 || snap.Changes[0].Kind != firestore.DocumentAdded ||
		snap.Changes[0].Doc.Ref.ID != "b" {
		log.Fatalf("add snapshot: unexpected changes %+v", snap.Changes)
	}
	fmt.Println("LISTEN ok: live add delivered")

	if _, err := coll.Doc("a").Set(ctx, map[string]interface{}{"n": int64(5)}); err != nil {
		log.Fatalf("listen update: %v", err)
	}
	snap, err = it.Next()
	if err != nil {
		log.Fatalf("update snapshot: %v", err)
	}
	if len(snap.Changes) != 1 || snap.Changes[0].Kind != firestore.DocumentModified ||
		snap.Changes[0].Doc.Data()["n"].(int64) != 5 {
		log.Fatalf("update snapshot: unexpected changes %+v", snap.Changes)
	}
	fmt.Println("LISTEN ok: live update delivered")

	// Filter departure: n drops to 0, doc leaves the result set.
	if _, err := coll.Doc("b").Set(ctx, map[string]interface{}{"n": int64(0)}); err != nil {
		log.Fatalf("listen filter-out: %v", err)
	}
	snap, err = it.Next()
	if err != nil {
		log.Fatalf("filter-out snapshot: %v", err)
	}
	if len(snap.Changes) != 1 || snap.Changes[0].Kind != firestore.DocumentRemoved ||
		snap.Changes[0].Doc.Ref.ID != "b" {
		log.Fatalf("filter-out snapshot: unexpected changes %+v", snap.Changes)
	}
	fmt.Println("LISTEN ok: filter departure delivered")

	if _, err := coll.Doc("a").Delete(ctx); err != nil {
		log.Fatalf("listen delete: %v", err)
	}
	snap, err = it.Next()
	if err != nil {
		log.Fatalf("delete snapshot: %v", err)
	}
	if len(snap.Changes) != 1 || snap.Changes[0].Kind != firestore.DocumentRemoved {
		log.Fatalf("delete snapshot: unexpected changes %+v", snap.Changes)
	}
	fmt.Println("LISTEN ok: delete delivered")

	// Single-document watcher.
	dit := coll.Doc("solo").Snapshots(ctx)
	defer dit.Stop()
	dsnap, err := dit.Next()
	if err != nil {
		log.Fatalf("doc watch first: %v", err)
	}
	if dsnap.Exists() {
		log.Fatal("doc watch: solo should not exist yet")
	}
	if _, err := coll.Doc("solo").Set(ctx, map[string]interface{}{"here": true}); err != nil {
		log.Fatalf("doc watch set: %v", err)
	}
	dsnap, err = dit.Next()
	if err != nil {
		log.Fatalf("doc watch second: %v", err)
	}
	if !dsnap.Exists() || dsnap.Data()["here"].(bool) != true {
		log.Fatal("doc watch: expected solo to exist")
	}
	fmt.Println("LISTEN ok: single-document watch")
}
