package main

import (
	"context"
	"fmt"
	"log"
	"sync"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
)

func runTransactionChecks(ctx context.Context, client *firestore.Client) {
	counter := client.Collection("txn").Doc("counter")
	if _, err := counter.Set(ctx, map[string]interface{}{"n": int64(0)}); err != nil {
		log.Fatalf("txn seed: %v", err)
	}

	// Basic read-modify-write transaction.
	err := client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		snap, err := tx.Get(counter)
		if err != nil {
			return err
		}
		n := snap.Data()["n"].(int64)
		return tx.Set(counter, map[string]interface{}{"n": n + 1})
	})
	if err != nil {
		log.Fatalf("RunTransaction: %v", err)
	}
	snap, _ := counter.Get(ctx)
	if snap.Data()["n"].(int64) != 1 {
		log.Fatalf("txn result: want 1 got %v", snap.Data()["n"])
	}
	fmt.Println("TXN ok: read-modify-write")

	// Contention: two goroutines increment concurrently; ABORTED retries
	// must make both land (final value 3).
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
				snap, err := tx.Get(counter)
				if err != nil {
					return err
				}
				n := snap.Data()["n"].(int64)
				return tx.Set(counter, map[string]interface{}{"n": n + 1})
			})
			if err != nil {
				log.Fatalf("concurrent txn: %v", err)
			}
		}()
	}
	wg.Wait()
	snap, _ = counter.Get(ctx)
	if got := snap.Data()["n"].(int64); got != 3 {
		log.Fatalf("contention result: want 3 got %v", got)
	}
	fmt.Println("TXN ok: concurrent increments retried to 3")

	// Transaction reading a missing doc then creating it.
	fresh := client.Collection("txn").Doc("fresh")
	err = client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		_, err := tx.Get(fresh)
		if err == nil {
			return fmt.Errorf("expected missing")
		}
		return tx.Create(fresh, map[string]interface{}{"born": true})
	})
	if err != nil {
		log.Fatalf("create txn: %v", err)
	}
	fmt.Println("TXN ok: missing-read then create")

	// ListCollectionIds via Collections().
	cols := client.Collections(ctx)
	var ids []string
	for {
		c, err := cols.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("Collections: %v", err)
		}
		ids = append(ids, c.ID)
	}
	fmt.Printf("COLLECTIONS ok: %v\n", ids)

	// ListDocuments via DocumentRefs.
	refs := client.Collection("cities").DocumentRefs(ctx)
	var docIDs []string
	for {
		r, err := refs.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("DocumentRefs: %v", err)
		}
		docIDs = append(docIDs, r.ID)
	}
	fmt.Printf("LISTDOCS ok: %v\n", docIDs)

	// Projection.
	iter := client.Collection("cities").Select("name").Documents(ctx)
	for {
		s, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("Select: %v", err)
		}
		if _, has := s.Data()["population"]; has {
			log.Fatal("projection leaked population")
		}
	}
	fmt.Println("SELECT ok: projection drops unselected fields")
}
