package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
)

func main() {
	ctx := context.Background()
	projectID := fmt.Sprintf("go-conf-%d", time.Now().UnixNano())
	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	// Set + merge + read back.
	doc := client.Collection("cities").Doc("tokyo")
	if _, err := doc.Set(ctx, map[string]interface{}{"name": "Tokyo", "population": int64(37400000)}); err != nil {
		log.Fatalf("Set: %v", err)
	}
	if _, err := client.Collection("cities").Doc("delhi").Set(ctx, map[string]interface{}{"name": "Delhi", "population": int64(31200000)}); err != nil {
		log.Fatalf("Set delhi: %v", err)
	}
	if _, err := client.Collection("cities").Doc("lyon").Set(ctx, map[string]interface{}{"name": "Lyon", "population": int64(1700000)}); err != nil {
		log.Fatalf("Set lyon: %v", err)
	}
	snap, err := doc.Get(ctx)
	if err != nil {
		log.Fatalf("Get: %v", err)
	}
	fmt.Printf("GET ok: %v\n", snap.Data())

	// Update with increment transform + precondition (doc must exist).
	if _, err := doc.Update(ctx, []firestore.Update{
		{Path: "population", Value: firestore.Increment(100)},
		{Path: "updated", Value: firestore.ServerTimestamp},
	}); err != nil {
		log.Fatalf("Update: %v", err)
	}
	snap, _ = doc.Get(ctx)
	fmt.Printf("UPDATE ok: population=%v updated=%v\n", snap.Data()["population"], snap.Data()["updated"] != nil)

	// Create colliding with existing doc must fail.
	if _, err := doc.Create(ctx, map[string]interface{}{"x": 1}); err == nil {
		log.Fatal("Create over existing doc should fail")
	} else {
		fmt.Println("CREATE precondition ok (AlreadyExists)")
	}

	// Query: population > 2M ordered desc.
	iter := client.Collection("cities").
		Where("population", ">", 2000000).
		OrderBy("population", firestore.Desc).
		Documents(ctx)
	var got []string
	for {
		s, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("Query: %v", err)
		}
		got = append(got, s.Data()["name"].(string))
	}
	fmt.Printf("QUERY ok: %v\n", got)
	if len(got) != 2 || got[0] != "Tokyo" || got[1] != "Delhi" {
		log.Fatalf("unexpected query result: %v", got)
	}

	// GetAll (BatchGetDocuments): found + missing.
	snaps, err := client.GetAll(ctx, []*firestore.DocumentRef{
		client.Collection("cities").Doc("tokyo"),
		client.Collection("cities").Doc("nowhere"),
	})
	if err != nil {
		log.Fatalf("GetAll: %v", err)
	}
	fmt.Printf("GETALL ok: tokyo exists=%v nowhere exists=%v\n", snaps[0].Exists(), snaps[1].Exists())

	// Delete, then read must be missing.
	if _, err := doc.Delete(ctx); err != nil {
		log.Fatalf("Delete: %v", err)
	}
	snap, err = doc.Get(ctx)
	if err == nil {
		log.Fatal("expected NotFound after delete")
	}
	fmt.Println("DELETE ok")

	runTransactionChecks(ctx, client)
	runListenChecks(ctx, client)

	fmt.Println("ALL GO CLIENT CHECKS PASSED")
	os.Exit(0)
}
