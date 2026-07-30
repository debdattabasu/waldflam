package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/firestore"
	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
)

func runAggregationChecks(ctx context.Context, client *firestore.Client) {
	q := client.Collection("cities").Where("population", ">", int64(0))
	results, err := q.NewAggregationQuery().
		WithCount("cnt").
		WithSum("population", "total").
		WithAvg("population", "avg").
		Get(ctx)
	if err != nil {
		log.Fatalf("aggregation: %v", err)
	}
	cnt := results["cnt"].(*pb.Value).GetIntegerValue()
	total := results["total"].(*pb.Value).GetIntegerValue()
	avg := results["avg"].(*pb.Value).GetDoubleValue()
	// cities at this point: delhi 31.2M, lyon 1.7M (tokyo deleted earlier).
	if cnt != 2 || total != 32900000 || avg != 16450000.0 {
		log.Fatalf("aggregation values: cnt=%d total=%d avg=%f", cnt, total, avg)
	}
	fmt.Printf("AGGREGATE ok: count=%d sum=%d avg=%.0f\n", cnt, total, avg)
}
