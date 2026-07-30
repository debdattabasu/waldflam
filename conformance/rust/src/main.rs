//! firestore-rs (the de-facto community Rust client) running against
//! waldflam via FIRESTORE_EMULATOR_HOST.
//!
//! The client library is unchanged; only the token source is injected
//! (this machine has no Google ADC, and firestore-rs unconditionally
//! resolves credentials even in emulator mode — see docs/architecture.md §3).

use firestore::*;
use gcloud_sdk::{Token, TokenSourceType};
use serde::{Deserialize, Serialize};

struct StaticToken;

#[async_trait::async_trait]
impl gcloud_sdk::Source for StaticToken {
    async fn token(&self) -> gcloud_sdk::error::Result<Token> {
        Ok(Token::new(
            "Bearer".into(),
            "owner".into(),
            chrono::Utc::now() + chrono::Duration::hours(1),
        ))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct City {
    name: String,
    population: i64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let db = FirestoreDb::with_options_token_source(
        FirestoreDbOptions::new(format!("rs-conf-{nanos}")),
        gcloud_sdk::GCP_DEFAULT_SCOPES.clone(),
        TokenSourceType::ExternalSource(Box::new(StaticToken)),
    )
    .await?;

    db.ping().await?;
    println!("PING ok");

    let tokyo = City { name: "Tokyo".into(), population: 37_400_000 };
    let created: City = db
        .fluent()
        .insert()
        .into("cities")
        .document_id("tokyo")
        .object(&tokyo)
        .execute()
        .await?;
    assert_eq!(created, tokyo);
    let delhi = City { name: "Delhi".into(), population: 31_200_000 };
    db.fluent()
        .insert()
        .into("cities")
        .document_id("delhi")
        .object(&delhi)
        .execute::<City>()
        .await?;
    println!("INSERT ok");

    let got: Option<City> = db.fluent().select().by_id_in("cities").obj().one("tokyo").await?;
    assert_eq!(got.as_ref(), Some(&tokyo));
    println!("GET ok: {:?}", got.unwrap().name);

    // Insert colliding with an existing id must fail (ALREADY_EXISTS).
    let clash = db
        .fluent()
        .insert()
        .into("cities")
        .document_id("tokyo")
        .object(&tokyo)
        .execute::<City>()
        .await;
    assert!(clash.is_err(), "duplicate insert must fail");
    println!("INSERT precondition ok (AlreadyExists)");

    let updated: City = db
        .fluent()
        .update()
        .fields(paths!(City::population))
        .in_col("cities")
        .document_id("tokyo")
        .object(&City { name: "Tokyo".into(), population: 37_400_100 })
        .execute()
        .await?;
    assert_eq!(updated.population, 37_400_100);
    println!("UPDATE ok: {}", updated.population);

    let big: Vec<City> = db
        .fluent()
        .select()
        .from("cities")
        .filter(|q| {
            q.for_all([q
                .field(path!(City::population))
                .greater_than_or_equal(31_200_000)])
        })
        .order_by([(path!(City::population), FirestoreQueryDirection::Descending)])
        .obj()
        .query()
        .await?;
    assert_eq!(big.len(), 2);
    assert_eq!(big[0].name, "Tokyo");
    assert_eq!(big[1].name, "Delhi");
    println!("QUERY ok: {:?}", big.iter().map(|c| &c.name).collect::<Vec<_>>());

    // Transaction: buffered update committed atomically.
    let mut txn = db.begin_transaction().await?;
    db.fluent()
        .update()
        .in_col("cities")
        .document_id("delhi")
        .object(&City { name: "Delhi".into(), population: 31_200_001 })
        .add_to_transaction(&mut txn)?;
    txn.commit().await?;
    let after: Option<City> = db.fluent().select().by_id_in("cities").obj().one("delhi").await?;
    assert_eq!(after.unwrap().population, 31_200_001);
    println!("TXN ok");

    // Streaming batch writer: exercises the bidi Write stream + handshake.
    let (writer, mut results) = db.create_streaming_batch_writer().await?;
    let reader = tokio::spawn(async move {
        use futures::TryStreamExt;
        let mut n = 0;
        while let Ok(Some(_)) = results.try_next().await {
            n += 1;
        }
        n
    });
    let mut batch = writer.new_batch();
    for i in 0..5 {
        db.fluent()
            .update()
            .in_col("cities")
            .document_id(format!("bulk-{i}"))
            .object(&City { name: format!("bulk-{i}"), population: i })
            .add_to_batch(&mut batch)?;
    }
    batch.write().await?;
    writer.finish().await;
    let responses = reader.await?;
    assert!(responses >= 1, "expected write-stream responses");
    let count = db
        .fluent()
        .select()
        .from("cities")
        .obj::<City>()
        .query()
        .await?
        .len();
    assert_eq!(count, 7);
    println!("BATCH ok: {count} docs");

    db.fluent().delete().from("cities").document_id("tokyo").execute().await?;
    let gone: Option<City> = db.fluent().select().by_id_in("cities").obj().one("tokyo").await?;
    assert!(gone.is_none());
    println!("DELETE ok");

    println!("ALL RUST CLIENT CHECKS PASSED");
    Ok(())
}
