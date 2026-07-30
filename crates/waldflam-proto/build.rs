fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["protos/google/firestore/v1/firestore.proto"], &["protos"])?;
    Ok(())
}
