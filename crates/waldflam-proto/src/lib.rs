//! Generated gRPC/protobuf types for the `google.firestore.v1` surface.
//!
//! Protos are vendored from the firebase-js-sdk checkout (which curates them
//! from googleapis) so the wire surface matches what official clients speak.

pub mod google {
    pub mod api {
        tonic::include_proto!("google.api");
    }
    pub mod rpc {
        tonic::include_proto!("google.rpc");
    }
    pub mod r#type {
        tonic::include_proto!("google.r#type");
    }
    pub mod firestore {
        pub mod v1 {
            tonic::include_proto!("google.firestore.v1");
        }
    }
}

pub use google::firestore::v1;
