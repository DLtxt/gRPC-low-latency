//! Generated protobuf messages and gRPC stubs for `hsm.v1`.

pub mod v1 {
    tonic::include_proto!("hsm.v1");

    /// Encoded descriptor set, used to serve gRPC reflection. Without it `grpcurl`
    /// would need to be handed the `.proto` file on every call.
    pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("hsm_descriptor");
}
