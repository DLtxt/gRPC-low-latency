use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Prefer a protoc the environment already provides (distro package, CI image),
    // otherwise fall back to the vendored binary so the build stays hermetic.
    if std::env::var_os("PROTOC").is_none() {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // Emitted so the server can expose gRPC reflection, which is what lets
        // `grpcurl` call the service without being handed a .proto file.
        .file_descriptor_set_path(out_dir.join("hsm_descriptor.bin"))
        .compile_protos(&["../proto/hsm/v1/hsm.proto"], &["../proto"])?;

    println!("cargo:rerun-if-changed=../proto/hsm/v1/hsm.proto");
    Ok(())
}
