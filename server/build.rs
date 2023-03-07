use std::env::var;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(var("OUT_DIR").unwrap());

    tonic_build::configure()
        .build_server(true)
        .file_descriptor_set_path(out_dir.join("knox_descriptor.bin"))
        .include_file("knox_proto.rs")
        .compile(&["proto/common.proto", "proto/auth.proto"], &["proto"])?;

    Ok(())
}
