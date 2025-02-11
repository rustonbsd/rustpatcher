use cargo_metadata::MetadataCommand;

fn main() {
    let metadata = MetadataCommand::new()
        .exec()
        .expect("Failed to read cargo metadata");

    // Extract the root package (application) version
    let app_version = metadata.root_package()
        .expect("No root package found (this is a library?)")
        .version.clone();

    // Pass the version to the library as a compile-time constant
    println!("cargo:rustc-env=APP_VERSION={}", app_version);
}