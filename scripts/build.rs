use sp1_build::{BuildArgs, build_program_with_args};
use std::fs;

fn main() {
    let program_dir = "../programs";
    let entries = fs::read_dir(program_dir).expect("Failed to read program directory");

    println!("cargo:rerun-if-changed=../Cargo.lock");

    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.is_dir() && path.join("Cargo.toml").exists() {
            let program_path = path.to_str().unwrap();

            println!("cargo:rerun-if-changed={}/src", program_path);
            println!("cargo:rerun-if-changed={}/Cargo.toml", program_path);

            build_program_with_args(
                program_path,
                BuildArgs {
                    output_directory: Some(format!("{}/elf", program_path)),
                    docker: true,
                    tag: "v5.2.4".to_string(),
                    ..Default::default()
                },
            );
        }
    }
}
