fn main() -> anyhow::Result<()> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let ebpf_dir = std::path::Path::new(&manifest_dir)
        .join("..")
        .join("ebpf");
    let ebpf_package = aya_build::Package {
        name: "secureexec-ebpf",
        root_dir: ebpf_dir.to_str().unwrap(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], aya_build::Toolchain::default())
}
