fn main() {
    println!("cargo:rerun-if-changed=linker-x86_64.ld");
    println!("cargo:rustc-link-arg=-Tkernel/linker-x86_64.ld");
}
