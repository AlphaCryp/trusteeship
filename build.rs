fn main() {
    cc::Build::new()
        .file("src/bls.c")
        .include("/usr/local/include/pbc")
        .static_flag(true)
        .compile("libbls.a");
}
