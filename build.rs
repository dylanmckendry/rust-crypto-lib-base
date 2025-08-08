fn main() {
    csbindgen::Builder::default()
        .input_extern_file("src/lib.rs")
        .csharp_dll_name("rust_crypto_lib_base")
        .csharp_class_name("ExtendedSigner")     // optional, default: NativeMethods
        .csharp_namespace("Slipstream.CommonDotNet.ExtendedSigner")
        .csharp_class_accessibility("public")
        .generate_csharp_file("dotnet/ExtendedSigner.g.cs")
        .unwrap();
}