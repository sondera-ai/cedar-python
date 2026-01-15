fn main() {
    // Ensure the Python extension module is linked with the correct loader flags.
    pyo3_build_config::add_extension_module_link_args();
}
