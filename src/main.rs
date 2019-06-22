use libfido2::Fido;

pub fn main() {
    let fido = Fido::new();
    fido.detect_devices(10).iter_paths().for_each(|path| println!("Found path: {}", path));
}
