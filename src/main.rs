use libfido2::Fido;

pub fn main() {
    let fido = Fido::new();
    let detected_devices = fido.detect_devices(1);
    let path = detected_devices.iter_paths().next().unwrap();
    println!("Found device: {}", path.to_string_lossy());
    let device = fido.new_device(path).unwrap();
}
