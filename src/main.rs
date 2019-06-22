use libfido2::Fido;

pub fn main() {
    let fido = Fido::new();
    let detected_devices = fido.detect_devices(1);
    let info = detected_devices.iter_info().next().unwrap();
    println!("Found device at {}: {}", info.path.to_string_lossy(), info.product.to_string_lossy());
    let device = fido.new_device(info.path).unwrap();
}
