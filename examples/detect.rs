use libfido2::Fido;

pub fn main() {
    let fido = Fido::new();
    let detected_devices = fido.detect_devices(1);
    let info = detected_devices
        .iter_info()
        .next()
        .expect("No device found");
    println!(
        "Found device at {}: {}",
        info.path.to_string_lossy(),
        info.product.to_string_lossy()
    );
    let mut device = fido.new_device(info.path).expect("Unable to open device");
    println!("CTAPHID info: {:#?}", device.ctap_hid_info());
    println!(
        "CBOR info: {:#?}",
        device
            .request_cbor_data()
            .expect("Unable to request CBOR info")
            .info()
    );
}
