/// Return the raw pixel bytes from a .png buffer
///
/// This is useful to compare the outputs of eg `garbled.eval()` with a .png
/// reference file. See Examples below.
///
/// cf https://docs.rs/png/latest/png/#using-the-decoder
///
/// # Examples
///
/// ```
/// let eval_outputs: Vec<u8> = vec![0]; // REPLACEME; eg use `garbled.eval()`
/// let expected_outputs = png_utils::read_png_to_bytes(include_bytes!("../tests/1x1.png"));
/// assert_eq!(eval_outputs, expected_outputs);
/// ```
///
pub fn read_png_to_bytes(buf: &[u8]) -> Vec<u8> {
    // The decoder is a build for reader and can be used to set various decoding options
    // via `Transformations`. The default output transformation is `Transformations::IDENTITY`.
    let decoder = png::Decoder::new(buf);
    let mut reader = decoder.read_info().unwrap();
    // Allocate the output buffer.
    let mut buf = vec![0; reader.output_buffer_size()];
    // Read the next frame. An APNG might contain multiple frames.
    let info = reader.next_frame(&mut buf).unwrap();
    // Grab the bytes of the image.
    let bytes = &buf[..info.buffer_size()];

    bytes.to_vec()
}

/// Write a raw bytes buffer as a new `.png` to the given path
///
/// Typically use by the various CLI; the tests usually use `read_png_to_bytes` above.
///
/// * `path` - the path to the to-be-created(or overwritten .png).
/// * `width`/`height` - the width and height of the image; it MUST math `data` length!
/// * `data` - the raw bytes of the image; this is NOT a .png with headers etc; this is JUST raw pixels
///
pub fn write_png(path: &str, width: usize, height: usize, data: &[u8]) {
    write_png_direct(path, width, height, data);
}

fn write_png_direct(path: &str, width: usize, height: usize, data: &[u8]) {
    use std::io::BufWriter;

    // use std::io::Cursor;
    // let buf = Vec::new();
    // let c = Cursor::new(buf);
    // let ref mut w = BufWriter::new(c);

    let file = std::fs::File::create(path).unwrap();
    let w = BufWriter::new(file);

    // TODO(interstellar) get from Circuit's "config"
    let mut encoder = png::Encoder::new(w, width.try_into().unwrap(), height.try_into().unwrap());
    encoder.set_color(png::ColorType::Grayscale);
    encoder.set_depth(png::BitDepth::Eight);

    let mut writer = encoder.write_header().unwrap();

    writer.write_image_data(data).unwrap();

    writer.finish().unwrap();
}
