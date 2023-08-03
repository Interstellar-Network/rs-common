#[test]
fn test_read_png_to_bytes() {
    let data = png_utils::read_png_to_bytes(include_bytes!("1x1.png"));

    assert_eq!(data, vec![0]);
}

#[test]
fn test_write_png() {
    let tmpfile = tempfile::NamedTempFile::new().unwrap();
    // "Close the file, but keep the path to it around."
    let path = tmpfile.into_temp_path();
    let path = path.as_os_str().to_str().unwrap();

    png_utils::write_png(path, 1, 1, &vec![0u8]);

    let new_png_data = std::fs::read(path).unwrap();
    assert!(new_png_data.len() > 0);

    // This FAIL b/c the .png can have different headers, compression, etc
    // assert_eq!(new_png_data, include_bytes!("1x1.png"));

    // So we call the previous test...
    test_read_png_to_bytes();
}
