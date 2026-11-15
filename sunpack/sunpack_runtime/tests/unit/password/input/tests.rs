use super::*;
use crate::test_support::temp_file;

#[test]
fn virtual_ranges_read_and_seek_across_files() {
    let first = temp_file("password_range_first", b"012345");
    let second = temp_file("password_range_second", b"abcdef");
    let ranges = [
        RangeSpec {
            reader: ManagedReader::open(&first).unwrap(),
            start: 2,
            len: 3,
            virtual_start: 0,
        },
        RangeSpec {
            reader: ManagedReader::open(&second).unwrap(),
            start: 1,
            len: 4,
            virtual_start: 3,
        },
    ];
    let mut reader = VirtualRangeReader::new(&ranges);
    let mut all = [0u8; 7];
    reader.read_exact(&mut all).unwrap();
    assert_eq!(&all, b"234bcde");
    reader.seek(SeekFrom::Start(2)).unwrap();
    let mut middle = [0u8; 3];
    reader.read_exact(&mut middle).unwrap();
    assert_eq!(&middle, b"4bc");
    let _ = std::fs::remove_file(first);
    let _ = std::fs::remove_file(second);
}
