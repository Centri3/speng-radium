use hashbrown::HashMap;
use std::ops::Range;

/// Signature (or e_magic) of DOS headers
pub const MZ_MAGIC: usize = 0x0usize;
/// Expected value of `MZ_SIGNATURE`
pub const MZ_MAGIC_VALUE: &str = "MZ";
/// Length of the signature
pub const MZ_MAGIC_LEN: usize = 0x2usize;
/// Address of `IMAGE_NT_HEADERS`
pub const MZ_NT_ADDRESS: usize = 0x3cusize;
/// Signature of NT headers. Offset from `MZ_NT_ADDRESS`
pub const NT_SIGNATURE: usize = 0x0usize;
/// Expected value of `NT_SIGNATURE`
pub const NT_SIGNATURE_VALUE: &str = "PE";
/// Length of the signature
pub const NT_SIGNATURE_LEN: usize = 0x4usize;
/// Address where the `IMAGE_FILE_HEADER` starts. Offset from
/// `MZ_NT_ADDRESS`
pub const NT_FILE: usize = 0x4usize;
/// Length of the `IMAGE_FILE_HEADER`
pub const NT_FILE_LEN: usize = 0x14usize;
/// Number of sections in `EXE`. Offset from `MZ_NT_ADDRESS` and
/// `NT_FILE`
pub const NT_FILE_SECTIONS_NUM: usize = 0x2usize;
/// Size of the optional header in `EXE`. Offset from `MZ_NT_ADDRESS` and
/// `NT_FILE`
pub const NT_FILE_OPTIONAL_LEN: usize = 0x10usize;
/// Expected value of `NT_FILE_OPTIONAL_LEN`
pub const NT_FILE_OPTIONAL_LEN_VALUE: usize = 0xf0usize;
/// Address where the `IMAGE_OPTIONAL_HEADER` starts. Offset from
/// `MZ_NT_ADDRESS`
pub const NT_OPTIONAL: usize = 0x18usize;
/// Magic. Offset from `MZ_NT_ADDRESS` and `NT_OPTIONAL`
pub const NT_OPTIONAL_MAGIC: usize = 0x0usize;
/// Expected value of `NT_OPTIONAL_MAGIC` if `EXE` is a 32-bit executable
pub const NT_OPTIONAL_MAGIC_32: usize = 0x10busize;
/// Expected value of `NT_OPTIONAL_MAGIC` if `EXE` is a 64-bit executable
pub const NT_OPTIONAL_MAGIC_64: usize = 0x20busize;
/// Entry point of the program. Offset from `MZ_NT_ADDRESS` and
/// `NT_OPTIONAL`
pub const NT_OPTIONAL_ENTRY_POINT: usize = 0x28usize;
/// Image base of the program. Used for names of functions and the sort.
/// Offset from `MZ_NT_ADDRESS` and `NT_OPTIONAL`
pub const NT_OPTIONAL_IMAGE_BASE: usize = 0x30usize;
/// Number of entries in `IMAGE_DATA_DIRECTORY`. Offset from `MZ_NT_ADDRESS`
/// and `NT_OPTIONAL`
pub const NT_OPTIONAL_DIRECTORY_ENTRY_NUM: usize = 0x84usize;
/// Expected value of `NT_OPTIONAL_DIRECTORY_ENTRY_NUM`. Quite a mouthful.
pub const NT_OPTIONAL_DIRECTORY_ENTRY_NUM_VALUE: usize = 0x10usize;
/// Length of each entry in `IMAGE_DATA_DIRECTORY`. Offset from
/// `MZ_NT_ADDRESS` and `NT_OPTIONAL`
pub const NT_OPTIONAL_DIRECTORY_ENTRY_LEN: usize = 0x8usize;
/// Address where the `IMAGE_DATA_DIRECTORY` begins. Offset from
/// `MZ_NT_ADDRESS` and `NT_OPTIONAL`
pub const NT_OPTIONAL_DIRECTORY: usize = 0x70usize;
/// Length of each section
pub const NT_SECTION_LEN: usize = 0x28usize;
/// Name of the section. Offset from `MZ_NT_ADDRESS`, `NT_OPTIONAL` and
/// `NT_FILE_OPTIONAL_LEN`
pub const NT_SECTION_NAME: usize = 0x0usize;
/// Size of the section. Offset from `MZ_NT_ADDRESS`, `NT_OPTIONAL` and
/// `NT_FILE_OPTIONAL_LEN`
pub const NT_SECTION_SIZE: usize = 0x10usize;
/// Start of the section. Offset from `MZ_NT_ADDRESS`, `NT_OPTIONAL` and
/// `NT_FILE_OPTIONAL_LEN`
pub const NT_SECTION: usize = 0x14usize;

pub type NtImageSections = HashMap<String, Range<usize>>;
pub type NtDirectoryEntry = Range<usize>;

#[derive(Debug)]
pub struct NtImage {
    optional: NtOptional,
    sections: NtImageSections,
}

impl NtImage {
    #[inline(always)]
    pub fn new(optional: NtOptional, sections: NtImageSections) -> Self {
        Self { optional, sections }
    }
}

#[derive(Debug)]
pub struct NtOptional {
    entry_point: usize,
    image_base: usize,
    directory: NtDirectory,
}

impl NtOptional {
    #[inline(always)]
    pub fn new(entry_point: usize, image_base: usize, directory: NtDirectory) -> Self {
        Self {
            entry_point,
            image_base,
            directory,
        }
    }
}

#[derive(Debug)]
pub struct NtDirectory {
    imports: NtDirectoryEntry,
    functions: NtDirectoryEntry,
}

impl NtDirectory {
    #[inline(always)]
    pub fn new(imports: NtDirectoryEntry, functions: NtDirectoryEntry) -> Self {
        Self { imports, functions }
    }
}
