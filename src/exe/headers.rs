use super::Exe;
use super::ExeHandler;
use eyre::eyre;
use eyre::Result;
use hashbrown::HashMap;
use std::any::type_name;
use std::fmt::Debug;
use std::ops::Range;
use tracing::info;
use tracing::instrument;

pub type NtImageSections = HashMap<String, (Range<usize>, Range<usize>)>;
pub type NtDirectoryEntry = Range<usize>;

#[derive(Debug)]
pub struct NtImage {
    optional: NtOptional,
    sections: NtImageSections,
}

impl NtImage {
    const MZ_MAGIC: usize = 0x0usize;
    const MZ_MAGIC_VALUE: &str = "MZ";
    const MZ_MAGIC_LEN: usize = 0x2usize;
    const MZ_NT_POINTER: usize = 0x3cusize;
    const NT_SIGNATURE: usize = 0x0usize;
    const NT_SIGNATURE_VALUE: &str = "PE";
    const NT_SIGNATURE_LEN: usize = 0x4usize;
    const NT_FILE: usize = 0x4usize;
    const NT_FILE_NUM_SECTIONS: usize = 0x2usize;
    const NT_FILE_OPTIONAL_LEN: usize = 0x10usize;
    const NT_FILE_OPTIONAL_LEN_VALUE: u16 = 0xf0u16;
    const NT_FILE_CHARACTERISTICS: usize = 0x12usize;
    const NT_FILE_CHARACTERISTICS_EXECUTABLE: u16 = 0x2u16;
    const NT_FILE_CHARACTERISTICS_DLL: u16 = 0x2000u16;
    const NT_OPTIONAL: usize = 0x18usize;
    const NT_OPTIONAL_MAGIC: usize = 0x0usize;
    const NT_OPTIONAL_MAGIC_32: u16 = 0x10bu16;
    const NT_OPTIONAL_MAGIC_64: u16 = 0x20bu16;
    const NT_OPTIONAL_ENTRY_POINT: usize = 0x10usize;
    const NT_OPTIONAL_IMAGE_BASE: usize = 0x18usize;
    const NT_OPTIONAL_NUM_DIRECTORY: usize = 0x6cusize;
    const NT_OPTIONAL_NUM_DIRECTORY_VALUE: u32 = 0x10u32;
    const NT_OPTIONAL_DIRECTORY: usize = 0x88usize;
    const NT_OPTIONAL_DIRECTORY_IMPORTS: usize = 0x1usize;
    const NT_OPTIONAL_DIRECTORY_FUNCTIONS: usize = 0x3usize;
    const NT_OPTIONAL_DIRECTORY_ENTRY_LEN: usize = 0x4usize;
    const NT_OPTIONAL_DIRECTORY_ENTRY_SIZE: usize = 0x0usize;
    const NT_OPTIONAL_DIRECTORY_ENTRY_POINTER: usize = 0x4usize;
    const NT_SECTION_LEN: usize = 0x28usize;
    const NT_SECTION_NAME: usize = 0x0usize;
    const NT_SECTION_NAME_LEN: usize = 0x8usize;
    const NT_SECTION_VIRTUAL_SIZE: usize = 0x4usize;
    const NT_SECTION_VIRTUAL_POINTER: usize = 0x8usize;
    const NT_SECTION_RAW_SIZE: usize = 0xcusize;
    const NT_SECTION_RAW_POINTER: usize = 0x10usize;

    #[inline(always)]
    pub const fn new(optional: NtOptional, sections: NtImageSections) -> Self {
        Self { optional, sections }
    }

    #[inline]
    #[instrument(skip(exe), fields(H = type_name::<H>()))]
    pub fn from_exe<H: Debug + ExeHandler>(exe: Exe<H>) -> Result<Self> {
        info!("Getting `NtImage` from `Exe`");

        let mz_base = 0x0usize;
        let nt_base = exe.read_to::<u32>(Self::MZ_NT_POINTER)? as usize;
        let nt_file = nt_base + Self::NT_FILE;
        let nt_optional = nt_base + Self::NT_OPTIONAL;
        let nt_directory = nt_base + Self::NT_OPTIONAL_DIRECTORY;

        let mz = exe.read_to_string(mz_base + Self::MZ_MAGIC, Some(Self::MZ_MAGIC_LEN))?;
        let nt = exe.read_to_string(nt_base + Self::NT_SIGNATURE, Some(Self::NT_SIGNATURE_LEN))?;

        if !(mz == Self::MZ_MAGIC_VALUE && nt == Self::NT_SIGNATURE_VALUE) {
            return Err(eyre!(
                "Either `EXE`'s MZ magic or NT signature are not right: mz = {mz}, nt = {nt}"
            ));
        }

        let characteristics = exe.read_to::<u16>(nt_file + Self::NT_FILE_CHARACTERISTICS)?;

        if characteristics & Self::NT_FILE_CHARACTERISTICS_EXECUTABLE == 0u16
            && characteristics & Self::NT_FILE_CHARACTERISTICS_DLL != 0u16
        {
            return Err(eyre!(
                "`EXE`'s characteristics are not that of SpaceEngine.exe: {:x}",
                characteristics
            ));
        }

        let optional = Self::get_optional(nt_optional, nt_directory, &exe)?;
        let sections = Self::get_sections(nt_file, nt_optional, &exe)?;

        info!(?optional, ?sections, "Successfully got `NtImage` from `Exe`");

        Ok(Self::new(optional, sections))
    }

    #[inline(always)]
    fn get_optional<H>(nt_optional: usize, nt_directory: usize, exe: &Exe<H>) -> Result<NtOptional>
    where
        H: Debug + ExeHandler,
    {
        let magic = exe.read_to::<u16>(nt_optional + Self::NT_OPTIONAL_MAGIC)?;

        // Verify magic is that of a 64-bit executable
        if magic == Self::NT_OPTIONAL_MAGIC_32 {
            return Err(eyre!("`EXE` is a 32-bit executable"));
        } else if magic != Self::NT_OPTIONAL_MAGIC_64 {
            return Err(eyre!("`EXE` is not a 64-bit executable: magic = {magic:x}"));
        }

        // Get fields of NtOptional
        let entry_point = exe.read_to::<u32>(nt_optional + Self::NT_OPTIONAL_ENTRY_POINT)? as usize;
        let image_base = exe.read_to::<u64>(nt_optional + Self::NT_OPTIONAL_IMAGE_BASE)? as usize;

        // Verify number of directories is 16. This should always be true...
        if exe.read_to::<u32>(nt_optional + Self::NT_OPTIONAL_NUM_DIRECTORY)?
            != Self::NT_OPTIONAL_NUM_DIRECTORY_VALUE
        {
            return Err(eyre!("Number of directories in `EXE` is not 16"));
        }

        let directory = Self::get_directory(nt_directory, exe)?;

        Ok(NtOptional::new(entry_point, image_base, directory))
    }

    #[inline(always)]
    fn get_directory<H>(nt_directory: usize, exe: &Exe<H>) -> Result<NtDirectory>
    where
        H: Debug + ExeHandler,
    {
        // Get each entry of directory (at least, the ones that we use!)
        let imports =
            Self::get_directory_entry(nt_directory, Self::NT_OPTIONAL_DIRECTORY_IMPORTS, exe)?;
        let functions =
            Self::get_directory_entry(nt_directory, Self::NT_OPTIONAL_DIRECTORY_FUNCTIONS, exe)?;

        Ok(NtDirectory::new(imports, functions))
    }

    // This is ugly ):
    #[inline(always)]
    fn get_directory_entry<H>(
        nt_directory: usize,
        i: usize,
        exe: &Exe<H>,
    ) -> Result<NtDirectoryEntry>
    where
        H: Debug + ExeHandler,
    {
        // Address of this entry
        let base = nt_directory + i * Self::NT_OPTIONAL_DIRECTORY_ENTRY_LEN;

        let size = exe.read_to::<u32>(base + Self::NT_OPTIONAL_DIRECTORY_ENTRY_SIZE)? as usize;
        let pointer =
            exe.read_to::<u32>(base + Self::NT_OPTIONAL_DIRECTORY_ENTRY_POINTER)? as usize;

        Ok(pointer..pointer + size)
    }

    #[inline(always)]
    fn get_sections<H>(nt_file: usize, nt_optional: usize, exe: &Exe<H>) -> Result<NtImageSections>
    where
        H: Debug + ExeHandler,
    {
        // Verify we're looking at PE32+
        if exe.read_to::<u16>(nt_file + Self::NT_FILE_OPTIONAL_LEN)?
            != Self::NT_FILE_OPTIONAL_LEN_VALUE
        {
            return Err(eyre!("`EXE`'s Optional header is not PE32+"));
        }

        // Address where sections starts
        let base = nt_optional + Self::NT_FILE_OPTIONAL_LEN_VALUE as usize;
        // Number of sections
        let num_sections = exe.read_to::<u16>(nt_file + Self::NT_FILE_NUM_SECTIONS)? as usize;
        // The sections
        let mut sections = NtImageSections::with_capacity(num_sections);

        for i in 0usize..exe.read_to::<u16>(nt_file + Self::NT_FILE_NUM_SECTIONS)? as usize {
            // Address of this section
            let base = base + i * Self::NT_SECTION_LEN;

            let name = exe.read_to_string(
                base + Self::NT_SECTION_NAME,
                Some(Self::NT_SECTION_NAME_LEN),
            )?;
            let raw_size = exe.read_to::<u32>(base + Self::NT_SECTION_RAW_SIZE)? as usize;
            let raw_pointer = exe.read_to::<u32>(base + Self::NT_SECTION_RAW_POINTER)? as usize;
            let virtual_size = exe.read_to::<u32>(base + Self::NT_SECTION_VIRTUAL_SIZE)? as usize;
            let virtual_pointer =
                exe.read_to::<u32>(base + Self::NT_SECTION_VIRTUAL_POINTER)? as usize;

            // Insert this section into sections
            sections.insert(
                name,
                (
                    raw_pointer..raw_pointer + raw_size,
                    virtual_pointer..virtual_pointer + virtual_size,
                ),
            );
        }

        Ok(sections)
    }

    #[inline(always)]
    pub fn optional(&self) -> &NtOptional {
        &self.optional
    }

    #[inline(always)]
    pub fn sections(&self) -> &NtImageSections {
        &self.sections
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
    pub const fn new(entry_point: usize, image_base: usize, directory: NtDirectory) -> Self {
        Self {
            entry_point,
            image_base,
            directory,
        }
    }

    #[inline(always)]
    pub fn entry_point(&self) -> usize {
        self.entry_point
    }

    #[inline(always)]
    pub fn image_base(&self) -> usize {
        self.image_base
    }

    #[inline(always)]
    pub fn directory(&self) -> &NtDirectory {
        &self.directory
    }
}

#[derive(Debug)]
pub struct NtDirectory {
    imports: NtDirectoryEntry,
    functions: NtDirectoryEntry,
}

impl NtDirectory {
    #[inline(always)]
    pub const fn new(imports: NtDirectoryEntry, functions: NtDirectoryEntry) -> Self {
        Self { imports, functions }
    }

    #[inline(always)]
    pub fn imports(&self) -> &NtDirectoryEntry {
        &self.imports
    }

    #[inline(always)]
    pub fn functions(&self) -> &NtDirectoryEntry {
        &self.functions
    }
}
