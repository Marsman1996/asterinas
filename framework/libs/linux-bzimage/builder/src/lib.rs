//! The linux bzImage builder.
//!
//! This crate is responsible for building the bzImage. It contains methods to build
//! the setup binary (with source provided in another crate) and methods to build the
//! bzImage from the setup binary and the kernel ELF.
//!
//! We should build the asterinas kernel as an ELF file, and feed it to the builder to
//! generate the bzImage. The builder will generate the PE/COFF header for the setup
//! code and concatenate it to the ELF file to make the bzImage.
//!
//! The setup code should be built into the ELF target and we convert it to a flat binary
//! in the builder.

mod mapping;
mod pe_header;

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use xmas_elf::program::SegmentData;

use mapping::{SetupFileOffset, SetupVA};

/// We need a flat binary which satisfies PA delta == File offset delta,
/// and objcopy does not satisfy us well, so we should parse the ELF and
/// do our own objcopy job.
///
/// Interstingly, the resulting binary should be the same as the memory
/// dump of the kernel setup header when it's loaded by the bootloader.
fn to_flat_binary(elf_file: &[u8]) -> Vec<u8> {
    let elf = xmas_elf::ElfFile::new(&elf_file).unwrap();
    let mut bin = Vec::<u8>::new();

    for program in elf.program_iter() {
        if program.get_type().unwrap() == xmas_elf::program::Type::Load {
            let SegmentData::Undefined(header_data) = program.get_data(&elf).unwrap() else {
                panic!("Unexpected segment data type");
            };
            let dst_file_offset = usize::from(SetupFileOffset::from(SetupVA::from(
                program.virtual_addr() as usize,
            )));
            let dst_file_length = program.file_size() as usize;
            if bin.len() < dst_file_offset + dst_file_length {
                bin.resize(dst_file_offset + dst_file_length, 0);
            }
            let dest_slice = bin[dst_file_offset..dst_file_offset + dst_file_length].as_mut();
            dest_slice.copy_from_slice(header_data);
        }
    }

    bin
}

/// This function sould be used when generating the Linux x86 Boot setup header.
/// Some fields in the Linux x86 Boot setup header should be filled after assembled.
/// And the filled fields must have the bytes with values of 0xAB. See
/// `framework/aster-frame/src/arch/x86/boot/linux_boot/setup/src/header.S` for more
/// info on this mechanism.
fn fill_header_field(header: &mut [u8], offset: usize, value: &[u8]) {
    let size = value.len();
    assert_eq!(
        &header[offset..offset + size],
        vec![0xABu8; size].as_slice(),
        "The field {:#x} to be filled must be marked with 0xAB",
        offset
    );
    header[offset..offset + size].copy_from_slice(value);
}

fn fill_legacy_header_fields(
    header: &mut [u8],
    kernel_len: usize,
    setup_len: usize,
    payload_offset: SetupVA,
) {
    fill_header_field(
        header,
        0x248, /* payload_offset */
        &(usize::from(payload_offset) as u32).to_le_bytes(),
    );

    fill_header_field(
        header,
        0x24C, /* payload_length */
        &(kernel_len as u32).to_le_bytes(),
    );

    fill_header_field(
        header,
        0x260, /* init_size */
        &((setup_len + kernel_len) as u32).to_le_bytes(),
    );
}

/// The type of the bzImage that we are building through `make_bzimage`.
///
/// Currently, Legacy32 and Efi64 are mutually exclusive.
pub enum BzImageType {
    Legacy32,
    Efi64,
}

pub fn make_bzimage(
    image_path: &Path,
    kernel_path: &Path,
    image_type: BzImageType,
    setup_src: &Path,
    setup_out: &Path,
) {
    let setup = match image_type {
        BzImageType::Legacy32 => {
            let arch = setup_src
                .join("x86_64-i386_pm-none.json")
                .canonicalize()
                .unwrap();
            build_setup_with_arch(setup_src, setup_out, &SetupBuildArch::Other(arch))
        }
        BzImageType::Efi64 => build_setup_with_arch(setup_src, setup_out, &SetupBuildArch::X86_64),
    };

    let mut setup_elf = Vec::new();
    File::open(setup)
        .unwrap()
        .read_to_end(&mut setup_elf)
        .unwrap();
    let mut setup = to_flat_binary(&setup_elf);
    // Pad the header with 8-byte alignment.
    setup.resize((setup.len() + 7) & !7, 0x00);

    let mut kernel = Vec::new();
    File::open(kernel_path)
        .unwrap()
        .read_to_end(&mut kernel)
        .unwrap();
    let payload = kernel;

    let setup_len = setup.len();
    let payload_len = payload.len();
    let payload_offset = SetupFileOffset::from(setup_len);
    fill_legacy_header_fields(&mut setup, payload_len, setup_len, payload_offset.into());

    let mut kernel_image = File::create(image_path).unwrap();
    kernel_image.write_all(&setup).unwrap();
    kernel_image.write_all(&payload).unwrap();

    let image_size = setup_len + payload_len;

    if matches!(image_type, BzImageType::Efi64) {
        // Write the PE/COFF header to the start of the file.
        // Since the Linux boot header starts at 0x1f1, we can write the PE/COFF header directly to the
        // start of the file without overwriting the Linux boot header.
        let pe_header = pe_header::make_pe_coff_header(&setup_elf, image_size);
        assert!(
            pe_header.header_at_zero.len() <= 0x1f1,
            "PE/COFF header is too large"
        );

        kernel_image.seek(SeekFrom::Start(0)).unwrap();
        kernel_image.write_all(&pe_header.header_at_zero).unwrap();
        kernel_image
            .seek(SeekFrom::Start(usize::from(pe_header.relocs.0) as u64))
            .unwrap();
        kernel_image.write_all(&pe_header.relocs.1).unwrap();
    }
}

enum SetupBuildArch {
    X86_64,
    Other(PathBuf),
}

/// Build the setup binary.
///
/// It will return the path to the built setup binary.
fn build_setup_with_arch(source_dir: &Path, out_dir: &Path, arch: &SetupBuildArch) -> PathBuf {
    if !out_dir.exists() {
        std::fs::create_dir_all(&out_dir).unwrap();
    }
    let out_dir = std::fs::canonicalize(out_dir).unwrap();

    // Relocations are fewer in release mode. That's why the release mode is more stable than
    // the debug mode.
    let profile = "release";

    let cargo = std::env::var("CARGO").unwrap();
    let mut cmd = std::process::Command::new(cargo);
    cmd.current_dir(source_dir);
    cmd.arg("build");
    if profile == "release" {
        cmd.arg("--release");
    }
    cmd.arg("--package").arg("linux-bzimage-setup");
    cmd.arg("--target").arg(match arch {
        SetupBuildArch::X86_64 => "x86_64-unknown-none",
        SetupBuildArch::Other(path) => path.to_str().unwrap(),
    });
    cmd.arg("-Zbuild-std=core,alloc,compiler_builtins");
    cmd.arg("-Zbuild-std-features=compiler-builtins-mem");
    // Specify the build target directory to avoid cargo running
    // into a deadlock reading the workspace files.
    cmd.arg("--target-dir").arg(out_dir.as_os_str());
    cmd.env_remove("RUSTFLAGS");
    cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");

    let mut child = cmd.spawn().unwrap();
    let status = child.wait().unwrap();
    if !status.success() {
        panic!(
            "Failed to build linux x86 setup header:\n\tcommand `{:?}`\n\treturned {}",
            cmd, status
        );
    }

    // Get the path to the setup binary.
    let arch_name = match arch {
        SetupBuildArch::X86_64 => "x86_64-unknown-none",
        SetupBuildArch::Other(path) => path.file_stem().unwrap().to_str().unwrap(),
    };

    let setup_artifact = out_dir
        .join(arch_name)
        .join(profile)
        .join("linux-bzimage-setup");

    setup_artifact.to_owned()
}