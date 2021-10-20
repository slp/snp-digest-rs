use std::slice;

use libc::{c_char, size_t};
use openssl::sha::Sha384;

mod vmsa;
use vmsa::VMSA_BP;

#[allow(dead_code)]
#[repr(packed)]
struct PageInfo {
    current: [u8; 48],
    contents: [u8; 48],
    length: u16,
    page_type: u8,
    imi_page: u8,
    resv: u32,
    gpa: u64,
}

impl PageInfo {
    fn new(page_type: u8) -> Self {
        PageInfo {
            current: [0; 48],
            contents: [0; 48],
            length: 112,
            page_type,
            imi_page: 0,
            resv: 0,
            gpa: 0,
        }
    }
}

fn digest_blob(blob: &[u8], base_addr: u64, current: &mut [u8]) {
    let iter = blob.chunks(4096).enumerate();

    for (i, page) in iter {
        let mut info = PageInfo::new(1);

        info.current.copy_from_slice(current);

        let mut hasher = Sha384::new();
        hasher.update(page);
        let hash = hasher.finish();
        info.contents.copy_from_slice(&hash);

        info.gpa = base_addr + ((i * 4096) as u64);

        let mut hasher = Sha384::new();
        hasher.update(unsafe { slice::from_raw_parts(&info as *const PageInfo as *const u8, 112) });
        let hash = hasher.finish();
        current.copy_from_slice(&hash);
    }
}

fn digest_zero(base_addr: u64, size: usize, page_type: u8, current: &mut [u8]) {
    let mut i = 0;

    while i < size {
        let mut info = PageInfo::new(page_type);

        info.current.copy_from_slice(current);

        info.gpa = base_addr + i as u64;

        let mut hasher = Sha384::new();
        hasher.update(unsafe { slice::from_raw_parts(&info as *const PageInfo as *const u8, 112) });
        let hash = hasher.finish();
        current.copy_from_slice(&hash);

        i += 4096;
    }
}

fn digest_vmsa(current: &mut [u8]) {
    let mut info = PageInfo::new(2);

    info.current.copy_from_slice(current);

    let mut hasher = Sha384::new();
    hasher.update(&VMSA_BP);
    let hash = hasher.finish();
    info.contents.copy_from_slice(&hash);

    info.gpa = 0xFFFF_FFFF_F000;

    let mut hasher = Sha384::new();
    hasher.update(unsafe { slice::from_raw_parts(&info as *const PageInfo as *const u8, 112) });
    let hash = hasher.finish();
    current.copy_from_slice(&hash);
}

#[link(name = "krunfw")]
extern "C" {
    fn krunfw_get_qboot(size: *mut size_t) -> *mut c_char;
    fn krunfw_get_initrd(size: *mut size_t) -> *mut c_char;
    fn krunfw_get_kernel(load_addr: *mut u64, size: *mut size_t) -> *mut c_char;
}

fn main() {
    let psize = std::mem::size_of::<PageInfo>();
    println!("page_info={}", psize);

    let mut kernel_guest_addr: u64 = 0;
    let mut kernel_size: usize = 0;
    let kernel_host_addr = unsafe {
        krunfw_get_kernel(
            &mut kernel_guest_addr as *mut u64,
            &mut kernel_size as *mut usize,
        )
    };

    let mut qboot_size: usize = 0;
    let qboot_host_addr = unsafe { krunfw_get_qboot(&mut qboot_size as *mut usize) };

    let mut initrd_size: usize = 0;
    let initrd_host_addr = unsafe { krunfw_get_initrd(&mut initrd_size as *mut usize) };

    let qboot_data =
        unsafe { std::slice::from_raw_parts(qboot_host_addr as *const u8, qboot_size) };
    let kernel_data =
        unsafe { std::slice::from_raw_parts(kernel_host_addr as *const u8, kernel_size) };
    let initrd_data =
        unsafe { std::slice::from_raw_parts(initrd_host_addr as *const u8, initrd_size) };

    let mut current: [u8; 48] = [0; 48];

    digest_blob(qboot_data, 0xffff0000, &mut current);
    digest_blob(kernel_data, kernel_guest_addr, &mut current);
    digest_blob(initrd_data, 0xa00000, &mut current);

    digest_zero(0x0, 0x1000, 4, &mut current);

    digest_zero(0x4000, 0x1000, 4, &mut current);

    digest_zero(0x5000, 0x1000, 5, &mut current);

    digest_zero(0x6000, 0x1000, 6, &mut current);

    digest_zero(0x7000, 0x19000, 4, &mut current);

    digest_vmsa(&mut current);
    println!("{:?}", hex::encode(current));
}
