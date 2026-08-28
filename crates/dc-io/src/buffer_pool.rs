use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

pub struct AlignedBuffer {
    ptr: NonNull<u8>,
    len: usize,
    capacity: usize,
}

unsafe impl Send for AlignedBuffer {}
unsafe impl Sync for AlignedBuffer {}

impl AlignedBuffer {
    pub fn allocate(size: usize, alignment: usize) -> Result<Self, std::io::Error> {
        let alignment = alignment.max(4096);
        // Ensure size is multiple of alignment
        let capacity = (size + alignment - 1) & !(alignment - 1);

        let mut raw_ptr: *mut libc::c_void = std::ptr::null_mut();
        let ret = unsafe { libc::posix_memalign(&mut raw_ptr, alignment, capacity) };

        if ret != 0 || raw_ptr.is_null() {
            return Err(std::io::Error::from_raw_os_error(ret));
        }

        // Try to lock memory into RAM to prevent paging to swap (ignore EPERM if not privileged)
        unsafe {
            let _ = libc::mlock(raw_ptr, capacity);
            #[cfg(target_os = "linux")]
            let _ = libc::madvise(raw_ptr, capacity, libc::MADV_HUGEPAGE);
        }

        let ptr = NonNull::new(raw_ptr as *mut u8).expect("non-null pointer");

        Ok(Self {
            ptr,
            len: size,
            capacity,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    pub fn ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Deref for AlignedBuffer {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for AlignedBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::munlock(self.ptr.as_ptr() as *mut libc::c_void, self.capacity);
            libc::free(self.ptr.as_ptr() as *mut libc::c_void);
        }
    }
}

pub struct BufferPool {
    buffers: Vec<AlignedBuffer>,
    buffer_size: usize,
}

impl BufferPool {
    pub fn new(count: usize, buffer_size: usize) -> Result<Self, std::io::Error> {
        let mut buffers = Vec::with_capacity(count);
        for _ in 0..count {
            buffers.push(AlignedBuffer::allocate(buffer_size, 4096)?);
        }
        Ok(Self {
            buffers,
            buffer_size,
        })
    }

    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut AlignedBuffer> {
        self.buffers.get_mut(index)
    }

    pub fn len(&self) -> usize {
        self.buffers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffers.is_empty()
    }
}
