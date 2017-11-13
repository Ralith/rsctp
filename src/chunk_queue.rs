use std::cmp;
use std::ptr;
use std::marker::PhantomData;

use byteorder::{ByteOrder, NetworkEndian};

use chunk::{self, Param, Chunk};

pub struct ChunkQueue {
    storage: Box<[u8]>,
    cursor: usize,
}

impl ChunkQueue {
    pub fn new() -> Self {
        ChunkQueue {
            storage: vec![0; 8 * 1024].into_boxed_slice(),
            cursor: 0,
        }
    }

    pub fn push<T: chunk::Type>(&mut self, x: T) -> ParamsBuilder<T> {
        let size = T::size() as usize + 4;
        self.ensure_free(size);
        let start = self.cursor;
        let end = start + size;
        Chunk {
            length: Chunk::<T>::size(),
            flags: 0.into(),
            value: x
        }.encode(&mut self.storage[start..end]);
        ParamsBuilder { start: end, queue: self, chunk_length: T::size() + 4, _flags: PhantomData }
    }

    pub fn clear(&mut self) { self.cursor = 0 }

    pub fn iter(&self) -> Iter { Iter(&self.storage[..self.cursor]) }
    pub fn is_empty(&self) -> bool { self.cursor == 0 }

    fn free(&self) -> usize {
        self.storage.len() - self.cursor
    }

    fn ensure_free(&mut self, size: usize) {
        if size > self.free() {
            let mut storage = vec![0; cmp::max(self.cursor + size, self.storage.len() * 2)].into_boxed_slice();
            unsafe {
                ptr::copy_nonoverlapping(self.storage.as_ptr(), storage.as_mut_ptr(), self.storage.len());
            }
            self.storage = storage;
        }
    }
}
    
pub struct ParamsBuilder<'a, T> {
    start: usize,
    queue: &'a mut ChunkQueue,
    chunk_length: u16,
    _flags: PhantomData<fn(T)>,
}

impl<'a, T> ParamsBuilder<'a, T> {
    pub fn flags(&mut self, x: T::Flags) -> &mut Self
        where T: chunk::Type
    {
        let flags_field = self.queue.cursor + 1;
        self.queue.storage[flags_field] = x.into();
        self
    }

    pub fn param<'b, P: chunk::Param<'b>>(&mut self, x: P) -> &mut Self {
        let total_param_size = x.dynamic_size() + 4;
        self.queue.ensure_free(total_param_size as usize);
        let start = self.queue.cursor + self.chunk_length as usize;
        {
            let mem = &mut self.queue.storage[start..start + (total_param_size as usize)];
            NetworkEndian::write_u16(&mut mem[0..2], P::TYPE);
            NetworkEndian::write_u16(&mut mem[2..4], total_param_size);
            x.encode(&mut mem[4..]);
        }
        self.chunk_length += total_param_size;
        self
    }

    pub fn raw_param(&mut self, ty: u16, value: &[u8]) -> &mut Self {
        let total_param_size = value.len() as u16 + 4;
        self.queue.ensure_free(total_param_size as usize);
        {
            let start = self.queue.cursor + self.chunk_length as usize;
            let mem = &mut self.queue.storage[start..start + (total_param_size as usize)];
            NetworkEndian::write_u16(&mut mem[0..2], ty);
            NetworkEndian::write_u16(&mut mem[2..4], total_param_size);
            mem[4..].copy_from_slice(value);
        }
        self.chunk_length += total_param_size;
        self
    }
}

impl<'a, F> Drop for ParamsBuilder<'a, F> {
    fn drop(&mut self) {
        let length_field = self.queue.cursor + 2;
        NetworkEndian::write_u16(&mut self.queue.storage[length_field..length_field+2], self.chunk_length);
        self.queue.cursor += self.chunk_length as usize;
    }
}

pub struct Iter<'a>(&'a [u8]);

impl<'a> Iterator for Iter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.0.is_empty() { return None; }
        let len = NetworkEndian::read_u16(&self.0[2..4]) as usize;
        debug_assert!(len >= 4);
        let result = &self.0[0..len];
        self.0 = &self.0[len..];
        Some(result)
    }
}

impl<'a> IntoIterator for &'a ChunkQueue {
    type Item = &'a [u8];
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Iter<'a> { self.iter() }
}
