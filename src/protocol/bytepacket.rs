use crate::UniResult;
use std::str;

pub struct BytePacketReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl BytePacketReader<'_> {
    /// Construct a new BytePacketReader from a byte slice, with the cursor initialized to 0
    pub fn new(buf: &[u8]) -> BytePacketReader {
        BytePacketReader {
            buf,
            pos: 0,
        }
    }

    fn read(&mut self) -> UniResult<u8> {
        if self.pos >= self.buf.len() {
            return Err("End of buffer".into());
        }

        let data = self.buf[self.pos];
        self.pos += 1;

        Ok(data)
    }

    fn read_range(&mut self, len: usize) -> UniResult<&[u8]> {
        if self.pos + len > self.buf.len() {
            return Err("End of buffer".into());
        }
        
        let data = &self.buf[self.pos..self.pos + len];
        self.pos += len;

        Ok(data)
    }

    /// Read 1 byte and step forward
    pub fn read_u8(&mut self) -> UniResult<u8> {
        self.read()
    }

    /// Read 2 bytes and step forward
    pub fn read_u16(&mut self) -> UniResult<u16> {
        let data = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(data)
    }

    /// Read a domain name represented by a sequence of labels as in RFC 1035, and step forward
    pub fn read_name(&mut self) -> UniResult<String> {
        let mut name = "".to_owned();
        let mut delim = "";
        
        loop {
            let len = self.read()? as usize;
            if len == 0 {
                break
            }

            let subname = str::from_utf8(self.read_range(len)?)?;

            name.push_str(delim);
            name.push_str(subname);
            delim = ".";
        }
        
        Ok(name)
    }
}

pub struct BytePacketWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl BytePacketWriter<'_> {
    /// Construct a new BytePacketWrite from a mutable byte slice, with the cursor initialized to 0
    pub fn new(buf: &mut [u8]) -> BytePacketWriter {
        BytePacketWriter {
            buf,
            pos: 0,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    fn write(&mut self, data: u8) -> UniResult<()> {
        if self.pos >= self.buf.len() {
            return Err("End of buffer".into());
        }

        self.buf[self.pos] = data;
        self.pos += 1;

        Ok(())
    }

    /// Write 1 byte and step forward
    pub fn write_u8(&mut self, data: u8) -> UniResult<()> {
        self.write(data)
    }

    /// Write 2 bytes and step forward
    pub fn write_u16(&mut self, data: u16) -> UniResult<()> {
        self.write((data >> 8) as u8)?;
        self.write(data as u8)
    }

    /// Write 4 bytes and step forward
    pub fn write_u32(&mut self, data: u32) -> UniResult<()> {
        self.write((data >> 24) as u8)?;
        self.write((data >> 16) as u8)?;
        self.write((data >> 8) as u8)?;
        self.write(data as u8)
    }

    /// Write a domain name in the form of a sequence of labels as in RFC 1035, and step forward
    pub fn write_name(&mut self, name: &str) -> UniResult<()> {
        for label in name.split(".") {
            let len = label.len();
            if len > 0xFF {
                return Err("Single label to long".into())
            }

            self.write(len as u8)?;
            for byte in label.as_bytes() {
                self.write(*byte)?;
            }
        }

        self.write(0)
    }
}
