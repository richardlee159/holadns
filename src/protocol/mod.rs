mod bytepacket;

use crate::UniResult;
use bytepacket::*;
use std::net::Ipv4Addr;

// pub enum RCode {
//     NoError = 0,
//     FormErr = 1,
//     SevFail = 2,
//     NameErr = 3,
//     NotImpl = 4,
//     Refused = 5,
// }

#[derive(Debug)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    fn new() -> DnsHeader {
        DnsHeader {
            id: 0,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    fn read(&mut self, bpacket: &mut BytePacketReader) -> UniResult<()> {
        self.id = bpacket.read_u16()?;

        let flag1 = bpacket.read_u8()?;
        self.qr = flag1 & 0x80 > 0;
        self.opcode = (flag1 >> 3) & 0x0F;
        self.aa = flag1 & 0x04 > 0;
        self.tc = flag1 & 0x02 > 0;
        self.rd = flag1 & 0x01 > 0;
        let flag2 = bpacket.read_u8()?;
        self.ra = flag2 & 0xF0 > 0;
        self.rcode = flag2 & 0x0F;

        self.qdcount = bpacket.read_u16()?;
        self.ancount = bpacket.read_u16()?;
        self.nscount = bpacket.read_u16()?;
        self.arcount = bpacket.read_u16()?;

        Ok(())
    }

    fn from_byte_packet(bpacket: &mut BytePacketReader) -> UniResult<DnsHeader> {
        let mut header = DnsHeader::new();
        header.read(bpacket)?;
        Ok(header)
    }

    fn write(&self, bpacket: &mut BytePacketWriter) -> UniResult<()> {
        bpacket.write_u16(self.id)?;

        bpacket.write_u8(
            (self.qr as u8) << 7 |
            (self.opcode  ) << 3 |
            (self.aa as u8) << 2 |
            (self.tc as u8) << 1 |
            (self.rd as u8)
        )?;
        bpacket.write_u8(
            (self.ra as u8) << 7 |
            (self.rcode   )
        )?;

        bpacket.write_u16(self.qdcount)?;
        bpacket.write_u16(self.ancount)?;
        bpacket.write_u16(self.nscount)?;
        bpacket.write_u16(self.arcount)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
}

impl DnsQuestion {
    fn new() -> DnsQuestion{
        DnsQuestion {
            qname: "".to_owned(),
            qtype: 0,
        }
    }

    fn read(&mut self, bpacket: &mut BytePacketReader) -> UniResult<()> {
        self.qname = bpacket.read_name()?;
        self.qtype = bpacket.read_u16()?;
        bpacket.read_u16()?;

        Ok(())
    }

    fn from_byte_packet(bpacket: &mut BytePacketReader) -> UniResult<DnsQuestion> {
        let mut question = DnsQuestion::new();
        question.read(bpacket)?;
        Ok(question)
    }

    fn write(&self, bpacket: &mut BytePacketWriter) -> UniResult<()> {
        bpacket.write_name(&self.qname)?;
        bpacket.write_u16(self.qtype)?;
        bpacket.write_u16(1)?;      // QCLASS = IN

        Ok(())
    }
}

#[derive(Debug)]
pub enum DnsRecord {
    A {
        name: String,
        addr: Ipv4Addr,
        ttl: u32,
    }
}

impl DnsRecord {
    fn write(&self, bpacket: &mut BytePacketWriter) -> UniResult<()> {
        match self {
            DnsRecord::A {
                name, addr, ttl,
            } => {
                bpacket.write_name(name)?;
                bpacket.write_u16(1)?;      // TYPE = A
                bpacket.write_u16(1)?;      // CLASS = IN
                bpacket.write_u32(*ttl)?;
                bpacket.write_u16(4)?;      // RDLENGTH = 4 bytes
                
                for &octet in addr.octets().iter() {
                    bpacket.write_u8(octet)?;
                }
            }
        }
        
        Ok(())
    }
}

#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsPacket {
    fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    /// Construct a new (request) DnsPacket from bytes
    pub fn from(buf: &[u8]) -> UniResult<DnsPacket> {
        let mut res = DnsPacket::new();

        let mut bpacket = BytePacketReader::new(buf);
        let bpacket = &mut bpacket;
        
        res.header = DnsHeader::from_byte_packet(bpacket)?;

        for _ in 0..res.header.qdcount {
            let question = DnsQuestion::from_byte_packet(bpacket)?;
            res.questions.push(question);
        }

        Ok(res)
    }

    /// Write a DnsPacket into bytes
    pub fn write(&self, buf: &mut [u8]) -> UniResult<usize> {
        let mut bpacket = BytePacketWriter::new(buf);
        let bpacket = &mut bpacket;

        self.header.write(bpacket)?;

        for question in &self.questions {
            question.write(bpacket)?;
        }
        for answer in &self.answers {
            answer.write(bpacket)?;
        }
        for authority in &self.authorities {
            authority.write(bpacket)?;
        }
        for additional in &self.additionals {
            additional.write(bpacket)?;
        }
        
        Ok(bpacket.pos())
    }
}

// pub fn get_id(buf: &[u8]) -> UniResult<u16> {
//     let mut bpacket = BytePacketReader::new(buf);
//     bpacket.read_u16()
// }