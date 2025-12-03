use bytes::{Buf, BytesMut};
use std::io::{self, Cursor};

pub const HTLC_MAGIC: &[u8; 12] = b"TRTPHOTL\0\x01\0\x02";

// Transaction Types
pub const HTLC_HDR_LOGIN: u32 = 0x6b;       // 107
pub const HTLC_HDR_USER_GETLIST: u32 = 0x12c; // 300
pub const HTLC_HDR_CHAT: u32 = 0x69;        // 105
pub const HTLC_HDR_USER_GETINFO: u32 = 0x12f; // 303
pub const HTLC_HDR_MSG: u32 = 0x6c; // 108
pub const HTLC_HDR_USER_CHANGE: u32 = 0x130; // 304

// Data Types (Field Types)
pub const HTLC_DATA_LOGIN: u16 = 0x69;      // 105
pub const HTLC_DATA_NAME: u16 = 0x66;       // 102
pub const HTLC_DATA_PASSWORD: u16 = 0x6a;   // 106
pub const HTLC_DATA_ICON: u16 = 0x68;       // 104
pub const HTLC_DATA_UID: u16 = 0x67;        // 103 (Same as HTLS_DATA_SENDER)
pub const HTLC_DATA_MSG: u16 = 0x65;        // 101 (Same as HTLS_DATA_CHAT, HTLS_DATA_USER_INFO)
pub const HTLC_DATA_CLIENTVERSION: u16 = 0xa0; // 160

pub const HTLS_DATA_USER_LIST: u16 = 0x12c; // 300
pub const HTLS_DATA_CHAT: u16 = 0x65;       // 101
pub const HTLS_DATA_MSG: u16 = 0x65;        // 101
pub const HTLS_DATA_USER_INFO: u16 = 0x65;  // 101
pub const HTLS_DATA_TASKERROR: u16 = 0x64;  // 100
pub const HTLS_DATA_SERVER_NAME: u16 = 0xa2; // 162
pub const HTLS_DATA_SENDER: u16 = 0x67;     // 103 (Same as HTLC_DATA_UID)

pub const HTLS_HDR_MSG: u32 = 0x68; // 104
pub const HTLS_HDR_CHAT: u32 = 0x6a; // 106

#[derive(Debug, Clone)]
pub struct Header {
    pub type_id: u32,
    pub trans_id: u32,
    pub flag: u32,
    pub len: u32, // Size of data
    pub hc: u16,  // Field count
    pub totlen: u32,
}

impl Header {
    pub const SIZE: usize = 22; // 4*5 + 2

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.type_id.to_be_bytes());
        buf.extend_from_slice(&self.trans_id.to_be_bytes());
        buf.extend_from_slice(&self.flag.to_be_bytes());
        buf.extend_from_slice(&self.totlen.to_be_bytes());
        buf.extend_from_slice(&self.len.to_be_bytes());
        buf.extend_from_slice(&self.hc.to_be_bytes());
    }

    pub fn decode(src: &mut Cursor<&[u8]>) -> io::Result<Self> {
        if src.remaining() < Self::SIZE {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Header too short"));
        }
        let type_id = src.get_u32();
        let trans_id = src.get_u32();
        let flag = src.get_u32();
        let totlen = src.get_u32(); 
        let len = src.get_u32();
        let hc = src.get_u16();
        Ok(Self {
            type_id,
            trans_id,
            flag,
            len,
            hc,
            totlen,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Field {
    pub id: u16,
    pub data: Vec<u8>,
}

impl Field {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.data);
    }

    pub fn decode(src: &mut Cursor<&[u8]>) -> io::Result<Self> {
        if src.remaining() < 4 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Field header too short"));
        }
        let id = src.get_u16();
        let len = src.get_u16() as usize;
        if src.remaining() < len {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Field data too short"));
        }
        let mut data = vec![0u8; len];
        src.copy_to_slice(&mut data);
        Ok(Self { id, data })
    }
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub header: Header,
    pub fields: Vec<Field>,
}

impl Transaction {
    pub fn new(type_id: u32, trans_id: u32, fields: Vec<Field>) -> Self {
        let fields_len: u32 = fields.iter().map(|f| 4 + f.data.len() as u32).sum();
        let len = fields_len + 2; // Add 2 bytes for HC (which is part of len but physically in header struct)
        
        // TotLen: It seems mhxd interprets totlen as Data Length (similar to len), or at least not Total Length including header.
        // Setting totlen = len seems to fix the 22-byte desync (Header size).
        
        Self {
            header: Header {
                type_id,
                trans_id,
                flag: 0,
                len,
                hc: fields.len() as u16,
                totlen: len, 
            },
            fields,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        self.header.encode(buf);
        for field in &self.fields {
            field.encode(buf);
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct User {
    pub uid: u16,
    pub icon: u16,
    pub color: u16,
    pub name: String,
}

impl User {
    pub fn from_field(field: &Field) -> io::Result<Self> {
        if field.id != HTLS_DATA_USER_LIST {
             return Err(io::Error::new(io::ErrorKind::InvalidData, "Not a user list field"));
        }
        let mut src = Cursor::new(&field.data);
        if src.remaining() < 8 {
             return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "User data too short"));
        }
        let uid = src.get_u16();
        let icon = src.get_u16();
        let color = src.get_u16();
        let nlen = src.get_u16() as usize;
        if src.remaining() < nlen {
             return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "User name too short"));
        }
        let mut name_bytes = vec![0u8; nlen];
        src.copy_to_slice(&mut name_bytes);
        // Lossy conversion to support non-utf8 names if necessary
        let name = String::from_utf8_lossy(&name_bytes).to_string();
        Ok(Self { uid, icon, color, name })
    }
}
