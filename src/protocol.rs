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
pub const HTLC_HDR_NEWS_GETFILE: u32 = 0x65; // 101
pub const HTLC_HDR_FILE_LIST: u32 = 0xC8;   // 200
pub const HTLC_HDR_AGREEMENTAGREE: u32 = 0x79; // 121
pub const HTLC_HDR_PING: u32 = 0x1F4; // 500
pub const HTLC_HDR_ACCOUNT_READ: u32 = 0x160; // 352

// Data Types (Field Types)
pub const HTLC_DATA_LOGIN: u16 = 0x69;      // 105
pub const HTLC_DATA_NAME: u16 = 0x66;       // 102
pub const HTLC_DATA_PASSWORD: u16 = 0x6a;   // 106
pub const HTLC_DATA_ICON: u16 = 0x68;       // 104
pub const HTLC_DATA_UID: u16 = 0x67;        // 103 (Same as HTLS_DATA_SENDER)
pub const HTLC_DATA_MSG: u16 = 0x65;        // 101 (Same as HTLS_DATA_CHAT, HTLS_DATA_USER_INFO)
pub const HTLC_DATA_DIR: u16 = 0xCA;        // 202
pub const HTLC_DATA_CLIENTVERSION: u16 = 0xa0; // 160
pub const HTLC_DATA_ACCESS: u16 = 0x6E;     // 110

pub const HTLS_DATA_USER_LIST: u16 = 0x12c; // 300
pub const HTLS_DATA_FILE_LIST: u16 = 0xC8;  // 200
pub const HTLS_DATA_CHAT: u16 = 0x65;       // 101
#[allow(dead_code)]
pub const HTLS_DATA_MSG: u16 = 0x65;        // 101
#[allow(dead_code)]
pub const HTLS_DATA_USER_INFO: u16 = 0x65;  // 101
pub const HTLS_DATA_TASKERROR: u16 = 0x64;  // 100
pub const HTLS_DATA_SERVER_NAME: u16 = 0xa2; // 162
pub const HTLS_DATA_SENDER: u16 = 0x67;     // 103 (Same as HTLC_DATA_UID)

pub const HTLS_HDR_MSG: u32 = 0x68; // 104
pub const HTLS_HDR_CHAT: u32 = 0x6a; // 106
pub const HTLS_HDR_AGREEMENT: u32 = 0x6D; // 109
pub const HTLS_HDR_USER_CHANGE: u32 = 0x12D; // 301
pub const HTLS_HDR_USER_PART: u32 = 0x12E; // 302

pub const HTLS_DATA_COLOR: u16 = 0x70; // 112

pub fn mangle_password(pwd: &str) -> Vec<u8> {
    pwd.bytes().map(|b| !b).collect()
}

pub fn encode_hotline_path(path: &[String]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&(path.len() as u16).to_be_bytes());
    for segment in path {
        buf.extend_from_slice(&0u16.to_be_bytes()); // Encoding 0
        let bytes = segment.as_bytes();
        buf.extend_from_slice(&(bytes.len() as u8).to_be_bytes());
        buf.extend_from_slice(bytes);
    }
    buf.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use std::io::Cursor;

    #[test]
    fn test_mangle_password() {
        let input = "guest";
        let expected: Vec<u8> = input.bytes().map(|b| !b).collect();
        assert_eq!(mangle_password(input), expected);
    }

    #[test]
    fn test_encode_hotline_path_root() {
        let path: Vec<String> = vec![];
        let encoded = encode_hotline_path(&path);
        assert_eq!(encoded, vec![0, 0]);
    }

    #[test]
    fn test_encode_hotline_path_subdir() {
        let path = vec!["foo".to_string()];
        let encoded = encode_hotline_path(&path);
        // Count (2) + Enc (2) + Len (1) + "foo" (3) = 8 bytes
        let expected = vec![
            0x00, 0x01, // Count 1
            0x00, 0x00, // Encoding 0
            0x03,       // Len 3
            b'f', b'o', b'o'
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_header_encoding() {
        let header = Header {
            type_id: 107,
            trans_id: 1,
            flag: 0,
            len: 10,
            hc: 2,
            totlen: 10,
        };
        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        assert_eq!(buf.len(), Header::SIZE);
        
        let mut curs = Cursor::new(&buf[..]);
        let decoded = Header::decode(&mut curs).unwrap();
        assert_eq!(decoded.type_id, 107);
        assert_eq!(decoded.trans_id, 1);
        assert_eq!(decoded.hc, 2);
    }

    #[test]
    fn test_transaction_framing() {
        // Verify the +2 logic for length
        let fields = vec![
            Field { id: 1, data: vec![0xAA, 0xBB] }
        ];
        // Field len = 2 (id) + 2 (len) + 2 (data) = 6.
        // Transaction len = fields_len + 2 = 8.
        
        let tx = Transaction::new(1, 1, fields);
        assert_eq!(tx.header.len, 8);
        assert_eq!(tx.header.hc, 1);
        
        let mut buf = BytesMut::new();
        tx.encode(&mut buf);
        // Header (22) + Field (6) = 28 bytes.
        assert_eq!(buf.len(), 28);
    }

    #[test]
    fn test_user_from_field() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_be_bytes()); // UID 1
        data.extend_from_slice(&2u16.to_be_bytes()); // Icon 2
        data.extend_from_slice(&3u16.to_be_bytes()); // Color 3
        data.extend_from_slice(&4u16.to_be_bytes()); // Name Len 4
        data.extend_from_slice(b"test"); // Name

        let field = Field { id: HTLS_DATA_USER_LIST, data };
        let user = User::from_field(&field).unwrap();
        
        assert_eq!(user.uid, 1);
        assert_eq!(user.icon, 2);
        assert_eq!(user.color, 3);
        assert_eq!(user.name, "test");
    }

    #[test]
    fn test_file_item_from_field() {
        let mut data = Vec::new();
        data.extend_from_slice(b"TEXT"); // Type
        data.extend_from_slice(b"ttxt"); // Creator
        data.extend_from_slice(&100u32.to_be_bytes()); // Size
        data.extend_from_slice(&0u32.to_be_bytes()); // Unknown
        data.extend_from_slice(&0u16.to_be_bytes()); // Encoding
        data.extend_from_slice(&8u16.to_be_bytes()); // Name Len
        data.extend_from_slice(b"file.txt"); // Name

        let field = Field { id: HTLS_DATA_FILE_LIST, data };
        let file = FileItem::from_field(&field).unwrap();
        
        assert_eq!(file.name, "file.txt");
        assert_eq!(file.size, 100);
        assert_eq!(file.is_folder, false);
    }
}

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
        let len = fields_len + 2; 
        
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
        // println!("TX Bytes: {:?}", buf.as_ref()); // Cannot print here easily without std::io
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

#[derive(Debug, Clone)]
pub struct FileItem {
    pub name: String,
    #[allow(dead_code)]
    pub ftype: u32,
    #[allow(dead_code)]
    pub fcreator: u32,
    pub size: u32,
    pub is_folder: bool,
}

impl FileItem {
    pub fn from_field(field: &Field) -> io::Result<Self> {
        if field.id != HTLS_DATA_FILE_LIST {
             return Err(io::Error::new(io::ErrorKind::InvalidData, "Not a file list field"));
        }
        // The hl_filelist_hdr in C is:
        // type (2), len (2) <- Already consumed by Field::decode
        // ftype (4), fcreator (4), fsize (4), unknown (4), encoding (2), fnlen (2), name...
        
        let mut src = Cursor::new(&field.data);
        if src.remaining() < 20 { // 4*4 + 2 + 2
             return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "File data too short"));
        }
        let ftype = src.get_u32();
        let fcreator = src.get_u32();
        let fsize = src.get_u32();
        let _unknown = src.get_u32();
        let _encoding = src.get_u16();
        let fnlen = src.get_u16() as usize;
        
        if src.remaining() < fnlen {
             return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "File name too short"));
        }
        
        let mut name_bytes = vec![0u8; fnlen];
        src.copy_to_slice(&mut name_bytes);
        let name = String::from_utf8_lossy(&name_bytes).to_string();
        
        let is_folder = ftype == u32::from_be_bytes(*b"fldr");

        Ok(Self { name, ftype, fcreator, size: fsize, is_folder })
    }
}

#[derive(Debug, Clone)]
pub struct TrackerServer {
    pub ip: u32,
    pub port: u16,
    pub users: u16,
    pub name: String,
    pub description: String,
}