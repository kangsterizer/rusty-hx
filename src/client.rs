use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::timeout;
use std::time::Duration;
use bytes::{Buf, BytesMut};
use std::io::Cursor;
use crate::protocol::*;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use rc4::{Rc4, KeyInit, StreamCipher};

type HmacSha1 = Hmac<Sha1>;

enum ReaderCommand {
    EnableCipher(Vec<u8>),
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub enum ClientCommand {
    Connect(String),
    Login(String, String, Option<String>, u16),
    Chat(String),
    RefreshUsers,
    GetUserInfo(u32),
    SendPrivateMessage(u32, String),
    GetNews,
    ListFiles(Vec<String>),
    SendAgreement(String, u16),
    AdminAccountRead(String),
    ChangeNick(String),
    ChangeIcon(u16),
    FetchTracker(String),
    EnableCipher(Vec<u8>),
    #[allow(dead_code)]
    Quit,
}

pub enum ClientEvent {
    Connected,
    TaskSuccess(u32),
    Disconnected,
    Error(String),
    UserList(Vec<User>),
    ChatMsg(String),
    Log(String),
    Debug(String),
    UserInfo(String),
    News(String),
    FileList(Vec<FileItem>),
    UserAccess(String),
    Agreement(String),
    UserUpdate(User),
    UserLeft(u32),
    TrackerServerList(String, Vec<TrackerServer>),
    CipherInit(Vec<u8>),
    Encrypted,
}

async fn fetch_tracker_servers(addr: String, event_tx: mpsc::Sender<ClientEvent>) {
    let target = if addr.contains(':') { addr.clone() } else { format!("{}:5498", addr) };
    
    let _ = event_tx.send(ClientEvent::Log(format!("Connecting to tracker {}...", target))).await;
    
    let stream = match TcpStream::connect(&target).await {
        Ok(s) => {
            let _ = s.set_nodelay(true);
            s
        }
        Err(e) => {
            let _ = event_tx.send(ClientEvent::Error(format!("Tracker connection failed: {}", e))).await;
            return;
        }
    };
    
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Send Request: HTRK (4) + Version 1 (2)
    let mut req = BytesMut::new();
    req.extend_from_slice(&0x4854524Bu32.to_be_bytes()); // HTRK
    req.extend_from_slice(&1u16.to_be_bytes()); // Version 1
    
    if let Err(e) = write_half.write_all(&req).await {
         let _ = event_tx.send(ClientEvent::Error(format!("Tracker write failed: {}", e))).await;
         return;
    }
    let _ = write_half.flush().await;

    // Read Response header: HTRK (4) + Ver (2) + Type (2) + Size (2) + Count (2) + Count (2)
    let mut header = [0u8; 14];
    if let Err(e) = reader.read_exact(&mut header).await {
         let _ = event_tx.send(ClientEvent::Error(format!("Tracker read header failed: {}", e))).await;
         return;
    }
    
    let mut curs = Cursor::new(&header);
    let magic = curs.get_u32();
    if magic != 0x4854524B {
         let _ = event_tx.send(ClientEvent::Error("Invalid tracker magic".to_string())).await;
         return;
    }
    
    let _ver = curs.get_u16();
    let _msg_type = curs.get_u16();
    let _data_size = curs.get_u16(); 
    let num_servers = curs.get_u16();
    let _num_servers_check = curs.get_u16();
    
    let _ = event_tx.send(ClientEvent::Debug(format!("Tracker reports {} servers.", num_servers))).await;

    let mut servers = Vec::new();
    
    for i in 0..num_servers {
        // Read fixed part
        let mut fixed = [0u8; 11];
        let read_fixed = timeout(Duration::from_secs(5), reader.read_exact(&mut fixed));
        if let Ok(res) = read_fixed.await {
             if let Err(e) = res {
                 let _ = event_tx.send(ClientEvent::Error(format!("Error reading server {} fixed data: {}", i, e))).await;
                 break;
             }
        } else {
             let _ = event_tx.send(ClientEvent::Error(format!("Timeout reading server {} fixed data", i))).await;
             break;
        }
        
        let mut fcurs = Cursor::new(&fixed);
        let ip = fcurs.get_u32();
        let port = fcurs.get_u16();
        let users = fcurs.get_u16();
        let _unused = fcurs.get_u16();
        let name_len = fcurs.get_u8() as usize;
        
        // Read Name
        let mut name_bytes = vec![0u8; name_len];
        let read_name = timeout(Duration::from_secs(5), reader.read_exact(&mut name_bytes));
        if let Ok(res) = read_name.await {
             if let Err(e) = res {
                 let _ = event_tx.send(ClientEvent::Error(format!("Error reading server {} name: {}", i, e))).await;
                 break;
             }
        } else {
             let _ = event_tx.send(ClientEvent::Error(format!("Timeout reading server {} name", i))).await;
             break;
        }
        let name = String::from_utf8_lossy(&name_bytes).to_string();
        
        // Read Desc Len
        let mut desc_len_buf = [0u8; 1];
        let read_dlen = timeout(Duration::from_secs(5), reader.read_exact(&mut desc_len_buf));
        if let Ok(res) = read_dlen.await {
             if let Err(e) = res {
                 let _ = event_tx.send(ClientEvent::Error(format!("Error reading server {} desc len: {}", i, e))).await;
                 break;
             }
        } else {
             let _ = event_tx.send(ClientEvent::Error(format!("Timeout reading server {} desc len", i))).await;
             break;
        }
        let desc_len = desc_len_buf[0] as usize;
        
        // Read Desc
        let mut desc_bytes = vec![0u8; desc_len];
        let read_desc = timeout(Duration::from_secs(5), reader.read_exact(&mut desc_bytes));
        if let Ok(res) = read_desc.await {
             if let Err(e) = res {
                 let _ = event_tx.send(ClientEvent::Error(format!("Error reading server {} desc: {}", i, e))).await;
                 break;
             }
        } else {
             let _ = event_tx.send(ClientEvent::Error(format!("Timeout reading server {} desc", i))).await;
             break;
        }
        let description = String::from_utf8_lossy(&desc_bytes).to_string();
        
        servers.push(TrackerServer {
            ip, port, users, name, description
        });
    }
    
    let _ = event_tx.send(ClientEvent::TrackerServerList(addr, servers)).await;
}

pub async fn run_client(mut cmd_rx: mpsc::Receiver<ClientCommand>, event_tx: mpsc::Sender<ClientEvent>) {
    let mut writer: Option<tokio::net::tcp::OwnedWriteHalf> = None;
    let mut reader_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut next_trans_id = 1u32;
    let mut ping_interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
    ping_interval.tick().await;

    let mut reader_cmd_tx: Option<mpsc::Sender<ReaderCommand>> = None;
    let mut login_password: Option<String> = None;
    let mut cipher_encoder: Option<Rc4<rc4::consts::U20>> = None; // SHA1 is 20 bytes

    loop {
        let _ = event_tx.try_send(ClientEvent::Debug("run_client loop tick".to_string()));
        tokio::select! {
            _ = ping_interval.tick() => {
                if let Some(w) = &mut writer {
                    let tx = Transaction::new(HTLC_HDR_PING, next_trans_id, vec![]);
                    next_trans_id += 1;
                    let mut buf = BytesMut::new();
                    tx.encode(&mut buf);
                    if let Some(enc) = &mut cipher_encoder {
                        enc.apply_keystream(&mut buf);
                    }
                    let _ = w.write_all(&buf).await;
                }
            }
            cmd = cmd_rx.recv() => {
                if let Some(ref c) = cmd {
                     // Debug log for command tracing (simple version)
                     let cmd_name = match c {
                         ClientCommand::Connect(_) => "Connect",
                         ClientCommand::Login(_,_,_,_) => "Login",
                         ClientCommand::Chat(_) => "Chat",
                         ClientCommand::RefreshUsers => "RefreshUsers",
                         ClientCommand::GetUserInfo(_) => "GetUserInfo",
                         ClientCommand::SendPrivateMessage(_,_) => "SendPrivateMessage",
                         ClientCommand::GetNews => "GetNews",
                         ClientCommand::ListFiles(_) => "ListFiles",
                         ClientCommand::SendAgreement(_,_) => "SendAgreement",
                         ClientCommand::AdminAccountRead(_) => "AdminAccountRead",
                         ClientCommand::ChangeNick(_) => "ChangeNick",
                         ClientCommand::ChangeIcon(_) => "ChangeIcon",
                         ClientCommand::FetchTracker(_) => "FetchTracker",
                         ClientCommand::EnableCipher(_) => "EnableCipher",
                         ClientCommand::Quit => "Quit",
                     };
                     let _ = event_tx.try_send(ClientEvent::Debug(format!("Processing Cmd: {} (NextTransID={})", cmd_name, next_trans_id)));
                }

                match cmd {
                    Some(ClientCommand::FetchTracker(addr)) => {
                         let tx = event_tx.clone();
                         tokio::spawn(async move {
                             fetch_tracker_servers(addr, tx).await;
                         });
                    }
                    Some(ClientCommand::Connect(addr)) => {
                        if let Some(h) = reader_handle.take() { h.abort(); }
                        writer = None;
                        reader_cmd_tx = None;
                        cipher_encoder = None;

                        event_tx.send(ClientEvent::Log(format!("Connecting to {}...", addr))).await.unwrap();

                        match TcpStream::connect(&addr).await {
                            Ok(s) => {
                                if let Err(e) = s.set_nodelay(true) {
                                    event_tx.send(ClientEvent::Log(format!("Failed to set nodelay: {}", e))).await.unwrap();
                                }

                                let (mut read_half, mut write_half) = s.into_split();

                                // Handshake
                                if let Err(e) = write_half.write_all(HTLC_MAGIC).await {
                                    event_tx.send(ClientEvent::Error(format!("Write error: {}", e))).await.unwrap();
                                    continue;
                                }
                                let mut magic = [0u8; 8];
                                if let Err(e) = read_half.read_exact(&mut magic).await {
                                    event_tx.send(ClientEvent::Error(format!("Read error: {}", e))).await.unwrap();
                                    continue;
                                }
                                
                                event_tx.send(ClientEvent::Connected).await.unwrap();
                                event_tx.send(ClientEvent::Log("Connected!".to_string())).await.unwrap();

                                writer = Some(write_half);
                                
                                let tx_clone = event_tx.clone();
                                let (rtx, rrx) = mpsc::channel(10);
                                reader_cmd_tx = Some(rtx);
                                
                                reader_handle = Some(tokio::spawn(async move {
                                    run_reader(read_half, tx_clone, rrx).await;
                                }));
                            }
                            Err(e) => {
                                event_tx.send(ClientEvent::Error(format!("Connection failed: {}", e))).await.unwrap();
                            }
                        }
                    }
                    Some(ClientCommand::Login(login, nick, password, icon)) => {
                        if let Some(w) = &mut writer {
                            let _ = event_tx.try_send(ClientEvent::Log(format!("Logging in as {} (User: {})...", nick, login)));
                            login_password = password.clone();
                            
                            let mangled_login = mangle_password(&login);
                            let pwd_data = if let Some(pwd) = password {
                                mangle_password(&pwd)
                            } else {
                                Vec::new()
                            };
                            
                            let mut cipher_list = vec![0u8, 1, 3];
                            cipher_list.extend_from_slice(b"RC4");
                            
                            let mut mac_list = vec![0u8, 1, 9];
                            mac_list.extend_from_slice(b"HMAC-SHA1");

                            let fields = vec![
                                Field { id: HTLC_DATA_ICON, data: icon.to_be_bytes().to_vec() },
                                Field { id: HTLC_DATA_LOGIN, data: mangled_login },
                                Field { id: HTLC_DATA_PASSWORD, data: pwd_data },
                                Field { id: HTLC_DATA_NAME, data: nick.into_bytes() },
                                Field { id: HTLC_DATA_CLIENTVERSION, data: 150u16.to_be_bytes().to_vec() },
                                Field { id: HTLC_DATA_CIPHER_ALG, data: cipher_list },
                                Field { id: HTLC_DATA_MAC_ALG, data: b"HMAC-SHA1".to_vec() },
                            ];

                            let tx = Transaction::new(HTLC_HDR_LOGIN, next_trans_id, fields);
                            next_trans_id += 1;
                            let mut buf = BytesMut::new();
                            tx.encode(&mut buf);
                            if let Some(enc) = &mut cipher_encoder {
                                enc.apply_keystream(&mut buf);
                            }
                            let _ = w.write_all(&buf).await;
                        }
                    }
                    Some(ClientCommand::EnableCipher(session_key)) => {
                        if let Some(pwd) = &login_password {
                            let pwd_bytes = pwd.as_bytes();
                            let real_mac = hmac_sha1(pwd_bytes, &session_key);
                            let server_tx_key = hmac_sha1(pwd_bytes, &real_mac);
                            let server_rx_key = hmac_sha1(pwd_bytes, &server_tx_key);
                            
                            let client_enc_key = server_rx_key;
                            let client_dec_key = server_tx_key;
                            
                            let enc = Rc4::new_from_slice(&client_enc_key).unwrap();
                            cipher_encoder = Some(enc);
                            
                            if let Some(rtx) = &reader_cmd_tx {
                                let _ = rtx.send(ReaderCommand::EnableCipher(client_dec_key)).await;
                            }
                            let _ = event_tx.send(ClientEvent::Encrypted).await;
                        } else {
                             let _ = event_tx.send(ClientEvent::Error("Cannot enable cipher: No password".to_string())).await;
                        }
                    }
                    Some(ClientCommand::Chat(msg)) => {
                        if let Some(w) = &mut writer {
                            let fields = vec![
                                Field { id: HTLS_DATA_CHAT, data: msg.clone().into_bytes() }
                            ];
                            let tx = Transaction::new(HTLC_HDR_CHAT, next_trans_id, fields);
                            next_trans_id += 1;
                            let mut buf = BytesMut::new();
                            tx.encode(&mut buf);
                            if let Some(enc) = &mut cipher_encoder {
                                enc.apply_keystream(&mut buf);
                            }
                            let _ = w.write_all(&buf).await;
                            let _ = event_tx.try_send(ClientEvent::Debug(format!("(Me): {}", msg)));
                        }
                    }
                    Some(ClientCommand::RefreshUsers) => {
                         if let Some(w) = &mut writer {
                            let tx_users = Transaction::new(HTLC_HDR_USER_GETLIST, next_trans_id, vec![]);
                            next_trans_id += 1;
                            let mut buf = BytesMut::new();
                            tx_users.encode(&mut buf);
                            if let Some(enc) = &mut cipher_encoder {
                                enc.apply_keystream(&mut buf);
                            }
                            let _ = w.write_all(&buf).await;
                         }
                    }
                    Some(ClientCommand::GetUserInfo(uid)) => {
                        if let Some(w) = &mut writer {
                            let fields = vec![
                                Field { id: HTLC_DATA_UID, data: uid.to_be_bytes().to_vec() },
                            ];
                            let tx = Transaction::new(HTLC_HDR_USER_GETINFO, next_trans_id, fields);
                            next_trans_id += 1;
                            let mut buf = BytesMut::new();
                            tx.encode(&mut buf);
                            if let Some(enc) = &mut cipher_encoder {
                                enc.apply_keystream(&mut buf);
                            }
                            let _ = w.write_all(&buf).await;
                        }
                    }
                    Some(ClientCommand::SendPrivateMessage(uid, msg)) => {
                        if let Some(w) = &mut writer {
                            let fields = vec![
                                Field { id: HTLC_DATA_UID, data: uid.to_be_bytes().to_vec() },
                                Field { id: HTLC_DATA_MSG, data: msg.clone().into_bytes() },
                            ];
                            let tx = Transaction::new(HTLC_HDR_MSG, next_trans_id, fields);
                            next_trans_id += 1;
                            let mut buf = BytesMut::new();
                            tx.encode(&mut buf);
                            if let Some(enc) = &mut cipher_encoder {
                                enc.apply_keystream(&mut buf);
                            }
                            let _ = w.write_all(&buf).await;
                            let _ = event_tx.send(ClientEvent::ChatMsg(format!("(To UID {}): {}", uid, msg))).await;
                        }
                    }
                    Some(ClientCommand::GetNews) => {
                        if let Some(w) = &mut writer {
                            let tx = Transaction::new(HTLC_HDR_NEWS_GETFILE, next_trans_id, vec![]);
                            next_trans_id += 1;
                            let mut buf = BytesMut::new();
                            tx.encode(&mut buf);
                            if let Some(enc) = &mut cipher_encoder {
                                enc.apply_keystream(&mut buf);
                            }
                            let _ = w.write_all(&buf).await;
                        }
                    }
                    Some(ClientCommand::ListFiles(path)) => {
                        if let Some(w) = &mut writer {
                             let path_data = encode_hotline_path(&path);
                             let fields = vec![
                                 Field { id: HTLC_DATA_DIR, data: path_data }
                             ];
                             let tx = Transaction::new(HTLC_HDR_FILE_LIST, next_trans_id, fields);
                             next_trans_id += 1;
                             let mut buf = BytesMut::new();
                             tx.encode(&mut buf);
                             if let Some(enc) = &mut cipher_encoder {
                                enc.apply_keystream(&mut buf);
                            }
                             let _ = w.write_all(&buf).await;
                        }
                    }
                    Some(ClientCommand::SendAgreement(nick, icon)) => {
                        if let Some(w) = &mut writer {
                             let fields = vec![
                                 Field { id: HTLC_DATA_NAME, data: nick.into_bytes() },
                                 Field { id: HTLC_DATA_ICON, data: icon.to_be_bytes().to_vec() },
                             ];
                             
                             let tx = Transaction::new(HTLC_HDR_AGREEMENTAGREE, next_trans_id, fields);
                             next_trans_id += 1;
                             let mut buf = BytesMut::new();
                             tx.encode(&mut buf);
                             if let Some(enc) = &mut cipher_encoder {
                                enc.apply_keystream(&mut buf);
                            }
                             let _ = w.write_all(&buf).await;
                        }
                    }
                    Some(ClientCommand::AdminAccountRead(login)) => {
                        if let Some(w) = &mut writer {
                             let mangled_login = mangle_password(&login);
                             let fields = vec![
                                 Field { id: HTLC_DATA_LOGIN, data: mangled_login },
                             ];
                             let tx = Transaction::new(HTLC_HDR_ACCOUNT_READ, next_trans_id, fields);
                             next_trans_id += 1;
                             let mut buf = BytesMut::new();
                             tx.encode(&mut buf);
                             if let Some(enc) = &mut cipher_encoder {
                                enc.apply_keystream(&mut buf);
                            }
                             let _ = w.write_all(&buf).await;
                        }
                    }
                    Some(ClientCommand::ChangeNick(new_nick)) => {
                        if let Some(w) = &mut writer {
                             let fields = vec![
                                 Field { id: HTLC_DATA_NAME, data: new_nick.into_bytes() },
                             ];
                             let tx = Transaction::new(HTLC_HDR_USER_CHANGE, next_trans_id, fields);
                             next_trans_id += 1;
                             let mut buf = BytesMut::new();
                             tx.encode(&mut buf);
                             if let Some(enc) = &mut cipher_encoder {
                                enc.apply_keystream(&mut buf);
                            }
                             let _ = w.write_all(&buf).await;
                        }
                    }
                    Some(ClientCommand::ChangeIcon(icon_id)) => {
                        if let Some(w) = &mut writer {
                             let fields = vec![
                                 Field { id: HTLC_DATA_ICON, data: icon_id.to_be_bytes().to_vec() },
                             ];
                             let tx = Transaction::new(HTLC_HDR_USER_CHANGE, next_trans_id, fields);
                             next_trans_id += 1;
                             let mut buf = BytesMut::new();
                             tx.encode(&mut buf);
                             if let Some(enc) = &mut cipher_encoder {
                                enc.apply_keystream(&mut buf);
                            }
                             let _ = w.write_all(&buf).await;
                        }
                    }
                    Some(ClientCommand::Quit) => {
                        break;
                    }
                    None => break,
                }
            }
        }
    }
}

async fn run_reader(mut reader: tokio::net::tcp::OwnedReadHalf, event_tx: mpsc::Sender<ClientEvent>, mut cmd_rx: mpsc::Receiver<ReaderCommand>) {
    let mut buf = BytesMut::with_capacity(4096);
    const MAX_PACKET_SIZE: u32 = 32 * 1024 * 1024; // 32 MB Limit
    let mut cipher_decoder: Option<Rc4<rc4::consts::U20>> = None;

    loop {
        let _ = event_tx.try_send(ClientEvent::Debug("run_reader waiting for data".to_string()));
        
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(ReaderCommand::EnableCipher(key)) => {
                        let dec = Rc4::new_from_slice(&key).unwrap();
                        cipher_decoder = Some(dec);
                        let _ = event_tx.send(ClientEvent::Log("Decryption Enabled (RC4-160)".to_string())).await;
                    }
                    None => break,
                }
            }
            read_res = reader.read_buf(&mut buf) => {
                let n = match read_res {
                    Ok(n) => n,
                    Err(e) => {
                        let _ = event_tx.try_send(ClientEvent::Log(format!("Reader error: {}", e)));
                        let _ = event_tx.send(ClientEvent::Disconnected).await;
                        break;
                    }
                };
                
                if n == 0 {
                    if buf.is_empty() {
                         let _ = event_tx.try_send(ClientEvent::Log("Reader EOF".to_string()));
                         let _ = event_tx.send(ClientEvent::Disconnected).await;
                         break;
                    } else {
                         let _ = event_tx.try_send(ClientEvent::Log("Reader EOF with partial data".to_string()));
                         let _ = event_tx.send(ClientEvent::Disconnected).await;
                         break;
                    }
                }
                
                if let Some(dec) = &mut cipher_decoder {
                    let len = buf.len();
                    let new_bytes = &mut buf[len-n..];
                    dec.apply_keystream(new_bytes);
                }

                // Process buffer
                loop {
                    if buf.len() < Header::SIZE {
                        break;
                    }
                    // Peek header
                    let mut curs = Cursor::new(&buf[..]);
                    let hdr = match Header::decode(&mut curs) {
                        Ok(h) => h,
                        Err(_) => break, // Wait for more
                    };

                    if hdr.len > MAX_PACKET_SIZE {
                        let _ = event_tx.send(ClientEvent::Error(format!("Packet too large: {} bytes (Max: {})", hdr.len, MAX_PACKET_SIZE))).await;
                        let _ = event_tx.send(ClientEvent::Disconnected).await;
                        return;
                    }
                    
                    let _ = event_tx.try_send(ClientEvent::Debug(format!("RX Trans: Type={} TransID={} Len={} HC={}", hdr.type_id, hdr.trans_id, hdr.len, hdr.hc)));

                    if hdr.type_id == 0x10000 {
                         let _ = event_tx.send(ClientEvent::TaskSuccess(hdr.trans_id)).await;
                    }

                    let body_len = (hdr.len as usize).saturating_sub(2);

                    if buf.len() < (Header::SIZE + body_len) {
                        break; 
                    }

                    buf.advance(Header::SIZE);
                    let body = buf.split_to(body_len);

                    let mut fields = Vec::new();
                    let mut body_curs = Cursor::new(&body[..]);
                    while body_curs.has_remaining() {
                        if let Ok(f) = Field::decode(&mut body_curs) {
                            fields.push(f);
                        } else {
                            let _ = event_tx.try_send(ClientEvent::Log("Failed to decode field".to_string()));
                            break;
                        }
                    }
                    
                    let mut users = Vec::new();
                    let mut chat_msg = String::new();
                    let mut sender = String::new();
                    let mut user_info_str = String::new();
                    let mut news_content = String::new();
                    let mut uid_info = 0u32;
                    let mut name_info = String::new();
                    let mut login_info = String::new();
                    let mut icon_info = 0u16;
                    let mut color_info = 0u16;
                    let mut generic_text_101 = String::new();
                    let mut file_list = Vec::new();
                    let mut acct_login = String::new();
                    let mut acct_name = String::new();
                    let mut acct_access = Vec::new();
                    let mut agreement_text = String::new();

                    for f in fields {
                        if f.id == HTLS_DATA_USER_LIST {
                             match User::from_field(&f) {
                                 Ok(u) => users.push(u),
                                 Err(e) => { let _ = event_tx.try_send(ClientEvent::Log(format!("Bad User Field: {}", e))); }
                             }
                        } else if f.id == HTLC_DATA_ACCESS {
                             acct_access = f.data.clone();
                        } else if f.id == HTLS_DATA_FILE_LIST {
                             match FileItem::from_field(&f) {
                                 Ok(item) => file_list.push(item),
                                 Err(e) => { let _ = event_tx.try_send(ClientEvent::Log(format!("Bad File Field: {}", e))); }
                             }
                        } else if f.id == HTLS_DATA_CHAT {
                             generic_text_101 = String::from_utf8_lossy(&f.data).replace('\r', "\n");
                        } else if f.id == HTLC_DATA_NAME {
                             let s = String::from_utf8_lossy(&f.data).replace('\r', "\n");
                             sender = s.clone(); name_info = s.clone(); acct_name = s;
                        } else if f.id == HTLS_DATA_SENDER {
                             if f.data.len() == 4 { uid_info = u32::from_be_bytes([f.data[0], f.data[1], f.data[2], f.data[3]]); }
                             else if f.data.len() == 2 { uid_info = u16::from_be_bytes([f.data[0], f.data[1]]) as u32; }
                        } else if f.id == HTLC_DATA_LOGIN {
                             let s = String::from_utf8_lossy(&f.data).replace('\r', "\n");
                             login_info = s.clone(); acct_login = s;
                        } else if f.id == HTLC_DATA_ICON {
                             if f.data.len() == 2 { icon_info = u16::from_be_bytes([f.data[0], f.data[1]]); }
                        } else if f.id == HTLS_DATA_COLOR {
                             if f.data.len() == 2 { color_info = u16::from_be_bytes([f.data[0], f.data[1]]); }
                        } else if f.id == HTLS_DATA_TASKERROR {
                            let err_msg = String::from_utf8_lossy(&f.data).replace('\r', "\n");
                            let _ = event_tx.send(ClientEvent::Error(format!("Server Error: {}", err_msg))).await;
                        } else if f.id == HTLS_DATA_SERVER_NAME {
                            let server_name = String::from_utf8_lossy(&f.data).replace('\r', "\n");
                            let _ = event_tx.try_send(ClientEvent::Log(format!("Server Name: {}", server_name)));
                        } else if f.id == HTLS_DATA_SESSIONKEY {
                            let _ = event_tx.send(ClientEvent::CipherInit(f.data.clone())).await;
                        }
                    }

                    if !generic_text_101.is_empty() {
                        if hdr.type_id == HTLS_HDR_CHAT || hdr.type_id == HTLS_HDR_MSG { chat_msg = generic_text_101; }
                        else if hdr.type_id == HTLS_HDR_AGREEMENT { agreement_text = generic_text_101; }
                        else if hdr.type_id == 0x10000 {
                            if name_info.is_empty() && login_info.is_empty() && icon_info == 0 { news_content = generic_text_101; }
                            else { user_info_str = generic_text_101; }
                        } else { user_info_str = generic_text_101; }
                    }

                    if !users.is_empty() { let _ = event_tx.send(ClientEvent::UserList(users)).await; }
                    if !file_list.is_empty() { 
                        let et = event_tx.clone(); let fl = file_list.clone(); 
                        tokio::spawn(async move { let _ = et.send(ClientEvent::FileList(fl)).await; }); 
                    }
                    if !acct_access.is_empty() {
                        let et = event_tx.clone(); let al = acct_login.clone(); let an = acct_name.clone(); let aa = acct_access.clone();
                        tokio::spawn(async move {
                            let ah = aa.iter().map(|b| format!("{:02X}", b)).collect::<String>();
                            let i = format!("User Access Info:\n  Login: {}\n  Name: {}\n  Access: {}", al, an, ah);
                            let _ = et.send(ClientEvent::UserAccess(i)).await;
                        });
                    }
                    if !chat_msg.is_empty() {
                        let fm = if !sender.is_empty() && hdr.type_id == HTLS_HDR_MSG { format!("[From {} (UID {})]: {}", sender, uid_info, chat_msg) }
                        else if !sender.is_empty() { format!("{}: {}", sender, chat_msg) }
                        else { chat_msg };
                        let _ = event_tx.send(ClientEvent::ChatMsg(fm)).await;
                    }
                    if !user_info_str.is_empty() {
                        let et = event_tx.clone(); let ni = name_info.clone(); let li = login_info.clone(); let ii = icon_info; let ui = user_info_str.clone();
                        tokio::spawn(async move { let _ = et.send(ClientEvent::UserInfo(format!("User Info - Nick: {} Login: {} Icon: {} Details: {}", ni, li, ii, ui))).await; });
                    }
                    if !news_content.is_empty() {
                         let et = event_tx.clone(); let nc = news_content.clone();
                         tokio::spawn(async move { let _ = et.send(ClientEvent::News(nc)).await; });
                    }
                    if !agreement_text.is_empty() {
                         let et = event_tx.clone(); let at = agreement_text.clone();
                         tokio::spawn(async move { let _ = et.send(ClientEvent::Agreement(at)).await; });
                    }
                    
                    if hdr.type_id == HTLS_HDR_USER_CHANGE {
                        let et = event_tx.clone(); let u = User { uid: uid_info as u16, icon: icon_info, color: color_info, name: name_info.clone() };
                        tokio::spawn(async move { let _ = et.send(ClientEvent::UserUpdate(u)).await; });
                    } else if hdr.type_id == HTLS_HDR_USER_PART {
                        let et = event_tx.clone(); let ui = uid_info;
                        tokio::spawn(async move { let _ = et.send(ClientEvent::UserLeft(ui)).await; });
                    }
                }
            }
        }
    }
}
