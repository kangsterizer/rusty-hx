use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::timeout;
use std::time::Duration;
use bytes::{Buf, BytesMut};
use std::io::Cursor;
use crate::protocol::*;

pub enum ClientCommand {
    Connect(String),
    Login(String, String, Option<String>),
    Chat(String),
    RefreshUsers,
    GetUserInfo(u32),
    SendPrivateMessage(u32, String),
    GetNews,
    ListFiles(Vec<String>),
    SendAgreement,
    AdminAccountRead(String),
    ChangeNick(String),
    ChangeIcon(u16),
    FetchTracker(String),
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
    UserInfo(String), // New event for displaying user info
    News(String),
    FileList(Vec<FileItem>),
    AccountInfo(String),
    Agreement(String),
    UserUpdate(User),
    UserLeft(u32),
    TrackerServerList(String, Vec<TrackerServer>),
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
        
        // Debug first server parsing
        if i == 0 {
             let _ = event_tx.send(ClientEvent::Debug(format!("Server 0: IP={:x} Port={} Users={} NameLen={}", ip, port, users, name_len))).await;
        }
        
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
        
        if i == 0 {
             let _ = event_tx.send(ClientEvent::Debug(format!("Server 0: Name={} DescLen={}", name, desc_len))).await;
        }
        
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
    let mut ping_interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes
    ping_interval.tick().await; // Consume immediate first tick

    loop {
        let _ = event_tx.try_send(ClientEvent::Debug("run_client loop tick".to_string()));
        tokio::select! {
            _ = ping_interval.tick() => {
                if let Some(w) = &mut writer {
                    // Send Ping
                    // event_tx.send(ClientEvent::Debug("Sending Keep-Alive Ping...".to_string())).await.unwrap();
                    let tx = Transaction::new(HTLC_HDR_PING, next_trans_id, vec![]);
                    next_trans_id += 1;
                    let mut buf = BytesMut::new();
                    tx.encode(&mut buf);
                    let _ = w.write_all(&buf).await;
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(ClientCommand::FetchTracker(addr)) => {
                         let tx = event_tx.clone();
                         tokio::spawn(async move {
                             fetch_tracker_servers(addr, tx).await;
                         });
                    }
                    Some(ClientCommand::Connect(addr)) => {
                        // Close existing
                        if let Some(h) = reader_handle.take() { h.abort(); }
                        writer = None;

                        event_tx.send(ClientEvent::Log(format!("Connecting to {}...", addr))).await.unwrap();

                        match TcpStream::connect(&addr).await {
                            Ok(s) => {
                                // Set NoDelay to avoid buffering small packets
                                if let Err(e) = s.set_nodelay(true) {
                                    event_tx.send(ClientEvent::Log(format!("Failed to set nodelay: {}", e))).await.unwrap();
                                }

                                let (mut read_half, mut write_half) = s.into_split();

                                // Handshake
                                if let Err(e) = write_half.write_all(HTLC_MAGIC).await {
                                    event_tx.send(ClientEvent::Error(format!("Write error: {}", e))).await.unwrap();
                                    continue;
                                }
                                // Read magic
                                let mut magic = [0u8; 8];
                                if let Err(e) = read_half.read_exact(&mut magic).await {
                                    event_tx.send(ClientEvent::Error(format!("Read error: {}", e))).await.unwrap();
                                    continue;
                                }
                                
                                event_tx.send(ClientEvent::Connected).await.unwrap();
                                event_tx.send(ClientEvent::Log("Connected!".to_string())).await.unwrap();

                                writer = Some(write_half);
                                
                                let tx_clone = event_tx.clone();
                                
                                reader_handle = Some(tokio::spawn(async move {
                                    run_reader(read_half, tx_clone).await;
                                }));
                            }
                            Err(e) => {
                                event_tx.send(ClientEvent::Error(format!("Connection failed: {}", e))).await.unwrap();
                            }
                        }
                    }
                    Some(ClientCommand::Login(login, nick, password)) => {
                        if let Some(w) = &mut writer {
                            let _ = event_tx.try_send(ClientEvent::Log(format!("Logging in as {} (User: {})...", nick, login)));
                            
                            let mangled_login = mangle_password(&login);
                            let _ = event_tx.try_send(ClientEvent::Debug(format!("Mangled Login: {:?}", mangled_login)));

                            let pwd_data = if let Some(pwd) = password {
                                let m = mangle_password(&pwd);
                                let _ = event_tx.try_send(ClientEvent::Debug(format!("Mangled Password: {:?}", m)));
                                m
                            } else {
                                Vec::new()
                            };
                            
                            // Reorder fields to match hx client legacy behavior: ICON, LOGIN, PASSWORD, NAME, VERSION
                            let fields = vec![
                                Field { id: HTLC_DATA_ICON, data: vec![0u8; 2] },
                                Field { id: HTLC_DATA_LOGIN, data: mangled_login },
                                Field { id: HTLC_DATA_PASSWORD, data: pwd_data },
                                Field { id: HTLC_DATA_NAME, data: nick.into_bytes() },
                                Field { id: HTLC_DATA_CLIENTVERSION, data: 150u16.to_be_bytes().to_vec() }, // Version 1.5
                            ];

                            let tx = Transaction::new(HTLC_HDR_LOGIN, next_trans_id, fields);
                            next_trans_id += 1;
                            let mut buf = BytesMut::new();
                            tx.encode(&mut buf);
                            let _ = event_tx.try_send(ClientEvent::Debug(format!("TX Trans: Type={} TransID={} Len={} Bytes={:?}", tx.header.type_id, tx.header.trans_id, tx.header.len, buf.as_ref())));
                            let _ = w.write_all(&buf).await;
                            // Removed flush to avoid potential hang
                        }
                    }
                    Some(ClientCommand::Chat(msg)) => {
                        if let Some(w) = &mut writer {
                            let fields = vec![
                                Field { id: HTLS_DATA_CHAT, data: msg.clone().into_bytes() } // 101
                            ];
                            let tx = Transaction::new(HTLC_HDR_CHAT, next_trans_id, fields);
                            next_trans_id += 1;
                            let mut buf = BytesMut::new();
                            tx.encode(&mut buf);
                            let _ = w.write_all(&buf).await;
                            // Removed flush
                            
                            // Local echo
                            let _ = event_tx.try_send(ClientEvent::ChatMsg(format!("(Me): {}", msg)));
                        }
                    }
                    Some(ClientCommand::RefreshUsers) => {
                         if let Some(w) = &mut writer {
                            let tx_users = Transaction::new(HTLC_HDR_USER_GETLIST, next_trans_id, vec![]);
                            next_trans_id += 1;
                            let mut buf = BytesMut::new();
                            tx_users.encode(&mut buf);
                            let _ = w.write_all(&buf).await;
                            // Removed flush
                            let _ = event_tx.send(ClientEvent::Debug("Requested User List".to_string())).await;
                         }
                    }
                    Some(ClientCommand::GetUserInfo(uid)) => {
                        if let Some(w) = &mut writer {
                            event_tx.send(ClientEvent::Debug(format!("Requesting info for UID {}...", uid))).await.unwrap();
                            let fields = vec![
                                Field { id: HTLC_DATA_UID, data: uid.to_be_bytes().to_vec() },
                            ];
                            let tx = Transaction::new(HTLC_HDR_USER_GETINFO, next_trans_id, fields);
                            next_trans_id += 1;
                            let mut buf = BytesMut::new();
                            tx.encode(&mut buf);
                            let _ = w.write_all(&buf).await;
                            // Removed flush
                        }
                    }
                    Some(ClientCommand::SendPrivateMessage(uid, msg)) => {
                        if let Some(w) = &mut writer {
                            event_tx.send(ClientEvent::Debug(format!("Sending private message to UID {}...", uid))).await.unwrap();
                            let fields = vec![
                                Field { id: HTLC_DATA_UID, data: uid.to_be_bytes().to_vec() },
                                Field { id: HTLC_DATA_MSG, data: msg.clone().into_bytes() },
                            ];
                            let tx = Transaction::new(HTLC_HDR_MSG, next_trans_id, fields);
                            next_trans_id += 1;
                            let mut buf = BytesMut::new();
                            tx.encode(&mut buf);
                            let _ = w.write_all(&buf).await;
                            // Removed flush
                            // Local Echo
                            let _ = event_tx.send(ClientEvent::ChatMsg(format!("(To UID {}): {}", uid, msg))).await;
                        }
                    }
                    Some(ClientCommand::GetNews) => {
                        if let Some(w) = &mut writer {
                            let _ = event_tx.try_send(ClientEvent::Debug("Requesting News...".to_string()));
                            let tx = Transaction::new(HTLC_HDR_NEWS_GETFILE, next_trans_id, vec![]);
                            next_trans_id += 1;
                            let mut buf = BytesMut::new();
                            tx.encode(&mut buf);
                            let _ = w.write_all(&buf).await;
                        }
                    }
                    Some(ClientCommand::ListFiles(path)) => {
                        if let Some(w) = &mut writer {
                             let _ = event_tx.try_send(ClientEvent::Debug(format!("Listing Files in {:?}...", path)));
                             
                             let path_data = encode_hotline_path(&path);
                             
                             let fields = vec![
                                 Field { id: HTLC_DATA_DIR, data: path_data }
                             ];
                             
                             let tx = Transaction::new(HTLC_HDR_FILE_LIST, next_trans_id, fields);
                             next_trans_id += 1;
                             let mut buf = BytesMut::new();
                             tx.encode(&mut buf);
                             let _ = w.write_all(&buf).await;
                        }
                    }
                    Some(ClientCommand::SendAgreement) => {
                        if let Some(w) = &mut writer {
                             event_tx.send(ClientEvent::Debug("Sending Agreement Agree...".to_string())).await.unwrap();
                             let tx = Transaction::new(HTLC_HDR_AGREEMENTAGREE, next_trans_id, vec![]);
                             next_trans_id += 1;
                             let mut buf = BytesMut::new();
                             tx.encode(&mut buf);
                             let _ = w.write_all(&buf).await;
                        }
                    }
                    Some(ClientCommand::AdminAccountRead(login)) => {
                        if let Some(w) = &mut writer {
                             event_tx.send(ClientEvent::Debug(format!("Reading Account {}...", login))).await.unwrap();
                             
                             let mangled_login = mangle_password(&login);
                             let fields = vec![
                                 Field { id: HTLC_DATA_LOGIN, data: mangled_login },
                             ];
                             
                             let tx = Transaction::new(HTLC_HDR_ACCOUNT_READ, next_trans_id, fields);
                             next_trans_id += 1;
                             let mut buf = BytesMut::new();
                             tx.encode(&mut buf);
                             let _ = w.write_all(&buf).await;
                        }
                    }
                    Some(ClientCommand::ChangeNick(new_nick)) => {
                        if let Some(w) = &mut writer {
                             let _ = event_tx.try_send(ClientEvent::Debug(format!("Changing nickname to {}...", new_nick)));
                             
                             let fields = vec![
                                 Field { id: HTLC_DATA_NAME, data: new_nick.into_bytes() },
                             ];
                             
                             let tx = Transaction::new(HTLC_HDR_USER_CHANGE, next_trans_id, fields);
                             next_trans_id += 1;
                             let mut buf = BytesMut::new();
                             tx.encode(&mut buf);
                             let _ = w.write_all(&buf).await;
                        }
                    }
                    Some(ClientCommand::ChangeIcon(icon_id)) => {
                        if let Some(w) = &mut writer {
                             let _ = event_tx.try_send(ClientEvent::Debug(format!("Changing icon to {}...", icon_id)));
                             
                             let fields = vec![
                                 Field { id: HTLC_DATA_ICON, data: icon_id.to_be_bytes().to_vec() },
                             ];
                             
                             let tx = Transaction::new(HTLC_HDR_USER_CHANGE, next_trans_id, fields);
                             next_trans_id += 1;
                             let mut buf = BytesMut::new();
                             tx.encode(&mut buf);
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

async fn run_reader(mut reader: tokio::net::tcp::OwnedReadHalf, event_tx: mpsc::Sender<ClientEvent>) {
    let mut buf = BytesMut::with_capacity(4096);
    const MAX_PACKET_SIZE: u32 = 32 * 1024 * 1024; // 32 MB Limit

    loop {
        let _ = event_tx.try_send(ClientEvent::Debug("run_reader waiting for data".to_string()));
        let n = match reader.read_buf(&mut buf).await {
            Ok(n) => {
                let _ = event_tx.try_send(ClientEvent::Debug(format!("run_reader read {} bytes. Buf len: {}", n, buf.len())));
                n
            }
            Err(e) => {
                let _ = event_tx.try_send(ClientEvent::Log(format!("Reader error: {}", e)));
                let _ = event_tx.send(ClientEvent::Disconnected).await;
                break;
            }
        };
        
        if n == 0 { // EOF
            if buf.is_empty() {
                 let _ = event_tx.try_send(ClientEvent::Log("Reader EOF".to_string()));
                 let _ = event_tx.send(ClientEvent::Disconnected).await;
                 break;
            } else {
                 // We have partial data but connection closed
                 let _ = event_tx.try_send(ClientEvent::Log("Reader EOF with partial data".to_string()));
                 let _ = event_tx.send(ClientEvent::Disconnected).await;
                 break;
            }
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

            // Security Check: Packet Size
            if hdr.len > MAX_PACKET_SIZE {
                let _ = event_tx.send(ClientEvent::Error(format!("Packet too large: {} bytes (Max: {})", hdr.len, MAX_PACKET_SIZE))).await;
                let _ = event_tx.send(ClientEvent::Disconnected).await;
                return; // Stop reading
            }
            
            // Debug log header
            let _ = event_tx.try_send(ClientEvent::Debug(format!("RX Trans: Type={} TransID={} Len={} HC={}", hdr.type_id, hdr.trans_id, hdr.len, hdr.hc)));
            let _ = event_tx.try_send(ClientEvent::Debug(format!("Header Bytes: {:?}", &buf[..Header::SIZE])));

            // Detect Login Success (Type 0x10000)
            if hdr.type_id == 0x10000 { // HTLS_HDR_TASK (Generic response)
                 // Pass the trans_id so main loop can verify if it matches login
                 let _ = event_tx.send(ClientEvent::TaskSuccess(hdr.trans_id)).await;
            }

            // The 'len' field in the header includes the size of HC (2 bytes) which we already read as part of Header::SIZE (22 bytes).
            // So remaining body size is len - 2.
            let body_len = (hdr.len as usize).saturating_sub(2);

            // Check if we have full body
            if buf.len() < (Header::SIZE + body_len) {
                let _ = event_tx.try_send(ClientEvent::Debug(format!("Waiting for more data. Need {}, Have {}", Header::SIZE + body_len, buf.len())));
                break; // Wait for more
            }

            // Consume
            buf.advance(Header::SIZE); // consume header
            let body = buf.split_to(body_len); // consume body

            // Parse Fields
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
            
            let _ = event_tx.try_send(ClientEvent::Debug(format!("Parsed {} fields. Entering loop.", fields.len())));

            // Handle Transaction
            
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
            
            // Account Info fields
            let mut acct_login = String::new();
            let mut acct_name = String::new();
            let mut acct_access = Vec::new();
            let mut agreement_text = String::new();

            for f in fields {
                if f.id == HTLS_DATA_USER_LIST {
                     match User::from_field(&f) {
                         Ok(u) => users.push(u),
                         Err(e) => {
                              let _ = event_tx.try_send(ClientEvent::Log(format!("Bad User Field: {}", e)));
                         }
                     }
                } else if f.id == HTLC_DATA_ACCESS {
                     acct_access = f.data.clone();
                } else if f.id == HTLS_DATA_FILE_LIST {
                     match FileItem::from_field(&f) {
                         Ok(item) => file_list.push(item),
                         Err(e) => {
                              let _ = event_tx.try_send(ClientEvent::Log(format!("Bad File Field: {}", e)));
                         }
                     }
                } else if f.id == HTLS_DATA_CHAT { // 101 - Chat content / Msg / News / User Info
                     let raw_string = String::from_utf8_lossy(&f.data);
                     let _ = event_tx.try_send(ClientEvent::Debug(format!("Raw 101 Data: {:?}", raw_string)));
                     generic_text_101 = raw_string.replace('\r', "\n");
                } else if f.id == HTLC_DATA_NAME { // 102
                     let s = String::from_utf8_lossy(&f.data).replace('\r', "\n");
                     sender = s.clone();
                     name_info = s.clone();
                     acct_name = s;
                } else if f.id == HTLS_DATA_SENDER { // 103
                     if f.data.len() == 4 {
                         uid_info = u32::from_be_bytes([f.data[0], f.data[1], f.data[2], f.data[3]]);
                     } else if f.data.len() == 2 {
                         uid_info = u16::from_be_bytes([f.data[0], f.data[1]]) as u32;
                     }
                } else if f.id == HTLC_DATA_LOGIN { // 105
                     let s = String::from_utf8_lossy(&f.data).replace('\r', "\n");
                     login_info = s.clone();
                     acct_login = s;
                } else if f.id == HTLC_DATA_ICON { // 104
                     if f.data.len() == 2 {
                         icon_info = u16::from_be_bytes([f.data[0], f.data[1]]);
                     }
                } else if f.id == HTLS_DATA_COLOR { // 112
                     if f.data.len() == 2 {
                         color_info = u16::from_be_bytes([f.data[0], f.data[1]]);
                     }
                } else if f.id == HTLS_DATA_TASKERROR {
                    let err_msg = String::from_utf8_lossy(&f.data).replace('\r', "\n");
                    let _ = event_tx.send(ClientEvent::Error(format!("Server Error: {}", err_msg))).await;
                } else if f.id == HTLS_DATA_SERVER_NAME {
                    let server_name = String::from_utf8_lossy(&f.data).replace('\r', "\n");
                    let _ = event_tx.try_send(ClientEvent::Log(format!("Server Name: {}", server_name)));
                }
            }

            if !generic_text_101.is_empty() {
                if hdr.type_id == HTLS_HDR_CHAT {
                    chat_msg = generic_text_101;
                } else if hdr.type_id == HTLS_HDR_MSG {
                    chat_msg = generic_text_101;
                } else if hdr.type_id == HTLS_HDR_AGREEMENT {
                    agreement_text = generic_text_101;
                } else if hdr.type_id == 0x10000 { // HTLS_HDR_TASK
                    // Ambiguous: Could be News or User Info.
                    // User Info usually comes with HTLC_DATA_NAME (102), LOGIN (105), ICON (104).
                    // News usually comes alone or with minimal fields.
                    if name_info.is_empty() && login_info.is_empty() && icon_info == 0 {
                        news_content = generic_text_101;
                    } else {
                        user_info_str = generic_text_101;
                    }
                } else {
                    // Default fallback
                    user_info_str = generic_text_101;
                }
            }

            if !users.is_empty() {
                let _ = event_tx.send(ClientEvent::UserList(users)).await; // User list is usually handled in bulk, not per-event
            }
            if !file_list.is_empty() {
                let event_tx_clone = event_tx.clone();
                let file_list_clone = file_list.clone();
                tokio::spawn(async move {
                    let _ = event_tx_clone.send(ClientEvent::FileList(file_list_clone)).await;
                });
            }
            
            if !acct_access.is_empty() {
                let event_tx_clone = event_tx.clone();
                let acct_login_clone = acct_login.clone();
                let acct_name_clone = acct_name.clone();
                let acct_access_clone = acct_access.clone();
                tokio::spawn(async move {
                    let access_hex = acct_access_clone.iter().map(|b| format!("{:02X}", b)).collect::<String>();
                    let info = format!("Account Info:\n  Login: {}\n  Name: {}\n  Access: {}", acct_login_clone, acct_name_clone, access_hex);
                    let _ = event_tx_clone.send(ClientEvent::AccountInfo(info)).await;
                });
            }

            if !chat_msg.is_empty() {
                // Standard chat message structure in HL might vary, but often it's just the msg content.
                // Sometimes sender is in a separate field or prefixed.
                // If sender is found, prepend it.
                let final_msg = if !sender.is_empty() && hdr.type_id == HTLS_HDR_MSG {
                    format!("[From {} (UID {})]: {}", sender, uid_info, chat_msg) // Private message with sender info
                } else if !sender.is_empty() {
                    format!("{}: {}", sender, chat_msg) // Public chat
                } else {
                    chat_msg
                };
                let _ = event_tx.send(ClientEvent::ChatMsg(final_msg)).await; // Chat messages are frequent, but usually short.
            }
            if !user_info_str.is_empty() {
                let event_tx_clone = event_tx.clone();
                let name_info_clone = name_info.clone();
                let login_info_clone = login_info.clone();
                let icon_info_clone = icon_info;
                let user_info_str_clone = user_info_str.clone();
                tokio::spawn(async move {
                    let _ = event_tx_clone.try_send(ClientEvent::Debug("Dispatching UserInfo".to_string()));
                    let _ = event_tx_clone.send(ClientEvent::UserInfo(format!("User Info - Nick: {} Login: {} Icon: {} Details: {}", name_info_clone, login_info_clone, icon_info_clone, user_info_str_clone))).await;
                    let _ = event_tx_clone.try_send(ClientEvent::Debug("Dispatched UserInfo".to_string()));
                });
            }
            if !news_content.is_empty() {
                 let event_tx_clone = event_tx.clone();
                 let news_content_clone = news_content.clone();
                 tokio::spawn(async move {
                     let _ = event_tx_clone.send(ClientEvent::News(news_content_clone)).await;
                 });
            }
            if !agreement_text.is_empty() {
                 let event_tx_clone = event_tx.clone();
                 let agreement_text_clone = agreement_text.clone();
                 tokio::spawn(async move {
                     let _ = event_tx_clone.send(ClientEvent::Agreement(agreement_text_clone)).await;
                 });
            }
            
            if hdr.type_id == HTLS_HDR_USER_CHANGE {
                let event_tx_clone = event_tx.clone();
                let user_uid = uid_info as u16;
                let user_icon = icon_info;
                let user_color = color_info;
                let user_name = name_info.clone(); // Clone name_info
                tokio::spawn(async move {
                    let user = User {
                        uid: user_uid,
                        icon: user_icon,
                        color: user_color,
                        name: user_name,
                    };
                    let _ = event_tx_clone.send(ClientEvent::UserUpdate(user)).await;
                });
            } else if hdr.type_id == HTLS_HDR_USER_PART {
                let event_tx_clone = event_tx.clone();
                let uid_info_clone = uid_info;
                tokio::spawn(async move {
                    let _ = event_tx_clone.send(ClientEvent::UserLeft(uid_info_clone)).await;
                });
            }
            let _ = event_tx.try_send(ClientEvent::Debug("Packet processed. Looping.".to_string()));
        }
    }
}