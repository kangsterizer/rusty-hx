use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
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
    Quit,
}

pub enum ClientEvent {
    Connected,
    LoggedIn(u32),
    Disconnected,
    Error(String),
    UserList(Vec<User>),
    ChatMsg(String),
    Log(String),
    Debug(String),
    UserInfo(String), // New event for displaying user info
}

fn mangle_password(pwd: &str) -> Vec<u8> {
    pwd.bytes().map(|b| !b).collect()
}

pub async fn run_client(mut cmd_rx: mpsc::Receiver<ClientCommand>, event_tx: mpsc::Sender<ClientEvent>) {
    let mut writer: Option<tokio::net::tcp::OwnedWriteHalf> = None;
    let mut reader_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut next_trans_id = 1u32;

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
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
                            event_tx.send(ClientEvent::Log(format!("Logging in as {} (User: {})...", nick, login))).await.unwrap();
                            
                            let mangled_login = mangle_password(&login);
                            event_tx.send(ClientEvent::Debug(format!("Mangled Login: {:?}", mangled_login))).await.unwrap();

                            let pwd_data = if let Some(pwd) = password {
                                let m = mangle_password(&pwd);
                                event_tx.send(ClientEvent::Debug(format!("Mangled Password: {:?}", m))).await.unwrap();
                                m
                            } else {
                                Vec::new()
                            };
                            
                            // Reorder fields to match hx client legacy behavior: ICON, LOGIN, PASSWORD, NAME
                            let fields = vec![
                                Field { id: HTLC_DATA_ICON, data: vec![0u8; 2] },
                                Field { id: HTLC_DATA_LOGIN, data: mangled_login },
                                Field { id: HTLC_DATA_PASSWORD, data: pwd_data },
                                Field { id: HTLC_DATA_NAME, data: nick.into_bytes() },
                            ];

                            let tx = Transaction::new(HTLC_HDR_LOGIN, next_trans_id, fields);
                            next_trans_id += 1;
                            let mut buf = BytesMut::new();
                            tx.encode(&mut buf);
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
                            let _ = event_tx.send(ClientEvent::ChatMsg(format!("(Me): {}", msg))).await;
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
    loop {
        let n = match reader.read_buf(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                let _ = event_tx.send(ClientEvent::Log(format!("Reader error: {}", e))).await;
                let _ = event_tx.send(ClientEvent::Disconnected).await;
                break;
            }
        };
        
        if n == 0 { // EOF
            if buf.is_empty() {
                 let _ = event_tx.send(ClientEvent::Log("Reader EOF".to_string())).await;
                 let _ = event_tx.send(ClientEvent::Disconnected).await;
                 break;
            } else {
                 // We have partial data but connection closed
                 let _ = event_tx.send(ClientEvent::Log("Reader EOF with partial data".to_string())).await;
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
            
            // Debug log header
            let _ = event_tx.send(ClientEvent::Debug(format!("RX Trans: Type={} TransID={} Len={} HC={}", hdr.type_id, hdr.trans_id, hdr.len, hdr.hc))).await;
            let _ = event_tx.send(ClientEvent::Debug(format!("Header Bytes: {:?}", &buf[..Header::SIZE]))).await;

            // Detect Login Success (Type 0x10000)
            if hdr.type_id == 0x10000 { // HTLS_HDR_TASK (Generic response)
                 // Pass the trans_id so main loop can verify if it matches login
                 let _ = event_tx.send(ClientEvent::LoggedIn(hdr.trans_id)).await;
            }

            // The 'len' field in the header includes the size of HC (2 bytes) which we already read as part of Header::SIZE (22 bytes).
            // So remaining body size is len - 2.
            let body_len = (hdr.len as usize).saturating_sub(2);

            // Check if we have full body
            if buf.len() < (Header::SIZE + body_len) {
                let _ = event_tx.send(ClientEvent::Debug(format!("Waiting for more data. Need {}, Have {}", Header::SIZE + body_len, buf.len()))).await;
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
                    let _ = event_tx.send(ClientEvent::Log("Failed to decode field".to_string())).await;
                    break;
                }
            }
            
            let _ = event_tx.send(ClientEvent::Debug(format!("Parsed {} fields. Entering loop.", fields.len()))).await;

            // Handle Transaction
            
            let mut users = Vec::new();
            let mut chat_msg = String::new();
            let mut sender = String::new();
            let mut user_info_str = String::new();
            let mut uid_info = 0u32;
            let mut name_info = String::new();
            let mut login_info = String::new();
            let mut icon_info = 0u16;

            for f in fields {
                if f.id == HTLS_DATA_USER_LIST {
                     match User::from_field(&f) {
                         Ok(u) => users.push(u),
                         Err(e) => {
                              let _ = event_tx.send(ClientEvent::Log(format!("Bad User Field: {}", e))).await;
                         }
                     }
                } else if f.id == HTLS_DATA_CHAT { // 101 - Chat content / Msg
                     let s = String::from_utf8_lossy(&f.data).replace('\r', "\n");
                     if hdr.type_id == HTLS_HDR_CHAT {
                         chat_msg = s;
                     } else if hdr.type_id == HTLS_HDR_MSG {
                         chat_msg = s; // handled as private later
                     } else {
                         user_info_str = s;
                     }
                } else if f.id == HTLC_DATA_NAME { // 102
                     sender = String::from_utf8_lossy(&f.data).replace('\r', "\n");
                     name_info = sender.clone();
                } else if f.id == HTLS_DATA_SENDER { // 103
                     if f.data.len() == 4 {
                         uid_info = u32::from_be_bytes([f.data[0], f.data[1], f.data[2], f.data[3]]);
                     } else if f.data.len() == 2 {
                         uid_info = u16::from_be_bytes([f.data[0], f.data[1]]) as u32;
                     }
                } else if f.id == HTLC_DATA_LOGIN { // 105
                     login_info = String::from_utf8_lossy(&f.data).replace('\r', "\n");
                } else if f.id == HTLC_DATA_ICON { // 104
                     if f.data.len() == 2 {
                         icon_info = u16::from_be_bytes([f.data[0], f.data[1]]);
                     }
                } else if f.id == HTLS_DATA_TASKERROR {
                    let err_msg = String::from_utf8_lossy(&f.data).replace('\r', "\n");
                    let _ = event_tx.send(ClientEvent::Error(format!("Server Error: {}", err_msg))).await;
                } else if f.id == HTLS_DATA_SERVER_NAME {
                    let server_name = String::from_utf8_lossy(&f.data).replace('\r', "\n");
                    let _ = event_tx.send(ClientEvent::Log(format!("Server Name: {}", server_name))).await;
                }
            }

            if !users.is_empty() {
                let _ = event_tx.send(ClientEvent::UserList(users)).await;
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
                let _ = event_tx.send(ClientEvent::ChatMsg(final_msg)).await;
            }
            if !user_info_str.is_empty() {
                let _ = event_tx.send(ClientEvent::UserInfo(format!("User Info - Nick: {} Login: {} Icon: {} Details: {}", name_info, login_info, icon_info, user_info_str))).await;
            }
        }
    }
}