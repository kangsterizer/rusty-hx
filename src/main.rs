use anyhow::Result;
use ratatui::crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, MouseEvent, MouseEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::crossterm::event::{EnableMouseCapture, DisableMouseCapture};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};
use std::io::{self, Write};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use crate::client::{ClientCommand, ClientEvent, run_client};
use crate::protocol::{User, TrackerServer};

mod client;
mod protocol;

fn parse_addr(addr: &str) -> String {
    if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{}:5500", addr)
    }
}

struct TrackerCache {
    url: String,
    timestamp: Instant,
    servers: Vec<TrackerServer>,
}

struct App {
    input: String,
    chat_history: Vec<String>,
    users: Vec<User>,
    client_tx: mpsc::Sender<ClientCommand>,
    // State
    server_addr: String,
    nickname: String,
    icon: u16,
    login: String,
    password: Option<String>,
    connected: bool,
    input_mode: InputMode,
    // Input History
    input_history: Vec<String>,
    history_index: usize,
    debug: bool,
    should_quit: bool,
    current_path: Vec<String>,
    state: ClientState,
    chat_scroll_state: ListState,
    auto_scroll: bool,
    has_unread: bool,
    mouse_capture: bool,
    tracker_cache: Option<TrackerCache>,
    encrypted: bool,
}

#[derive(PartialEq)]
enum ClientState {
    Disconnected,
    LoggingIn,
    LoggedIn,
}

enum InputMode {
    Normal,
    Password,
}

impl App {
    async fn new(client_tx: mpsc::Sender<ClientCommand>, initial_addr: Option<String>, initial_login_arg: Option<String>, initial_pass: Option<String>, debug: bool) -> App {
        let login = initial_login_arg.clone().unwrap_or("guest".to_string());
        let nickname = std::env::var("USER").unwrap_or("guest".to_string());
        
        let server_addr = if let Some(addr) = initial_addr {
            let _ = client_tx.send(ClientCommand::Connect(addr.clone())).await;
            addr
        } else {
            "127.0.0.1:5500".to_string()
        };

        App {
            input: String::new(),
            chat_history: Vec::new(),
            users: Vec::new(),
            client_tx,
            server_addr,
            nickname,
            icon: 404,
            login,
            password: initial_pass,
            connected: false,
            input_mode: InputMode::Normal,
            input_history: Vec::new(),
            history_index: 0,
            debug,
            should_quit: false,
            current_path: Vec::new(),
            state: ClientState::Disconnected,
            chat_scroll_state: ListState::default(),
            auto_scroll: true,
            has_unread: false,
            mouse_capture: true,
            tracker_cache: None,
            encrypted: false,
        }
    }

    fn add_message(&mut self, msg: String) {
        self.chat_history.push(msg);
        if !self.auto_scroll {
            self.has_unread = true;
        }
    }

    fn display_tracker_servers(&mut self, servers: &[TrackerServer]) {
        self.add_message(format!("--- Tracker Server List ({} servers) ---", servers.len()));
        for s in servers {
            let ip_bytes = s.ip.to_be_bytes();
            let ip_str = format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            self.add_message(format!("- {} ({}:{}) Users: {} - {}", s.name, ip_str, s.port, s.users, s.description));
        }
        self.add_message("----------------------------------------".to_string());
    }

    async fn on_mouse(&mut self, event: MouseEvent) {
        match event.kind {
            MouseEventKind::ScrollUp => {
                let current = self.chat_scroll_state.selected().unwrap_or(0);
                if current > 0 {
                    self.chat_scroll_state.select(Some(current.saturating_sub(1)));
                    self.auto_scroll = false;
                }
            }
            MouseEventKind::ScrollDown => {
                 let current = self.chat_scroll_state.selected().unwrap_or(0);
                 let max_idx = self.chat_history.len().saturating_sub(1);
                 if current < max_idx {
                     let new_idx = current + 1;
                     self.chat_scroll_state.select(Some(new_idx));
                     if new_idx == max_idx {
                         self.auto_scroll = true;
                         self.has_unread = false;
                     }
                 }
            }
            _ => {}
        }
    }

    async fn on_key(&mut self, key: KeyCode) {
        match self.input_mode {
            InputMode::Normal => match key {
                KeyCode::Enter => {
                    let msg = self.input.drain(..).collect::<String>();
                    if !msg.trim().is_empty() {
                         self.input_history.push(msg.clone());
                         self.history_index = self.input_history.len();
                    }

                    if msg.starts_with('/') {
                        // Commands
                        let parts: Vec<&str> = msg.split_whitespace().collect();
                        match parts.get(0) {
                            Some(&"/connect") => {
                                let addr_str = if let Some(s) = parts.get(1) {
                                    s.to_string()
                                } else {
                                    "guest@chatonly.org".to_string()
                                };

                                // Handle user@host
                                let full_str = addr_str;
                                let (_user_part, host_part) = if let Some(idx) = full_str.find('@') {
                                    let user = &full_str[..idx];
                                    let host = &full_str[idx+1..];
                                    // Handle user:pass
                                    if let Some(cidx) = user.find(':') {
                                        self.login = user[..cidx].to_string();
                                        self.password = Some(user[cidx+1..].to_string());
                                    } else {
                                        self.login = user.to_string();
                                        self.password = None; // Reset password if just user provided
                                    }
                                    // self.nickname = self.login.clone(); // REMOVED: Keep existing nickname
                                    (Some(user.to_string()), host.to_string())
                                } else {
                                    (None, full_str)
                                };

                                let addr = parse_addr(&host_part);
                                self.server_addr = addr.clone();
                                let _ = self.client_tx.send(ClientCommand::Connect(addr)).await;
                            }
                            Some(&"/nick") => {
                                if let Some(nick) = parts.get(1) {
                                    self.nickname = nick.to_string();
                                    if self.connected {
                                         let _ = self.client_tx.send(ClientCommand::ChangeNick(self.nickname.clone())).await;
                                    } else {
                                         self.add_message(format!("Nickname set to {}. Will use on next connect/login.", self.nickname));
                                    }
                                } else {
                                    self.add_message("Usage: /nick <new_nickname>".to_string());
                                }
                            }
                            Some(&"/icon") => {
                                if let Some(icon_str) = parts.get(1) {
                                    if let Ok(icon_id) = icon_str.parse::<u16>() {
                                        self.icon = icon_id;
                                        if self.connected {
                                             let _ = self.client_tx.send(ClientCommand::ChangeIcon(icon_id)).await;
                                        } else {
                                             self.add_message("Not connected. Icon change will be effective on login if you reconnect.".to_string());
                                             // Note: We don't strictly store icon state for pre-login yet, relying on server default or successful login.
                                             // But the command is mainly for live updates.
                                        }
                                    } else {
                                        self.add_message("Usage: /icon <id> (ID must be a number 0-65535)".to_string());
                                    }
                                } else {
                                    self.add_message("Usage: /icon <id>".to_string());
                                }
                            }
                            Some(&"/quit") => {
                                 self.should_quit = true;
                            }
                            Some(&"/users") => {
                                 let _ = self.client_tx.send(ClientCommand::RefreshUsers).await;
                            }
                            Some(&"/info") => {
                                 if let Some(uid_str) = parts.get(1) {
                                     if let Ok(uid) = uid_str.parse::<u32>() {
                                         let _ = self.client_tx.send(ClientCommand::GetUserInfo(uid)).await;
                                     } else {
                                         self.add_message("Usage: /info <uid> (UID must be a number)".to_string());
                                     }
                                 } else {
                                     self.add_message("Usage: /info <uid>".to_string());
                                 }
                            }
                            Some(&"/msg") => {
                                 if parts.len() >= 3 {
                                     let uid_str = parts[1];
                                     if let Ok(uid) = uid_str.parse::<u32>() {
                                         // Robust message extraction
                                         if let Some(uid_start) = msg.find(uid_str) {
                                             let after_uid = &msg[uid_start + uid_str.len()..];
                                             if let Some(msg_start_relative) = after_uid.find(|c: char| !c.is_whitespace()) {
                                                 let message = after_uid[msg_start_relative..].to_string();
                                                 let _ = self.client_tx.send(ClientCommand::SendPrivateMessage(uid, message)).await;
                                             } else {
                                                 // Empty message?
                                                 self.add_message("Usage: /msg <uid> <message>".to_string());
                                             }
                                         } else {
                                             // Should not happen due to parts logic, but safe fallback
                                             self.add_message("Error parsing message command.".to_string());
                                         }
                                     } else {
                                         self.add_message("Usage: /msg <uid> <message> (UID must be a number)".to_string());
                                     }
                                 } else {
                                     self.add_message("Usage: /msg <uid> <message>".to_string());
                                 }
                            }
                            Some(&"/news") => {
                                 let _ = self.client_tx.send(ClientCommand::GetNews).await;
                            }
                            Some(&"/ls") => {
                                 // List current dir
                                 let _ = self.client_tx.send(ClientCommand::ListFiles(self.current_path.clone())).await;
                            }
                            Some(&"/cd") => {
                                 // Extract path from raw message to support spaces
                                 let path_str_raw = if let Some(idx) = msg.find(' ') {
                                     msg[idx+1..].trim().to_string()
                                 } else {
                                     "".to_string()
                                 };
                                 
                                 if !path_str_raw.is_empty() {
                                     let path_str = if path_str_raw.starts_with('"') && path_str_raw.ends_with('"') && path_str_raw.len() > 1 {
                                         &path_str_raw[1..path_str_raw.len()-1]
                                     } else {
                                         &path_str_raw
                                     };
                                     
                                     // Handle ".." and normal paths
                                     if path_str == ".." {
                                         self.current_path.pop();
                                         self.add_message(format!("Changed directory to: /{}", self.current_path.join("/")));
                                         // Auto list? Maybe not, let user type /ls
                                         let _ = self.client_tx.send(ClientCommand::ListFiles(self.current_path.clone())).await;
                                     } else {
                                         // Handle "cd /"
                                         if path_str == "/" {
                                              self.current_path.clear();
                                         } else {
                                              // Split by / just in case user typed "foo/bar"
                                              for p in path_str.split('/') {
                                                  if !p.is_empty() {
                                                      if p == ".." {
                                                          self.current_path.pop();
                                                      } else {
                                                          self.current_path.push(p.to_string());
                                                      }
                                                  }
                                              }
                                         }
                                         self.add_message(format!("Changed directory to: /{}", self.current_path.join("/")));
                                         let _ = self.client_tx.send(ClientCommand::ListFiles(self.current_path.clone())).await;
                                     }
                                 } else {
                                     self.add_message(format!("Current directory: /{}", self.current_path.join("/")));
                                 }
                            }
                            Some(&"/admin") => {
                                 if parts.len() >= 4 && parts[1] == "account" && parts[2] == "read" {
                                     let login = parts[3];
                                     let _ = self.client_tx.send(ClientCommand::AdminAccountRead(login.to_string())).await;
                                 } else {
                                     self.add_message("Usage: /admin account read <login>".to_string());
                                 }
                            }
                            Some(&"/tracker") => {
                                 let url = if let Some(u) = parts.get(1) {
                                     u.to_string()
                                 } else {
                                     "tracker.preterhuman.net".to_string()
                                 };
                                 
                                 let mut use_cache = false;
                                 if let Some(cache) = &self.tracker_cache {
                                     if cache.url == url && Instant::now().duration_since(cache.timestamp) < Duration::from_secs(600) {
                                         use_cache = true;
                                     }
                                 }
                                 
                                 if use_cache {
                                     self.add_message(format!("Using cached server list for {} (older than 10 mins refreshes automatically)", url));
                                     // Clone to avoid borrow checker issues if we need to mutate self in display
                                     let servers = self.tracker_cache.as_ref().unwrap().servers.clone(); 
                                     self.display_tracker_servers(&servers);
                                 } else {
                                     let _ = self.client_tx.send(ClientCommand::FetchTracker(url)).await;
                                 }
                            }
                            Some(&"/help") => {
                                 self.add_message("--- Available Commands ---".to_string());
                                 self.add_message("/connect [user[:password]@]host[:port] - Connect to a Hotline server.".to_string());
                                 self.add_message("/nick <nickname> - Change your nickname.".to_string());
                                 self.add_message("/quit - Disconnect and exit.".to_string());
                                 self.add_message("/users - Refresh and list online users.".to_string());
                                 self.add_message("/info <uid> - Get information about a user by UID.".to_string());
                                 self.add_message("/msg <uid> <message> - Send a private message to a user.".to_string());
                                 self.add_message("/news - Get the latest server news.".to_string());
                                 self.add_message("/ls - List files in the current server directory.".to_string());
                                 self.add_message("/cd <directory> - Change the current server directory.".to_string());
                                 self.add_message("/tracker [url] - List servers from a tracker (default: hltracker.com)".to_string());
                                 self.add_message("/admin account read <login> - Read and display user account data (requires admin privileges).".to_string());
                                 self.add_message("/help - Display this help message.".to_string());
                                 self.add_message("--------------------------".to_string());
                            }
                            _ => {
                                 self.add_message(format!("Unknown command: {}", msg));
                            }
                        }
                    } else {
                        if self.connected {
                            let _ = self.client_tx.send(ClientCommand::Chat(msg)).await;
                        } else {
                            self.add_message("Not connected. Use /connect <host:port>".to_string());
                        }
                    }
                }
                KeyCode::Up => {
                    if self.history_index > 0 {
                        self.history_index -= 1;
                        if let Some(cmd) = self.input_history.get(self.history_index) {
                            self.input = cmd.clone();
                        }
                    }
                }
                KeyCode::Down => {
                    if self.history_index < self.input_history.len() {
                        self.history_index += 1;
                        if self.history_index == self.input_history.len() {
                            self.input.clear();
                        } else if let Some(cmd) = self.input_history.get(self.history_index) {
                            self.input = cmd.clone();
                        }
                    }
                }
                KeyCode::Char(c) => {
                    self.input.push(c);
                }
                KeyCode::Backspace => {
                    self.input.pop();
                }
                KeyCode::PageUp => {
                    let current = self.chat_scroll_state.selected().unwrap_or(0);
                    if current > 0 {
                        let new_idx = current.saturating_sub(10);
                        self.chat_scroll_state.select(Some(new_idx));
                        self.auto_scroll = false;
                    }
                }
                KeyCode::PageDown => {
                     let current = self.chat_scroll_state.selected().unwrap_or(0);
                     let max_idx = self.chat_history.len().saturating_sub(1);
                     if current < max_idx {
                         let new_idx = std::cmp::min(current + 10, max_idx);
                         self.chat_scroll_state.select(Some(new_idx));
                         if new_idx == max_idx {
                             self.auto_scroll = true;
                             self.has_unread = false;
                         }
                     }
                }
                _ => {}
            },
            InputMode::Password => match key {
                KeyCode::Enter => {
                     let pwd = self.input.drain(..).collect::<String>();
                     self.password = Some(pwd);
                     self.input_mode = InputMode::Normal;
                     let _ = self.client_tx.send(ClientCommand::Login(self.login.clone(), self.nickname.clone(), self.password.clone(), self.icon)).await;
                }
                KeyCode::Char(c) => {
                    self.input.push(c);
                }
                KeyCode::Backspace => {
                    self.input.pop();
                }
                KeyCode::Esc => {
                    self.input.clear();
                    self.input_mode = InputMode::Normal;
                    self.add_message("Login cancelled.".to_string());
                }
                _ => {}
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Set panic hook to restore terminal
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        let _ = execute!(io::stdout(), ratatui::crossterm::cursor::Show);
        default_hook(info);
    }));

    main_app_run(std::env::args().collect()).await
}

async fn main_app_run(args: Vec<String>) -> Result<()> {
    // Parse CLI args
    let mut initial_addr = None;
    let mut initial_login = None;
    let mut debug = false;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--help" {
            println!("Usage: rusty-hx [OPTIONS]");
            println!("Options:");
            println!("  --connect <[login@]host[:port]>  Connect to a server on startup");
            println!("  --debug                          Enable debug mode");
            println!("  --help                           Display this help message");
            return Ok(());
        } else if args[i] == "--connect" {
            if i + 1 < args.len() {
                let input = &args[i + 1];
                if let Some(idx) = input.find('@') {
                    initial_login = Some(input[..idx].to_string());
                    initial_addr = Some(parse_addr(&input[idx + 1..]));
                } else {
                    initial_addr = Some(parse_addr(input));
                }
                i += 2;
            } else {
                eprintln!("Error: --connect requires an argument");
                return Ok(());
            }
        } else if args[i] == "--debug" {
            debug = true;
            i += 1;
        } else {
            i += 1;
        }
    }

    // Prompt for password if needed
    let mut initial_pass = None;
    if initial_addr.is_some() && initial_login.is_some() {
        print!("Password for {}: ", initial_login.as_ref().unwrap());
        io::stdout().flush()?;
        
        enable_raw_mode()?;
        let mut pass = String::new();
        loop {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Enter => break,
                        KeyCode::Char(c) => pass.push(c),
                        KeyCode::Backspace => { pass.pop(); },
                        KeyCode::Esc => { 
                            pass.clear(); 
                            break; 
                        },
                        _ => {}
                    }
                }
            }
        }
        disable_raw_mode()?;
        println!(); // Newline
        if !pass.is_empty() {
            initial_pass = Some(pass);
        }
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Setup Client
    let (cmd_tx, cmd_rx) = mpsc::channel(1000);
    let (event_tx, mut event_rx) = mpsc::channel(10000);

    tokio::spawn(async move {
        run_client(cmd_rx, event_tx).await;
    });

    let mut app = App::new(cmd_tx, initial_addr, initial_login, initial_pass, debug).await;
    app.chat_history.push("Welcome to Rusty HX Client!".to_string());
    app.chat_history.push("Type /connect [login[:pass]@]host[:port] to start.".to_string());

    // Event loop
    let _tick_rate = Duration::from_millis(100);
    
    // We need to poll crossterm events in a way that doesn't block the tokio runtime too much
    // So we spawn a thread for input events.
    let (input_tx, mut input_rx) = mpsc::channel(100);
    std::thread::spawn(move || {
        loop {
            if event::poll(Duration::from_millis(100)).unwrap() {
                let event = event::read().unwrap();
                match event {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                         let _ = input_tx.blocking_send(event);
                    }
                    Event::Mouse(_) => {
                         let _ = input_tx.blocking_send(event);
                    }
                    _ => {}
                }
            }
        }
    });

    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        tokio::select! {
            Some(event) = event_rx.recv() => {
                match event {
                    ClientEvent::Connected => {
                        app.connected = true;
                        app.state = ClientState::LoggingIn;
                        app.add_message("Connected.".to_string());
                        // Auto login
                        let _ = app.client_tx.send(ClientCommand::Login(app.login.clone(), app.nickname.clone(), app.password.clone(), app.icon)).await;
                    }
                    ClientEvent::TaskSuccess(_trans_id) => {
                        if app.state == ClientState::LoggingIn {
                             app.state = ClientState::LoggedIn;
                             app.add_message("Login Successful.".to_string());
                             let _ = app.client_tx.send(ClientCommand::RefreshUsers).await;
                        }
                        // Ignore other TaskSuccess (like from SendAgreement or Ping)
                    }
                    ClientEvent::Disconnected => {
                        app.connected = false;
                        app.state = ClientState::Disconnected;
                        app.add_message("Disconnected.".to_string());
                        app.users.clear(); // Clear user list on disconnect
                    }
                    ClientEvent::Error(e) => {
                        app.add_message(format!("Error: {}", e));
                        if e.to_lowercase().contains("authent") || e.to_lowercase().contains("pass") || e.contains("Access denied") { // Check for auth errors
                             app.add_message("Authentication failed. Please enter password:".to_string());
                             app.input_mode = InputMode::Password;
                             app.input.clear();
                        }
                    }
                    ClientEvent::ChatMsg(msg) => {
                        for line in msg.lines() {
                            app.add_message(line.to_string());
                        }
                    }
                    ClientEvent::UserList(users) => {
                        app.add_message(format!("Received User List ({} users).", users.len()));
                        app.users = users;
                    }
                    ClientEvent::Log(msg) => {
                        app.add_message(format!("[System] {}", msg));
                    }
                    ClientEvent::Debug(msg) => {
                        if app.debug {
                            app.add_message(format!("[Debug] {}", msg));
                        }
                    }
                    // ... other events ...
                    ClientEvent::UserInfo(info) => {
                        for line in info.lines() {
                            app.add_message(format!("[Info] {}", line));
                        }
                    }
                    ClientEvent::News(news) => {
                        app.add_message("--- Hotline News ---".to_string());
                        for line in news.lines() {
                            app.add_message(line.to_string());
                        }
                        app.add_message("--------------------".to_string());
                    }
                    ClientEvent::FileList(files) => {
                        app.add_message(format!("--- File List ({}) ---", files.len()));
                        for file in files {
                            let type_indicator = if file.is_folder { "[DIR] " } else { "" };
                            let size_str = if file.is_folder { "".to_string() } else { format!(" ({} bytes)", file.size) };
                            app.add_message(format!("{}{}{}", type_indicator, file.name, size_str));
                        }
                        app.add_message("----------------------".to_string());
                    }
                    ClientEvent::UserAccess(info) => {
                        if app.state == ClientState::LoggedIn { // Implicit update after login
                            app.add_message("User Access details updated.".to_string());
                            if app.debug {
                                for line in info.lines() {
                                    app.add_message(format!("[Debug] {}", line));
                                }
                            }
                        } else { // Explicitly requested or other context
                            app.add_message("--- User Access Info ---".to_string());
                            for line in info.lines() {
                                app.add_message(line.to_string());
                            }
                            app.add_message("--------------------------".to_string());
                        }
                    }
                    ClientEvent::Agreement(text) => {
                        app.add_message("--- Server Agreement ---".to_string());
                        for line in text.lines() {
                            app.add_message(line.to_string());
                        }
                        app.add_message("------------------------".to_string());
                        
                        if app.state != ClientState::LoggedIn {
                            app.add_message("Accepting agreement...".to_string());
                            let _ = app.client_tx.send(ClientCommand::SendAgreement(app.nickname.clone(), app.icon)).await;
                        } else {
                            app.add_message("Agreement received but already logged in. Ignoring acceptance request.".to_string());
                        }
                    }
                    ClientEvent::UserUpdate(user) => {
                        // Check if exists
                        if let Some(existing) = app.users.iter_mut().find(|u| u.uid == user.uid) {
                            existing.name = user.name.clone();
                            existing.icon = user.icon;
                            existing.color = user.color;
                            // app.chat_history.push(format!("User {} updated.", user.name)); // Optional: too noisy?
                        } else {
                            app.add_message(format!("User {} joined.", user.name));
                            app.users.push(user);
                        }
                    }
                    ClientEvent::UserLeft(uid) => {
                        if let Some(idx) = app.users.iter().position(|u| u.uid as u32 == uid) {
                            let name = app.users[idx].name.clone();
                            app.users.remove(idx);
                            app.add_message(format!("User {} left.", name));
                        }
                    }
                    ClientEvent::TrackerServerList(url, mut servers) => {
                        // Sort by users ascending (higher users last)
                        servers.sort_by(|a, b| a.users.cmp(&b.users));
                        
                        app.tracker_cache = Some(TrackerCache {
                            url,
                            timestamp: Instant::now(),
                            servers: servers.clone(),
                        });
                        
                        app.display_tracker_servers(&servers);
                    }
                    ClientEvent::CipherInit(session_key) => {
                        app.add_message("Cipher negotiation started...".to_string());
                        let _ = app.client_tx.send(ClientCommand::EnableCipher(session_key)).await;
                    }
                    ClientEvent::Encrypted => {
                        app.encrypted = true;
                        app.add_message("🔒 Encrypted Connection Established (RC4-160/HMAC-SHA1)".to_string());
                    }
                }
            }
            Some(input_event) = input_rx.recv() => {
                match input_event {
                    Event::Key(key) => {
                        if key.code == KeyCode::Esc {
                            // Handle global ESC if needed, or let input modes handle it
                            if let InputMode::Password = app.input_mode {
                                app.input_mode = InputMode::Normal;
                                app.chat_history.push("Cancelled.".to_string());
                                app.input.clear();
                            } else {
                                break; 
                            }
                        } else if key.code == KeyCode::F(2) {
                            app.mouse_capture = !app.mouse_capture;
                            if app.mouse_capture {
                                let _ = execute!(terminal.backend_mut(), EnableMouseCapture);
                                app.add_message("Mouse Capture Enabled (Scroll: ON, Select: Shift+Click)".to_string());
                            } else {
                                let _ = execute!(terminal.backend_mut(), DisableMouseCapture);
                                app.add_message("Mouse Capture Disabled (Scroll: OFF, Select: Native)".to_string());
                            }
                        } else {
                            app.on_key(key.code).await;
                            if app.should_quit {
                                break;
                            }
                        }
                    }
                    Event::Mouse(mouse) => {
                        app.on_mouse(mouse).await;
                    }
                    _ => {}
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_addr_with_port() {
        assert_eq!(parse_addr("localhost:8080"), "localhost:8080");
    }

    #[test]
    fn test_parse_addr_without_port() {
        assert_eq!(parse_addr("localhost"), "localhost:5500");
    }

    #[test]
    fn test_parse_addr_empty() {
        assert_eq!(parse_addr(""), ":5500");
    }

    // This is an integration test, as it effectively runs parts of the main logic.
    // It's tricky to test due to side effects (terminal setup, tokio runtime).
    // For now, we'll test the argument parsing aspect by calling main_app_run with specific args
    // and checking the initial state of the App struct, but this requires more refactoring
    // to expose App state or capture side effects.
    // For now, we'll assume the argument parsing loop itself is correct from inspection.
    // A more robust test would involve mocking mpsc channels and terminal interactions.
}

#[cfg(test)]
mod app_tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_add_message_auto_scroll_enabled() {
        let (client_tx, _cmd_rx) = mpsc::channel(1);
        let mut app = App::new(client_tx, None, None, None, false).await;
        
        app.auto_scroll = true;
        app.add_message("Test message".to_string());
        
        assert_eq!(app.chat_history.len(), 1);
        assert_eq!(app.chat_history[0], "Test message");
        assert!(!app.has_unread); // Should not be marked unread if auto_scroll is true
    }

    #[tokio::test]
    async fn test_add_message_auto_scroll_disabled() {
        let (client_tx, _cmd_rx) = mpsc::channel(1);
        let mut app = App::new(client_tx, None, None, None, false).await;
        
        app.auto_scroll = false;
        app.add_message("Test message".to_string());
        
        assert_eq!(app.chat_history.len(), 1);
        assert_eq!(app.chat_history[0], "Test message");
        assert!(app.has_unread); // Should be marked unread if auto_scroll is false
    }
}

fn ui(f: &mut ratatui::Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Min(1),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(f.area());

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(70),
                Constraint::Percentage(30),
            ]
            .as_ref(),
        )
        .split(chunks[0]);

    let messages: Vec<ListItem> = app
        .chat_history
        .iter()
        .map(|m| ListItem::new(Line::from(Span::raw(m))))
        .collect();
    
    let unread_marker = if app.has_unread { "(*)" } else { "" };
    let mouse_status = if app.mouse_capture { "[Mouse: ON]" } else { "[Mouse: OFF]" };
    let enc_status = if app.encrypted { "[ENC]" } else { "" };
    let chat_title = format!("Chat {} {} {} (F2 to toggle)", unread_marker, mouse_status, enc_status);

    let messages_list = List::new(messages)
        .block(Block::default().borders(Borders::ALL).title(chat_title));
    
    // Auto-scroll to bottom
    if app.auto_scroll && !app.chat_history.is_empty() {
        app.chat_scroll_state.select(Some(app.chat_history.len() - 1));
    }
    f.render_stateful_widget(messages_list, main_chunks[0], &mut app.chat_scroll_state);

    let users: Vec<ListItem> = app
        .users
        .iter()
        .map(|u| ListItem::new(Line::from(Span::raw(format!("{} ({}) [Icon:{}]", u.name, u.uid, u.icon)))))
        .collect();
    let users_list = List::new(users)
        .block(Block::default().borders(Borders::ALL).title("Users"));
    f.render_widget(users_list, main_chunks[1]);

    let input_title = match app.input_mode {
        InputMode::Normal => "Input",
        InputMode::Password => "Password (Input Hidden)",
    };

    let input_text = match app.input_mode {
        InputMode::Normal => app.input.as_str(),
        InputMode::Password => "", // Hide password
    };

    let input = Paragraph::new(input_text)
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title(input_title));
    f.render_widget(input, chunks[1]);
}
