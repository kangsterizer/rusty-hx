use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use std::{io, time::Duration};
use tokio::sync::mpsc;
use crate::client::{ClientCommand, ClientEvent, run_client};
use crate::protocol::User;

mod client;
mod protocol;

fn parse_addr(addr: &str) -> String {
    if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{}:5500", addr)
    }
}

struct App {
    input: String,
    chat_history: Vec<String>,
    users: Vec<User>,
    client_tx: mpsc::Sender<ClientCommand>,
    // State
    server_addr: String,
    nickname: String,
    login: String,
    password: Option<String>,
    connected: bool,
    input_mode: InputMode,
    // Input History
    input_history: Vec<String>,
    history_index: usize,
    debug: bool,
    should_quit: bool,
}

enum InputMode {
    Normal,
    Password,
}

impl App {
    async fn new(client_tx: mpsc::Sender<ClientCommand>, initial_addr: Option<String>, initial_login_arg: Option<String>, initial_pass: Option<String>, debug: bool) -> App {
        let login = initial_login_arg.clone().unwrap_or("guest".to_string());
        let nickname = if initial_login_arg.is_some() {
            login.clone()
        } else {
            std::env::var("USER").unwrap_or("guest".to_string())
        };
        
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
            login,
            password: initial_pass,
            connected: false,
            input_mode: InputMode::Normal,
            input_history: Vec::new(),
            history_index: 0,
            debug,
            should_quit: false,
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
                                if let Some(addr_str) = parts.get(1) {
                                    // Handle user@host
                                    let full_str = addr_str.to_string();
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
                                        self.nickname = self.login.clone();
                                        (Some(user.to_string()), host.to_string())
                                    } else {
                                        (None, full_str)
                                    };

                                    let addr = parse_addr(&host_part);
                                    self.server_addr = addr.clone();
                                    let _ = self.client_tx.send(ClientCommand::Connect(addr)).await;
                                } else {
                                    self.chat_history.push("Usage: /connect [user[:password]@]host[:port]".to_string());
                                }
                            }
                            Some(&"/login") => {
                                if let Some(nick) = parts.get(1) {
                                    self.nickname = nick.to_string();
                                    if self.login == "guest" {
                                        self.login = self.nickname.clone();
                                    }
                                    let _ = self.client_tx.send(ClientCommand::Login(self.login.clone(), self.nickname.clone(), self.password.clone())).await;
                                } else {
                                    self.chat_history.push("Usage: /login <nickname>".to_string());
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
                                         self.chat_history.push("Usage: /info <uid> (UID must be a number)".to_string());
                                     }
                                 } else {
                                     self.chat_history.push("Usage: /info <uid>".to_string());
                                 }
                            }
                            Some(&"/msg") => {
                                 if parts.len() >= 3 {
                                     let uid_str = parts[1];
                                     if let Ok(uid) = uid_str.parse::<u32>() {
                                         // Robust message extraction
                                         let uid_start = msg.find(uid_str).unwrap(); // Must exist
                                         let after_uid = &msg[uid_start + uid_str.len()..];
                                         if let Some(msg_start_relative) = after_uid.find(|c: char| !c.is_whitespace()) {
                                             let message = after_uid[msg_start_relative..].to_string();
                                             let _ = self.client_tx.send(ClientCommand::SendPrivateMessage(uid, message)).await;
                                         } else {
                                             // Empty message?
                                             self.chat_history.push("Usage: /msg <uid> <message>".to_string());
                                         }
                                     } else {
                                         self.chat_history.push("Usage: /msg <uid> <message> (UID must be a number)".to_string());
                                     }
                                 } else {
                                     self.chat_history.push("Usage: /msg <uid> <message>".to_string());
                                 }
                            }
                            _ => {
                                 self.chat_history.push(format!("Unknown command: {}", msg));
                            }
                        }
                    } else {
                        if self.connected {
                            let _ = self.client_tx.send(ClientCommand::Chat(msg)).await;
                        } else {
                            self.chat_history.push("Not connected. Use /connect <host:port>".to_string());
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
                _ => {}
            },
            InputMode::Password => match key {
                KeyCode::Enter => {
                     let pwd = self.input.drain(..).collect::<String>();
                     self.password = Some(pwd);
                     self.input_mode = InputMode::Normal;
                     let _ = self.client_tx.send(ClientCommand::Login(self.login.clone(), self.nickname.clone(), self.password.clone())).await;
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
                    self.chat_history.push("Login cancelled.".to_string());
                }
                _ => {}
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI args
    let args: Vec<String> = std::env::args().collect();
    let mut initial_addr = None;
    let mut initial_login = None;
    let mut initial_pass = None;
    let mut debug = false;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--connect" {
            if i + 1 < args.len() {
                initial_addr = Some(parse_addr(&args[i + 1]));
                i += 2;
            } else {
                eprintln!("Error: --connect requires an argument");
                return Ok(());
            }
        } else if args[i] == "--login" {
            if i + 1 < args.len() {
                initial_login = Some(args[i + 1].clone());
                i += 2;
            }
        } else if args[i] == "--pass" {
             if i + 1 < args.len() {
                initial_pass = Some(args[i + 1].clone());
                i += 2;
            }
        } else if args[i] == "--debug" {
            debug = true;
            i += 1;
        } else {
            i += 1;
        }
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Setup Client
    let (cmd_tx, cmd_rx) = mpsc::channel(1000);
    let (event_tx, mut event_rx) = mpsc::channel(1000);

    tokio::spawn(async move {
        run_client(cmd_rx, event_tx).await;
    });

    let mut app = App::new(cmd_tx, initial_addr, initial_login, initial_pass, debug).await;
    app.chat_history.push("Welcome to MHXD TUI Client!".to_string());
    app.chat_history.push("Type /connect [login[:pass]@]host[:port] to start.".to_string());

        // Event loop
        let _tick_rate = Duration::from_millis(100);
    
        // We need to poll crossterm events in a way that doesn't block the tokio runtime too much    // But we can't easily mix async loop with blocking crossterm::event::read
    // So we spawn a thread for input events.
    let (key_tx, mut key_rx) = mpsc::channel(100);
    std::thread::spawn(move || {
        loop {
            if event::poll(Duration::from_millis(100)).unwrap() {
                if let Event::Key(key) = event::read().unwrap() {
                    if key.kind == KeyEventKind::Press {
                        let _ = key_tx.blocking_send(key.code);
                    }
                }
            }
        }
    });

    loop {
        terminal.draw(|f| ui(f, &app))?;

        tokio::select! {
            Some(event) = event_rx.recv() => {
                match event {
                    ClientEvent::Connected => {
                        app.connected = true;
                        app.chat_history.push("Connected.".to_string());
                        // Auto login
                        let _ = app.client_tx.send(ClientCommand::Login(app.login.clone(), app.nickname.clone(), app.password.clone())).await;
                    }
                    ClientEvent::LoggedIn(trans_id) => {
                        if trans_id == 1 {
                             app.chat_history.push("Login Successful.".to_string());
                             let _ = app.client_tx.send(ClientCommand::RefreshUsers).await;
                        }
                    }
                    ClientEvent::Disconnected => {
                        app.connected = false;
                        app.chat_history.push("Disconnected.".to_string());
                    }
                    ClientEvent::Error(e) => {
                        app.chat_history.push(format!("Error: {}", e));
                        if e.to_lowercase().contains("authent") || e.to_lowercase().contains("pass") || e.contains("Access denied") { // Check for auth errors
                             app.chat_history.push("Authentication failed. Please enter password:".to_string());
                             app.input_mode = InputMode::Password;
                             app.input.clear();
                        }
                    }
                    ClientEvent::ChatMsg(msg) => {
                        app.chat_history.push(msg);
                    }
                    ClientEvent::UserList(users) => {
                        app.chat_history.push(format!("Received User List ({} users).", users.len()));
                        app.users = users;
                    }
                    ClientEvent::Log(msg) => {
                        app.chat_history.push(format!("[System] {}", msg));
                    }
                    ClientEvent::Debug(msg) => {
                        if app.debug {
                            app.chat_history.push(format!("[Debug] {}", msg));
                        }
                    }
                    ClientEvent::UserInfo(info) => {
                        app.chat_history.push(format!("[Info] {}", info));
                    }
                }
            }
            Some(key) = key_rx.recv() => {
                if key == KeyCode::Esc {
                    // Handle global ESC if needed, or let input modes handle it
                    if let InputMode::Password = app.input_mode {
                         app.input_mode = InputMode::Normal;
                         app.chat_history.push("Cancelled.".to_string());
                         app.input.clear();
                    } else {
                         break; 
                    }
                } else {
                     app.on_key(key).await;
                     if app.should_quit {
                         break;
                     }
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn ui(f: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Min(1),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(f.size());

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
    let messages_list = List::new(messages)
        .block(Block::default().borders(Borders::ALL).title("Chat"));
    f.render_widget(messages_list, main_chunks[0]);

    let users: Vec<ListItem> = app
        .users
        .iter()
        .map(|u| ListItem::new(Line::from(Span::raw(format!("{} ({})", u.name, u.uid)))))
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
