# Rusty HX Client

A Rust-based Text User Interface (TUI) client for the Hotline protocol. It's mainly been tested with Hotline 1.2.3 and mhxd.

## Prerequisites

You need to have Rust installed on your system.

## Installation

1. Navigate to this directory.
2. Run `cargo build` to compile.

## Usage

Run the client using:
```bash
./target/debug/rusty-hx [OPTIONS]
```

**Command-line Options:**
*   `--connect <[user[:password]@]host[:port]>`: Connect to a server on startup. Example: `--connect guest@127.0.0.1:5500`
*   `--debug`: Enable debug output in the chat history.
*   `--help`: Display the help message.

**In-app Commands:**

Once inside the TUI, type `/help` for a full list, or use the following:

*   `/connect [user[:password]@]host[:port]`: Connect to a Hotline server. If `user` and `password` are provided, it will attempt to log in with them. Default is `guest@chatonly.org:5500` if no arguments are provided.
*   `/nick <nickname>`: Change your nickname. This will be used on the next connect/login or immediately if already connected.
*   `/users`: Refresh and list online users.
*   `/info <uid>`: Get information about a user by their User ID (UID).
*   `/msg <uid> <message>`: Send a private message to a user.
*   `/news`: Get the latest server news.
*   `/ls`: List files in the current server directory.
*   `/cd <directory>`: Change the current server directory. Use `..` to go up one level, or `/` for the root. Supports quoted paths for directories with spaces.
*   `/tracker [url]`: List servers from a Hotline tracker. Default URL is `tracker.preterhuman.net`.
*   `/admin account read <login>`: Read and display user account data (requires admin privileges).
*   `/quit`: Disconnect and exit the application.
*   `/help`: Display the list of available commands.

**Keyboard Shortcuts & Mouse:**

*   `Esc`: Exit the application.
*   `Up`/`Down` Arrow Keys: Navigate through command history.
*   `PageUp`/`PageDown`: Scroll through chat history.
*   Mouse Scroll Wheel: Scroll through chat history.
*   `F2`: Toggle mouse capture (enables/disables mouse interaction with the TUI).

**Features:**

*   **Unread Indicator**: If you scroll up to view older messages, the Chat window title will change to `Chat (*)` when new messages arrive. Scrolling back to the bottom clears the indicator.
*   **Tracker Support**: Fetch and sort server lists from standard Hotline trackers.
*   **File System Navigation**: Basic `/ls` and `/cd` support.

Any other text typed will be sent as a chat message to the server.
