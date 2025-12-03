# MHXD TUI Client

A Rust-based Text User Interface (TUI) client for the Hotline protocol, designed to work with `mhxd`.

## Prerequisites

You need to have Rust installed on your system.

## Installation

1. Navigate to this directory.
2. Run `cargo build` to compile.

## Usage

Run the client using:
```bash
cargo run
```

## Commands

Once inside the TUI, you can use the following commands:

- `/connect <host>:<port>` : Connect to a hotline server (e.g., `127.0.0.1:5500`).
- `/login <nickname>` : Change your nickname and login (happens automatically after connect with 'guest').
- `/quit` : Exit the application.
- `Esc` : Exit the application.

Any other text typed will be sent as a chat message to the server.
