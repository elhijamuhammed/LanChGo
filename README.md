# LanChGo (Windows)

LanChGo is an open-source, privacy-focused LAN messaging application for Windows.  
It allows devices on the same local network to communicate instantly **without internet access, servers, or accounts**.

This repository contains the **Windows implementation** of LanChGo.

---

## ✨ Features

- Local network (LAN) messaging
- No internet connection required
- Automatic device discovery via local network
- Secure channel mode using a PIN
- End-to-end encrypted secure communication
- Lightweight and fast
- Built with Rust and Slint UI

---

## 🖥️ Platform Scope

- ✅ **Windows** — open-source (this repository)
- ❌ Android — **not included here**

The Android app exists as a separate project and is not part of this repository.

---

## 🔐 Security & Privacy

- Communication is limited to the local network
- No cloud services or external servers
- Secure channels use PIN-based encryption
- No user accounts, tracking, or analytics

This makes LanChGo suitable for private environments such as:
- Home networks
- Offices
- Labs
- Local events or classrooms

---

## 🚀 Building the Windows App

### Prerequisites
- Rust (stable)
- Cargo
- Windows OS

### Build
```bash
cd windows
cargo build --release
```

### RUN
```bash
cargo run
```

The compiled binary will be located in:
```bash
windows/target/release/
```

License
This project is licensed under the MIT License.
See the LICENSE file for details.

Author
Developed by Muhammed Abu El-Hija
 
