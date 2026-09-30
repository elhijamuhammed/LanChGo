# LanChGo (Windows)

**Fast. Private. Local.**

LanChGo is an open-source LAN communication and productivity application for Windows.

It allows devices connected to the same local network to communicate, transfer files, and collaborate without requiring internet access, accounts, subscriptions, or cloud services.

This repository contains the Windows implementation of LanChGo.

---

## Why LanChGo?

Most communication tools depend on internet connectivity, cloud infrastructure, and user accounts.

LanChGo takes a different approach.

It is designed for environments where devices simply need to communicate directly with each other on the same network—quickly, privately, and without unnecessary complexity.

Perfect for:

* Home networks
* Offices
* Classrooms
* Laboratories
* LAN events
* Environments with limited or no internet access

---

## Features

### Communication

* Instant LAN messaging
* Automatic device discovery
* Secure channel creation using PIN pairing
* End-to-end encrypted secure communication
* No internet connection required

### File Sharing

* Direct device-to-device file transfers
* Reliable TCP-based transfers
* Multi-device compatibility
* No cloud storage involved

### Productivity

* Web Companion for browser-based access
* Lightweight and responsive user interface
* Fast local communication
* Designed for low-latency local networking

### Privacy

* No accounts
* No tracking
* No analytics
* No external servers
* No cloud dependency

---

## Platform Scope

| Platform      | Status                        |
| ------------- | ----------------------------- |
| Windows       | Open Source (this repository) |
| Android       | Separate project              |
| Web Companion | Included                      |
| Linux         | Open Source (this repository) |

The Android application is maintained separately and is not included in this repository.

---

## Security & Privacy

LanChGo is built with privacy as a core principle.

* Communication remains within the local network
* No external server communication
* Secure channels use encrypted communication
* No personal information is collected
* No analytics or tracking services are used

---

## Building the Windows Application

### Prerequisites

* Rust (stable)
* Cargo
* Windows

### Build

```bash
cargo build --release
```

### Run

```bash
cargo run
```

Compiled binaries will be available in:

```bash
target/release/
```

---

## Project Website

https://lanchgo.com

---

## Contributing

Contributions, bug reports, feature suggestions, and pull requests are welcome.

If you encounter a bug or have an idea for improving LanChGo, feel free to open an issue.

---

## License

This project is licensed under the MIT License.

---

## Author

Developed by Muhammed Abu El-Hija

© 2025–2026 LanChGo
