# LanChGo (Windows)

**Fast. Private. Local.**

LanChGo is an open-source LAN communication and productivity application for Windows.

It allows devices connected to the same local network to communicate, transfer files, and collaborate without requiring internet access, accounts, subscriptions, or cloud services.

This repository contains the Windows implementation of LanChGo.

---

## Why LanChGo?

Most communication tools depend on internet connectivity, cloud infrastructure, and user accounts.

LanChGo takes a different approach.

It is designed for environments where devices simply need to communicate directly with each other on the same network: quickly, privately, and without unnecessary complexity.

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
* Device names, so you can tell who sent what, even when two devices share a name
* Secure channel creation using PIN or QR pairing
* Encrypted messages and file offers inside secure channels
* No internet connection required

### File Sharing

* Direct device-to-device file transfers
* Reliable TCP-based transfers
* Resend a file offer to devices that missed it
* Works between Windows, Android and the browser
* No cloud storage involved

### Activities

* **Polls:** create a poll, vote from any device on the network, and watch the live counts
* A countdown closes the poll when votes stop coming in, or the creator can end it early
* Results can be viewed as bars, a pie chart or columns
* Polls are available in public mode; support for secure channels is planned

### Productivity

* Web Companion for browser-based access
* Chat commands (type `/help` to see them all)
* Available in Arabic, English and Chinese, including right-to-left layout
* Lightweight and responsive user interface
* Designed for low-latency local networking

### Privacy

* No accounts
* No tracking
* No analytics
* No cloud dependency
* Messages, files and polls stay inside your local network

---

## Platform Scope

| Platform      | Status                        |
| ------------- | ----------------------------- |
| Windows       | Open Source (this repository) |
| Android       | Separate project              |
| Web Companion | Included                      |
| Linux         | Soon to come                  |

The Android application is maintained separately and is not included in this repository.

---

## Security & Privacy

LanChGo is built with privacy as a core principle.

* Communication stays within the local network
* Secure channels encrypt messages and file offers
* Polls are not encrypted yet and are disabled while a secure channel is active
* No personal information is collected
* No analytics or tracking services are used
* The only request that leaves your network is a check against GitHub Releases to see whether a newer version is available

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
