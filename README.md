# pyquickshare

![Ruff logo](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/teaishealthy/teaishealthy/refs/heads/main/ruff-badge.json&style=flat-square)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/teaishealthy/pyquickshare/ruff.yml?style=flat-square&label=lint+and+format)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/teaishealthy/pyquickshare/test.yml?style=flat-square&label=tests)
![Coveralls](https://img.shields.io/coverallsCoverage/github/teaishealthy/pyquickshare?style=flat-square)


An implementation of Quick Share in Python.

## System requirements

pyquickshare has following expectations from the system:
- some mDNS implementation (avahi, systemd-resolved, etc.)
- Bluetooth stack using BlueZ reachable via D-Bus

As these are de-facto standards on Linux, pyquickshare should work on most Linux distributions.

### Firewalls

As Quick Share uses a direct connection between devices, it is necessary to allow incoming connections on the advertised port. firewalld is supported out of the box (but not required).

pyquickshare temporarily reconfigures `firewalld` (if available) to accept an incoming connection on it's advertised port.
This is done by adding a temporary rule to the currently "active" zone.
This rule is automatically removed by `firewalld` after 5 minutes.

Communication with `firewalld` is done over D-Bus, `polkit` may prompt for authentication.

## Installation

```bash
pip install git+https://github.com/teaishealthy/pyquickshare
```

## Features

Receive is fully implemented, namely WiFi credentials, files, and text. Sending only supports files, but support for sending text and WiFi credentials is planned.

### Transfer
Only LAN/Wifi is supported at the moment, but Bluetooth is planned.

### Discovery
pyquickshare uses mDNS to discover other devices on the local network. BLE is only used to trigger advertisment at the moment.

## Usage

**example.py** is a basic example of how to use pyquickshare.
It provides a command line interface to send and receive files using Quick Share:

```bash
uv run example.py receive
```

```bash
uv run example.py send <file>
```


## Notes and Acknowledgements

- The code in [`pyquickshare/protos`](https://github.com/teaishealthy/pyquickshare/blob/main/pyquickshare/protos/) is generated from protobuf sources licensed under Apache 2.0.
As a derivative work, these generated files remain under the original Apache 2.0 license.
A copy of the original license can be found in the [`pyquickshare/protos`](https://github.com/teaishealthy/pyquickshare/blob/main/pyquickshare/protos/) directory.

- This project would not have been possible without the amazing reverse engineering work done by [grishka](https://github.com/grishka/) on the Quick Share protocol.
Check out [NearDrop](https://github.com/grishka/NearDrop/), a similar project for Mac OS.

- **WiFi-Direct**: While according to Google's Nearby documentation and the protobuf fields WiFi-Direct is supposed to be an available medium, it seems that Quick Share does not use it.
It more likely uses WiFi-Aware which isn't widely supported outside of Android devices.
