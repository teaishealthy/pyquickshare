# pyquickshare

![Ruff logo](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/teaishealthy/teaishealthy/refs/heads/main/ruff-badge.json&style=flat-square)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/teaishealthy/pyquickshare/ruff.yml?style=flat-square&label=lint+and+format)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/teaishealthy/pyquickshare/test.yml?style=flat-square&label=tests)
![Coveralls](https://img.shields.io/coverallsCoverage/github/teaishealthy/pyquickshare?style=flat-square)


An asynchronous Python implementation of the Android Quick Share (Nearby Share) protocol

## System requirements

pyquickshare makes no assumptions about the underlying system and will gracefully degrade if features are missing.
All services are accessed over D-Bus (with the exception of some Bluetooth operations).
For full functionality, the following are needed:

- **Bluetooth:** BlueZ with a Bluetooth Classic adapter
- **Nudging nearby devices:** BLE support*
- **Wi-Fi Direct:** NetworkManager with a Wi-Fi adapter

pyquickshare collets `facts` about the system to determine which features are available and which transports can be used. Check the logging output for details.

*BlueZ must be running in dual mode: set `ControllerMode = dual` in `/etc/bluetooth/main.conf` and restart the Bluetooth service (`systemctl restart bluetooth`).

### Firewalls

As Quick Share uses a direct connection between devices, it is necessary to allow incoming connections on the advertised port. firewalld is supported out of the box (but not required).

pyquickshare temporarily reconfigures `firewalld` (if available) to accept an incoming connection on it's advertised port.
This is done by adding a temporary rule to the currently "active" zone.
This rule is automatically removed by `firewalld` after 5 minutes.

Communication with `firewalld` is done over D-Bus, `polkit` may prompt for authentication.

## Installation

Depending on your Linux distribution, you may need to install some development packages to build the C++ extension module:

| Distro          | Package                                                             |
| --------------- | ------------------------------------------------------------------- |
| Debian / Ubuntu | `python3-dev` `libbluetooth-dev` `cmake` `pkgconf`                 |
| Arch            | `python` `bluez` `cmake` `pkgconf`                                 |
| Fedora / RHEL   | `python3-devel` `bluez-libs-devel` `cmake` `pkgconf-pkg-config`    |
| Alpine          | `python3-dev` `bluez-dev` `cmake` `pkgconf`                        |


Now you can install pyquickshare using pip:

```bash
pip install pyquickshare

# or, to install with extras (QR code support)
pip install pyquickshare[extras]
```

## Features

Receive is fully implemented, namely WiFi credentials, files, and text. Sending only supports files, but support for sending text and WiFi credentials is planned.

### Transfer
Quick Share supports two "bare" transports: WiFi/LAN and Bluetooth Classic. Bluetooth Classic *can* transfer files, but can also be used to trigger an upgrade to a faster medium (e.g. WiFi Direct or Hotspot).

pyquickshare supports both transports for discovery and transfer. It also supports upgrading to WiFi Direct (and WiFi/LAN).

### Discovery
pyquickshare uses mDNS to discover other devices on the local network. BLE is only used to trigger advertisment at the moment ("nudging" or "Fast Init").

## Usage

**example.py** is a basic example of how to use pyquickshare.
It provides a command line interface to send and receive files using Quick Share:

```bash
uv run example.py receive
```

```bash
uv run example.py send <file>
```

## Development

Make sure you installed the system dependencies mentioned in the installation section. Now sync with:

```bash
uv sync --dev --all-extras
```

## Notes and Acknowledgements

- The code in [`pyquickshare/protos`](https://github.com/teaishealthy/pyquickshare/blob/main/pyquickshare/protos/) is generated from protobuf sources licensed under Apache 2.0.
As a derivative work, these generated files remain under the original Apache 2.0 license.
A copy of the original license can be found in the [`pyquickshare/protos`](https://github.com/teaishealthy/pyquickshare/blob/main/pyquickshare/protos/) directory.

- This project would not have been possible without the amazing reverse engineering work done by [grishka](https://github.com/grishka/) on the Quick Share protocol.
Check out [NearDrop](https://github.com/grishka/NearDrop/), a similar project for Mac OS.

