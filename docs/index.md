# pyquickshare documentation


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
uv install
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

This project would not have been possible without the amazing reverse engineering work done by [grishka](https://github.com/grishka/) on the Quick Share protocol.
Check out [NearDrop](https://github.com/grishka/NearDrop/), a similar project for Mac OS.

## API Documentation

```{toctree}
:maxdepth: 2

self
api
internals
```