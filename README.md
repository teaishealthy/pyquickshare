# pyquickshare

An implementation of QuickShare in Python.

## System requirements

pyquickshare has following expectations from the system:
- Bluetooth stack using BlueZ
- BlueZ reachable over D-Bus

As these are de-facto standards on Linux, pyquickshare should work on most Linux distributions.

### Firewalls

As QuickShare uses a direct connection between devices, it is necessary to allow incoming connections on the advertised port. firewalld is supported out of the box (but not required).

pyquickshare temporarily reconfigures `firewalld` (if available) to accept an incoming connection on it's advertised port.
This is done by adding a temporary rule to the currently "active" zone.
This rule is automatically removed by `firewalld` after 5 minutes.

Communication with `firewalld` is done over D-Bus, `polkit` may prompt for authentication.
## Installation

```bash
poetry install
```

## Usage

**example.py** is a basic example of how to use pyquickshare.
It provides a command line interface to send and receive files using QuickShare:

```bash
poetry run python example.py receive
```

```bash
poetry run python example.py send <file>
```


## Notes

This project would not have been possible without the amazing reverse engineering work done by [grishka](https://github.com/grishka/) on the QuickShare protocol.
Check out [NearDrop](https://github.com/grishka/NearDrop/), a similar project for Mac OS.