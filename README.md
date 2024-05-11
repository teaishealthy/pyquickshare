# pyquickshare

An implementation of QuickShare in Python.

## System requirements

pyquickshare has following expectations from the system:
- Bluetooth stack using BlueZ
- BlueZ reachable over D-Bus

As these are de-facto standards on Linux, pyquickshare should work on most Linux distributions.

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

This project would not have been possible without the amazing reverse engineering work done by [grishka](https://github.com/grishka/) on the QuickShare protocol. Check out [NearDrop](https://github.com/grishka/NearDrop/), a similar project for Mac OS.