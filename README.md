# MITM Attack Tool

**MITM Attack Tool** is a powerful tool for monitoring and capturing network traffic, intercepting packets, and conducting Man-In-The-Middle attacks. This tool is designed for educational and testing purposes.

## Features
- Intercept network traffic
- Capture HTTP packets
- Send captured data to a specified email
- IP forward and firewall bypass

## Requirements
- Rooted Android Device (for Termux usage)
- Termux app installed
- Python 2 or 3
- Scapy library

## Installation Instructions

### Step 1: Install Termux
Download and install **Termux** from the Google Play Store or [official GitHub](https://github.com/termux/termux-app).

### Step 2: Install Python and Dependencies
In Termux, execute the following commands to install dependencies:

```bash
pkg update
pkg install python
pkg install git
pkg install scapy
pkg install openssl
pkg install curl
