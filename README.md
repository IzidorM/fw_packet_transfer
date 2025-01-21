# Packet Transfer Protocol

Packet Transfer is a lightweight protocol designed for transferring data packets over a byte stream-based lower layer. It facilitates point-to-point packet transfers, ideal for communication between embedded devices or between an embedded device and a server, mobile phone, or PC.

## Key Features

- Reference implementation available in C and Python
- Compact and efficient codebase
- BSD licensed for flexible use

## Protocol Overview

The Packet Transfer Protocol encompasses two distinct protocols that can be used interchangeably:

### Pico Packet Protocol

A simplistic protocol allows transferring payloads of up to 64 bytes. It includes an 8-bit BSD checksum for basic error detection.

### Extended Packet Protocol

Designed for transferring larger payloads (up to 4GB), this protocol includes start, payload, and end messages, supporting basic error checking and retransmissions for reliable data transfer.

## Size Measurement

All sizes were measured using GCC 13.2 with -Os optimization for the Cortex-M4 target.

Packet Transfer Core Size:

|                    | Text        | Data |                  |
|--------------------|-------------|------|------------------|
| Only Pico          | 350B + 267B | 0B   |                  |
| Pico with Extended | TBD         | TBD  | //to be measured |

This protocol ensures efficient data packet transfer, crucial for resource-constrained environments like embedded systems.
