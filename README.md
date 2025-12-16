# Traffic Anonymization

This project provides tools for high-performance network traffic anonymization and manipulation. It is written in Go and supports various packet capture drivers including PCAP, AF_PACKET, and PF_RING.

## Tools

The project consists of two main utilities:

1.  **`traffic-anonymization`**: The core tool that captures traffic from one or more input interfaces, optionally anonymizes IP addresses (CryptoPAn), and forwards the traffic to an output interface.
2.  **`decapsulate`**: A utility for decapsulating network traffic (e.g., removing tunnel headers) and forwarding it.

## Architecture Overview

```
                                    ┌─────────────────────────────┐
                                    │  Machine A                  │
┌─────────┐      ┌─────────┐        │  ┌───────────────────────┐  │        ┌─────────────────────────────┐
│ Network │──────│   TAP   │────────│──│ traffic-anonymization │──│────────│  Machine B                  │
│ Traffic │      │ Device  │ mirror │  │   (anonymizes IPs)    │  │        │  ┌───────────────────────┐  │
└─────────┘      └─────────┘        │  └───────────────────────┘  │        │  │     decapsulate       │──│───▶ Output
                                    └─────────────────────────────┘        │  │ (removes tunnel hdrs) │  │
                                                                           │  └───────────────────────┘  │
                                                                           └─────────────────────────────┘
```

## Prerequisites

*   **Go**: Version 1.21 or later.
*   **libpcap-dev**: Required for PCAP support.
*   **PF_RING** (Optional): Required if you intend to use the PF_RING driver for high-speed capture.

## Building

You can build the tools using the provided `Makefile`.

### Standard Build
To build the `traffic-anonymization` tool with standard drivers (PCAP, AF_PACKET):
```bash
make
```

### Build with PF_RING
To build with PF_RING support (requires PF_RING libraries installed):
```bash
make ring
```

### Build Decapsulate Tool
To build the `decapsulate` tool:
```bash
make decapsulate
```

## Configuration

The tools are configured using a JSON file. By default, the tools look for `config.json` in `/opt/traffic-anonymization/config/` or the current directory, but you can specify a custom path using the `-conf` flag.

### Configuration Structure

A sample configuration file looks like this:

```json
{
  "InInterfaces": [
    {
      "Driver": "afpacket",
      "Ifname": "eth0",
      "Filter": "tcp port 80",
      "FanOut": true
    }
  ],
  "OutInterface": {
    "Driver": "pcap",
    "Ifname": "eth1"
  },
  "Misc": {
    "Anonymize": true,
    "LogLevel": "info",
    "PrivateNets": true,
    "LocalNets": ["100.100.0.0/16"],
    "LoopTime": 10
  }
}
```

### Configuration Options

#### `InInterfaces` (Array)
Defines the input interfaces to capture traffic from.
*   `Driver`: Packet capture driver. Options: `"pcap"`, `"afpacket"`, `"ring"` (PF_RING), see below for a full list.
*   `Ifname`: Name of the network interface (e.g., `eth0`).
*   `Filter`: BPF filter string (e.g., `tcp port 80`).
*   `Clustered`: (bool) Enable clustering for load balancing (PF_RING).
*   `ClusterID`: (int) Cluster ID for load balancing.
*   `ClusterN`: (int) Number of threads to use in the cluster.
*   `ZeroCopy`: (bool) Enable Zero Copy mode (PF_RING).
*   `FanOut`: (bool) Enable AF_PACKET Fanout.

#### `OutInterface` (Object)
Defines the output interface where processed traffic is sent.
*   Supports the same fields as `InInterfaces` (`Driver`, `Ifname`, etc.).

#### `Misc` (Object)
*   `Anonymize`: (bool) Enable or disable IP anonymization.
*   `LogLevel`: Logging verbosity. Options: `"debug"`, `"info"`, `"warn"`, `"error"`, `"fatal"`.
*   `PrivateNets`: (bool) Drop traffic from private nets (10.0.0.0/8, ...)
*   `LocalNets`: (Array of strings) Local networks to anonymize
*   `LoopTime`: (int) Time of the day when to create a new key

#### Drivers

Here are the available drivers:

    *   `pcapwrite`: Write to a network interface using libpcap.
    *   `ringwrite`: Write to a network interface using PF_RING.
    *   `afpacketwrite`: Write to a network interface using AF_PACKET.
    *   `fileread`: Read from a PCAP file.
    *   `filewrite`: Write to a PCAP file.
    *   `socketwrite`: Write to a socket.
    *   `socketbufferedwrite`: Buffered write to a socket.
    *   `filebufferedwrite`: Buffered write to a file.
    *   `drop`: Drop packets (no output).

## Usage

### Running Traffic Anonymization

```bash
./traffic-anonymization -conf path/to/config.json
```

**Flags:**
*   `-conf <file>`: Path to the configuration file (default: `config.json`).
*   `-debug`: Enable debug logging.
*   `-info`: Enable info logging.
*   `-warn`: Enable warn logging.
*   `-error`: Enable error logging.
*   `-fatal`: Enable fatal logging.

### Running Decapsulate

```bash
./decapsulate -conf path/to/config.json
```
(Accepts similar flags as `traffic-anonymization`)

## Deployment

A sample service script `scripts/run_traffic_an.sh` is provided to manage the execution of the tool. It can be used as a watchdog to ensure the process keeps running.

```bash
# Example usage in crontab or systemd
./scripts/run_traffic_an.sh
```
