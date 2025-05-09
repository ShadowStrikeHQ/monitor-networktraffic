# monitor-networktraffic
Monitor network traffic for unusual patterns, flagging unexpected connections or high data transfer rates to specific IPs.  Uses `scapy` to capture and analyze packets. - Focused on System monitoring and alerts

## Install
`git clone https://github.com/ShadowStrikeHQ/monitor-networktraffic`

## Usage
`./monitor-networktraffic [params]`

## Parameters
- `-h`: Show help message and exit
- `-i`: No description provided
- `-f`: BPF filter (e.g., 
- `-t`: No description provided
- `-n`: Number of packets to capture. If 0, capture indefinitely.
- `-d`: Monitor traffic to a specific IP address.
- `--log-level`: Set the logging level.
- `--pcap`: Enable saving captured packets to a pcap file.

## License
Copyright (c) ShadowStrikeHQ
