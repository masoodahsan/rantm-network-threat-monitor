# RANTM — Real-Time Adaptive and Explainable Network Threat Monitor

RANTM is a Linux C project that captures authorized IPv4 traffic with libpcap,
tracks short time-window statistics per source address, and emits explainable
risk alerts for selected traffic patterns.

## Features in this version

- Live packet capture with libpcap.
- Bounds-checked Ethernet/IPv4/TCP/UDP/ICMP parsing.
- Optional VLAN tag parsing.
- Per-source traffic profiles and destination-port diversity.
- Configurable threshold indicators and a simple moving-average baseline.
- Console alerts and append-only log file.
- Separate C modules and basic tests.

## Requirements

On Debian/Ubuntu/Kali:

```sh
sudo apt update
sudo apt install build-essential libpcap-dev
```

## Build

```sh
make
```

Run tests:

```sh
make test
```

## Run

Find interface names:

```sh
ip link
```

Run on an interface you own or are explicitly authorized to monitor:

```sh
sudo ./rantm -i eth0
```

Use another config/log:

```sh
sudo ./rantm -c config/rantm.conf -i eth0 -l logs/alerts.log
```

Show help:

```sh
./rantm --help
```

## Important limitations

This is a learning/research prototype, not a production IDS. It currently
supports Ethernet or raw IPv4 link types, IPv4 only, and simple heuristic
signals. It does not reconstruct TCP sessions, verify whether connections
completed, or prove that an alert is an attack. The SYN/SYN-ACK counts are
observed packet counts in the monitored capture point, not a reliable
handshake tracker. Baseline learning needs more evaluation and safeguards
against poisoning, changing traffic patterns, NAT, and profile-table exhaustion.
It also does not automatically block traffic.

The capture loop currently runs until interrupted. Stop with Ctrl+C. Always
capture only traffic you are permitted to monitor.

## Research evaluation suggestions

Compare a fixed-threshold-only configuration against the baseline-enabled
configuration using benign lab traffic and repeatable synthetic traces. Report
true positives, false positives, precision, recall, detection latency, CPU use,
and memory use. Do not claim a statistically validated confidence percentage
unless the model has been calibrated against a labeled dataset.
