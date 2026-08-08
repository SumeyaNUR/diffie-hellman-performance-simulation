Diffie-Hellman Protocol Performance Simulation

## Overview

This Python project compares the performance of two cryptographic key exchange methods:

- Finite-field Diffie-Hellman using a 2048-bit key
- Elliptic Curve Diffie-Hellman using the SECP256R1 curve

The simulation measures how both protocols perform across a lossy 500 km network link.

It evaluates computational time, network latency, retransmission attempts, transmitted data size and successful shared-key generation.

## Features

- Generates Diffie-Hellman and ECDH key pairs
- Exchanges public keys between two simulated participants
- Derives matching 256-bit keys using HKDF and SHA-256
- Simulates packet loss and retransmissions
- Models propagation delay across a 500 km fibre link
- Runs repeated trials for each protocol
- Calculates average performance results
- Compares public-key sizes and total transmitted data

## Technologies

- Python
- Cryptography library
- Diffie-Hellman
- Elliptic Curve Cryptography
- HKDF
- SHA-256
- Network simulation
- Statistical analysis

## Network Model

The simulation uses the following assumptions:

- Link distance: 500 km
- Packet-loss probability: 30%
- Fibre signal speed: 200,000 km/s
- Failed transmissions are repeated until successful
- Each public key is transmitted separately

These values are configurable inside `simulation.py`.

## Metrics

The program records:

- Key agreement success
- Computation time
- Network latency
- Total latency
- Total bytes transmitted
- Number of transmission attempts
- Public-key size
- Average results across repeated trials


## How to Run

1. Clone the repository.
2. Install the required dependency:

```bash
pip install -r requirements.txt
```bash
python simulation.py
