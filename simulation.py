"""
Diffie-Hellman Performance Simulation

Compares finite-field Diffie-Hellman (2048-bit) and elliptic-curve
Diffie-Hellman (secp256r1) under simulated network conditions.

The simulation measures:
- Key exchange computation time
- Network latency
- Public key sizes
- Total bytes transmitted
- Retransmission attempts under packet loss
- Successful shared-key agreement
"""

import time
import random
import statistics

from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# Link model

LINK_DISTANCE_KM = 500
LOSS_PROBABILITY = 0.30
FIBRE_SIGNAL_SPEED_KM_PER_S = 200000  
SINGLE_TRIP_DELAY_S = LINK_DISTANCE_KM / FIBRE_SIGNAL_SPEED_KM_PER_S
RETURN_TRIP_DELAY_S = SINGLE_TRIP_DELAY_S * 2


DH_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048)


def simulate_transmission(payload_bytes, loss_rate=LOSS_PROBABILITY):
    """
    Simulate sending one message over a lossy 500 km link.
    Returns:
        total_delay_s: transmission delay including retransmissions
        attempts: number of attempts needed
        bytes_sent: total bytes sent including retransmissions
    """
    attempts = 0
    total_delay_s = 0.0
    bytes_sent = 0

    while True:
        attempts += 1
        total_delay_s += RETURN_TRIP_DELAY_S
        bytes_sent += payload_bytes

        if random.random() >= loss_rate:
            break

    return total_delay_s, attempts, bytes_sent



# Finite-field Diffie-Hellman

def run_ffdh():
    """Run one finite-field Diffie-Hellman key exchange simulation."""

    start = time.perf_counter()

    private_key_a = DH_PARAMETERS.generate_private_key()
    private_key_b = DH_PARAMETERS.generate_private_key()

    public_key_a = private_key_a.public_key()
    public_key_b = private_key_b.public_key()

    pub_a_bytes = public_key_a.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_b_bytes = public_key_b.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    tx1_delay, tx1_attempts, tx1_bytes = simulate_transmission(len(pub_a_bytes))
    tx2_delay, tx2_attempts, tx2_bytes = simulate_transmission(len(pub_b_bytes))

    shared_key_a = private_key_a.exchange(public_key_b)
    shared_key_b = private_key_b.exchange(public_key_a)

    derived_key_a = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key_a)

    derived_key_b = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key_b)

    end = time.perf_counter()

    return {
        "protocol": "Finite-field Diffie-Hellman (2048-bit)",
        "success": derived_key_a == derived_key_b,
        "compute_time_ms": (end - start) * 1000,
        "network_latency_ms": (tx1_delay + tx2_delay) * 1000,
        "total_latency_ms": ((end - start) + tx1_delay + tx2_delay) * 1000,
        "bytes_sent": tx1_bytes + tx2_bytes,
        "attempts": tx1_attempts + tx2_attempts,
        "pubkey_a_size": len(pub_a_bytes),
        "pubkey_b_size": len(pub_b_bytes),
    }



# Elliptic Curve Diffie-Hellman

def run_ecdh():
    """Run one elliptic-curve Diffie-Hellman key exchange simulation."""
    start = time.perf_counter()

    private_key_a = ec.generate_private_key(ec.SECP256R1())
    private_key_b = ec.generate_private_key(ec.SECP256R1())

    public_key_a = private_key_a.public_key()
    public_key_b = private_key_b.public_key()

    pub_a_bytes = public_key_a.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    pub_b_bytes = public_key_b.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    tx1_delay, tx1_attempts, tx1_bytes = simulate_transmission(len(pub_a_bytes))
    tx2_delay, tx2_attempts, tx2_bytes = simulate_transmission(len(pub_b_bytes))

    shared_key_a = private_key_a.exchange(ec.ECDH(), public_key_b)
    shared_key_b = private_key_b.exchange(ec.ECDH(), public_key_a)

    derived_key_a = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key_a)

    derived_key_b = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key_b)

    end = time.perf_counter()

    return {
        "protocol": "ECDH (secp256r1)",
        "success": derived_key_a == derived_key_b,
        "compute_time_ms": (end - start) * 1000,
        "network_latency_ms": (tx1_delay + tx2_delay) * 1000,
        "total_latency_ms": ((end - start) + tx1_delay + tx2_delay) * 1000,
        "bytes_sent": tx1_bytes + tx2_bytes,
        "attempts": tx1_attempts + tx2_attempts,
        "pubkey_a_size": len(pub_a_bytes),
        "pubkey_b_size": len(pub_b_bytes),
    }



# Repeated trials

def run_trials(protocol_fn, trials=5):
    results = []
    for _ in range(trials):
        results.append(protocol_fn())
    return results


def summarise_results(results):
    return {
        "protocol": results[0]["protocol"],
        "success_rate": sum(1 for r in results if r["success"]) / len(results),
        "avg_compute_time_ms": statistics.mean(r["compute_time_ms"] for r in results),
        "avg_network_latency_ms": statistics.mean(r["network_latency_ms"] for r in results),
        "avg_total_latency_ms": statistics.mean(r["total_latency_ms"] for r in results),
        "avg_bytes_sent": statistics.mean(r["bytes_sent"] for r in results),
        "avg_attempts": statistics.mean(r["attempts"] for r in results),
        "pubkey_a_size": results[0]["pubkey_a_size"],
        "pubkey_b_size": results[0]["pubkey_b_size"],
    }


if __name__ == "__main__":
    random.seed(42)

    ffdh_results = run_trials(run_ffdh, trials=5)
    ecdh_results = run_trials(run_ecdh, trials=5)

    ffdh_summary = summarise_results(ffdh_results)
    ecdh_summary = summarise_results(ecdh_results)

    print("=== Raw Trial Outputs ===")
    for r in ffdh_results:
        print(r)
    for r in ecdh_results:
        print(r)

    print("\n=== Summary ===")
    print(ffdh_summary)
    print(ecdh_summary)
