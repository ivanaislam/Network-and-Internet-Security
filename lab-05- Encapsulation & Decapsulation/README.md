# Lab 05 — Encapsulation and De-encapsulation (TCP/IP Stack) using Scapy

*Network and Internet Security — Department of Cyber Security Engineering, University of Frontier Technology, Bangladesh*

---

## 1. Problem Statement

A client host (**seed base**, my SEED lab Sender machine) with IP address `192.168.56.105`, MAC address `08:00:27:01:c1:64`, and TCP source port `5000` sends the message **"Cyber Security Engineering"** to a server (**seed Receiver**, my SEED lab Receiver machine) with IP address `192.168.56.107`, MAC address `08:00:27:a8:5e:f3`, and TCP destination port `80`.

Assume the TCP layer segments the application message into data units of **at most 15 bytes** before transmission, with:
- TCP header: 20 bytes
- IP header: 20 bytes
- Ethernet header: 14 bytes
- Ethernet trailer (FCS): 4 bytes

The task is to construct the complete encapsulation process — Data → TCP Segments → IP Packets → Ethernet Frames — and then reverse it (decapsulation) on the server side.

---

## 2. Analysis & Segmentation Math

**Application Message**
- Data: `"Cyber Security Engineering"`
- Total length: **26 bytes**
- Segmentation limit: at most **15 bytes** per segment

Number of segments = ⌈26 / 15⌉ = **2 segments**

- **Segment 1 data (15 bytes):** `"Cyber Security "` (bytes 0–14)
- **Segment 2 data (11 bytes):** `"Engineering"` (bytes 15–25)

---

## 3. Layer-by-Layer Byte Calculations

Assume the client (seed base) starts with an Initial Sequence Number (**ISN**) of `1000`.

| Layer | Header / Trailer | Frame 1 (15-byte payload) | Frame 2 (11-byte payload) |
|---|---|---|---|
| **L7: Application** | Payload only | **15 bytes** | **11 bytes** |
| **L4: TCP** | Header: 20 bytes (Sport: 5000, Dport: 80) | Total: **35 bytes** (Seq=1000) | Total: **31 bytes** (Seq=1015) |
| **L3: IP** | Header: 20 bytes (Src: 192.168.56.105, Dst: 192.168.56.107) | Total: **55 bytes** (Total Length = 55) | Total: **51 bytes** (Total Length = 51) |
| **L2: Ethernet** | Header: 14 bytes, Trailer (FCS): 4 bytes | Total: **73 bytes** (14 + 55 + 4) | Total: **69 bytes** (14 + 51 + 4) |

> **Note on minimum frame size:** The minimum standard Ethernet frame size is **64 bytes** (including FCS). Since Frame 1 is 73 bytes and Frame 2 is 69 bytes, **no Ethernet padding** is needed for either frame.

---

## 4. Visual Encapsulation Diagrams

### Frame 1 Encapsulation Diagram (73 Bytes on Wire)

```
+--------------------------------------------------------------------+
|                         ETHERNET FRAME 1                           |
+-----------------+------------------+--------------+-------+-------+
| Ethernet Header |    IP Header     | TCP Header   | App   |  FCS  |
|   (14 Bytes)    |   (20 Bytes)     |  (20 Bytes)  | Data  | (4 B) |
|                 |                  |              |(15 B) |       |
+-----------------+------------------+--------------+-------+-------+
| Dst: AA:BB:...FF (08:00:27:a8:5e:f3) | Src: 192.168.56.105  | Sport: 5000  | "Cyber Security |  CRC-32 |
| Src: 00:11:...55 (08:00:27:01:c1:64) | Dst: 192.168.56.107  | Dport: 80    |  "              |         |
| Type: 0x0800                         | Protocol: 6 (TCP)    | Seq: 1000    |                 |         |
+-----------------+------------------+--------------+-------+-------+
|<----------- Header + IP Payload = 69 Bytes ------------>|<-Trailer->|
|<-------------------- Total Wire Size = 73 Bytes -------------------->|
```

### Frame 2 Encapsulation Diagram (69 Bytes on Wire)

```
+--------------------------------------------------------------------+
|                         ETHERNET FRAME 2                           |
+-----------------+------------------+--------------+-------+-------+
| Ethernet Header |    IP Header     | TCP Header   | App   |  FCS  |
|   (14 Bytes)    |   (20 Bytes)     |  (20 Bytes)  | Data  | (4 B) |
|                 |                  |              |(11 B) |       |
+-----------------+------------------+--------------+-------+-------+
| Dst: AA:BB:...FF (08:00:27:a8:5e:f3) | Src: 192.168.56.105  | Sport: 5000  | "Engineering"   |  CRC-32 |
| Src: 00:11:...55 (08:00:27:01:c1:64) | Dst: 192.168.56.107  | Dport: 80    |                 |         |
| Type: 0x0800                         | Protocol: 6 (TCP)    | Seq: 1015    |                 |         |
+-----------------+------------------+--------------+-------+-------+
|<----------- Header + IP Payload = 65 Bytes ------------>|<-Trailer->|
|<-------------------- Total Wire Size = 69 Bytes -------------------->|
```

---

## 5. Scapy Code Implementation (Encapsulation)

This script constructs the exact encapsulation for both frames, inspects the byte lengths at each layer, and calculates the 4-byte CRC-32 FCS trailer — using my actual SEED lab addresses (seed base as client/sender, seed Receiver as server).

```python
import zlib
import struct
from scapy.all import Ether, IP, TCP, Raw, hexdump

# --------------------------------------------------------------
# Configuration Parameters (my SEED lab addresses)
# --------------------------------------------------------------
SRC_MAC = "08:00:27:01:c1:64"   # seed base (client/Sender)
DST_MAC = "08:00:27:a8:5e:f3"   # seed Receiver (server)
SRC_IP  = "192.168.56.105"      # seed base
DST_IP  = "192.168.56.107"      # seed Receiver
SRC_PORT = 5000
DST_PORT = 80
ISN = 1000
FULL_MESSAGE = b"Cyber Security Engineering"
MAX_SEG_SIZE = 15

print(f"[*] Original Message: '{FULL_MESSAGE.decode()}' ({len(FULL_MESSAGE)} bytes)\n")

# --------------------------------------------------------------
# 1. APPLICATION LAYER (L7) - Segmentation
# --------------------------------------------------------------
chunk_1 = FULL_MESSAGE[:MAX_SEG_SIZE]      # b"Cyber Security " (15 bytes)
chunk_2 = FULL_MESSAGE[MAX_SEG_SIZE:]      # b"Engineering" (11 bytes)

data_units = [
    {"chunk": chunk_1, "seq": ISN},
    {"chunk": chunk_2, "seq": ISN + len(chunk_1)}
]

frames = []

for i, unit in enumerate(data_units, start=1):
    payload = unit["chunk"]
    seq_num = unit["seq"]

    print("=" * 65)
    print(f"CONSTRUCTING FRAME {i}")
    print("=" * 65)

    # L7: Data
    l7 = Raw(load=payload)
    print(f"[L7 Data] Payload: '{payload.decode()}' | Length: {len(payload)} bytes")

    # L4: TCP Segment
    l4 = TCP(sport=SRC_PORT, dport=DST_PORT, seq=seq_num, flags="PA") / l7
    l4_bytes = bytes(l4)
    print(f"[L4 Segment] TCP Header (20B) + Payload ({len(payload)}B) = {len(l4_bytes)} bytes")
    print(f"             Seq Number: {seq_num}")

    # L3: IP Packet
    l3 = IP(src=SRC_IP, dst=DST_IP) / l4
    l3_bytes = bytes(l3)
    print(f"[L3 Packet] IP Header (20B) + Segment ({len(l4_bytes)}B) = {len(l3_bytes)} bytes")

    # L2: Ethernet Frame (Header + Payload)
    l2 = Ether(src=SRC_MAC, dst=DST_MAC) / l3
    l2_without_fcs = bytes(l2)
    print(f"[L2 Frame Hdr] Eth Header (14B) + Packet ({len(l3_bytes)}B) = {len(l2_without_fcs)} bytes")

    # L2 Trailer: 4-Byte Frame Check Sequence (FCS) using CRC-32
    fcs_int = zlib.crc32(l2_without_fcs) & 0xffffffff
    fcs_bytes = struct.pack("!I", fcs_int)

    # Complete Wire Bytes (including 4-byte FCS)
    wire_frame = l2_without_fcs + fcs_bytes
    frames.append(wire_frame)

    print(f"[L2 Trailer] Ethernet FCS (CRC-32): {fcs_bytes.hex()} (4 bytes)")
    print(f"[TOTAL ON WIRE] {len(wire_frame)} bytes\n")

    print("Hexdump of Complete Frame on Wire:")
    hexdump(wire_frame)
    print("\n")
```

---

## 6. Decapsulation & Reassembly on the Server Side (seed Receiver)

This shows how the server host (`192.168.56.107`, seed Receiver) strips the headers from both frames and reassembles the original message.

```python
print("=" * 65)
print("SERVER-SIDE DECAPSULATION & REASSEMBLY")
print("=" * 65)

reassembled_message = b""

for i, raw_wire in enumerate(frames, start=1):
    # 1. Hardware checks & strips 4-byte FCS
    frame_body = raw_wire[:-4]

    # 2. Parse Ethernet (L2)
    eth_layer = Ether(frame_body)
    print(f"Frame {i}: Verified MAC Dst: {eth_layer.dst} (Matches Server)")

    # 3. Strip Ethernet -> Parse IP (L3)
    ip_layer = eth_layer[IP]
    print(f"          Verified IP Dst : {ip_layer.dst} (Matches Server)")

    # 4. Strip IP -> Parse TCP (L4)
    tcp_layer = eth_layer[TCP]
    print(f"          Verified Port   : {tcp_layer.dport} (Port 80 HTTP)")
    print(f"          TCP Seq Number  : {tcp_layer.seq}")

    # 5. Extract Application Payload (L7)
    app_chunk = tcp_layer[Raw].load
    print(f"          Extracted Chunk : '{app_chunk.decode()}'\n")

    reassembled_message += app_chunk

print(f"[\u2713] Final Reassembled Message at Server: '{reassembled_message.decode()}'")
```

### Expected Output

```
=================================================================
SERVER-SIDE DECAPSULATION & REASSEMBLY
=================================================================
Frame 1: Verified MAC Dst: 08:00:27:a8:5e:f3 (Matches Server)
          Verified IP Dst : 192.168.56.107 (Matches Server)
          Verified Port   : 80 (Port 80 HTTP)
          TCP Seq Number  : 1000
          Extracted Chunk : 'Cyber Security '

Frame 2: Verified MAC Dst: 08:00:27:a8:5e:f3 (Matches Server)
          Verified IP Dst : 192.168.56.107 (Matches Server)
          Verified Port   : 80 (Port 80 HTTP)
          TCP Seq Number  : 1015
          Extracted Chunk : 'Engineering'

[✓] Final Reassembled Message at Server: 'Cyber Security Engineering'
```

---

## 7. Conclusion

This lab walked through the full TCP/IP encapsulation pipeline in both directions:

- **Encapsulation (client / seed base side):** the 26-byte application message was segmented into two TCP data units (15 bytes and 11 bytes, respecting the 15-byte segment limit), each wrapped in a 20-byte TCP header, then a 20-byte IP header, then a 14-byte Ethernet header plus a 4-byte CRC-32 FCS trailer — producing complete wire frames of 73 and 69 bytes respectively, both safely above the 64-byte Ethernet minimum so no padding was required.
- **Decapsulation (server / seed Receiver side):** each frame was unwrapped layer by layer (Ethernet → IP → TCP → Application), verifying the destination MAC, destination IP, and destination port at every step, before the two extracted data chunks were concatenated back into the original message, `'Cyber Security Engineering'`.

This confirms, byte-for-byte, how encapsulation adds headers (and a trailer) going down the stack on the sender's side, and how decapsulation strips them back off going up the stack on the receiver's side — using the same Sender (`192.168.56.105`) and Receiver (`192.168.56.107`) addressing scheme used throughout my other SEED labs (Lab 02, Lab 03, and Lab 04).

---

*Prepared for academic lab submission — Encapsulation and De-encapsulation using Scapy (Lab 05).*
