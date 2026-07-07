# Upstream pouch: issues & proposals

Findings from building pouch-network-provisioning on top of
[golioth/pouch](https://github.com/golioth/pouch). Each is a candidate
issue/PR against pouch; filed here first so the provisioning library can
track and, where possible, work around them.

---

## 1. Proposal: mix a pre-shared secret into the saead HKDF (closes MITM gap)

**What.** Add an optional application-supplied secret as additional HKDF
input when deriving the saead session key (alongside the ECDH shared
secret and the existing info string).

**Why.** Local provisioning terminates the pouch session at an untrusted
client and authorizes it with a proof-of-possession challenge inside the
encrypted channel (`.prov/auth`). Because the PoP is *not* bound into the
key agreement, an active relay present during the provisioning window can
in principle bridge two sessions (classic unauthenticated-DH MITM). Mixing
the PoP into the KDF binds the channel to knowledge of the secret and
closes this without a PKI.

**Sketch.** In `session_key_generate` (`src/saead/session.c`), after the
ECDH `key_agreement` and before `output_key`, optionally
`psa_key_derivation_input_bytes(PSA_KEY_DERIVATION_INPUT_INFO, psk, len)`
(or a dedicated salt input). Gate on a new config/parameter so existing
device↔cloud sessions are unchanged.

**Impact for us.** Removes the one accepted residual risk in
[docs/protocol.md](protocol.md#threat-model). Until then we document the
window as a known limitation.

---

## 2. Doc: SAR FIN success requires the IDLE flag; first FIN omits it

**What.** Document the FIN semantics in `src/transport/sar` for host/client
implementers.

Observed (pouch `receiver.c`):
- The receiver treats a FIN as **success only if the IDLE flag is set**
  (`success = !!(pkt.flags & POUCH_SAR_TX_PKT_FLAG_IDLE)`); a bare FIN ends
  the transfer as *failed* and the peripheral disconnects.
- The sender's *first* FIN is sent **without** IDLE; IDLE is only added on
  a retransmitted FIN (`sender.c: send_fin`, `state == STATE_IDLE`).

**Why it matters.** A from-scratch client (our Python SAR) must set IDLE on
its final FIN, and must treat the device's first (IDLE-less) FIN as
success. This asymmetry is easy to get wrong and fails silently as a
dropped BLE link. A short note in the SAR header or a `docs/` page would
save reimplementers the reverse-engineering.

---

## 3. Bug: `POUCH_DOWNLINK_HANDLER` macro pastes a literal token

**What.** In `include/pouch/downlink.h`, the macro builds the static symbol
name from a literal `_callback` rather than the handler argument:

```c
#define POUCH_DOWNLINK_HANDLER(_start_cb, _data_cb) \
    static const POUCH_STRUCT_SECTION_ITERABLE( \
        pouch_downlink_handler, \
        _pouch_downlink_handler_##_callback) = {...}   // <-- always "_callback"
```

**Effect.** Registering two downlink handlers in the same translation unit
produces duplicate symbol names → build error. Single-handler users are
unaffected (we deliberately register exactly one), but it's a latent
foot-gun.

**Fix.** Paste one of the callback argument names, e.g.
`_pouch_downlink_handler_##_start_cb`.

---

## 4. Proposal: reserve an advertising flag bit for "provisioning available"

**What.** The GATT advertising payload (`struct pouch_gatt_adv_data`,
`include/pouch/transport/bluetooth/gatt.h`) has a `flags` byte with bit 0 =
`POUCH_GATT_ADV_FLAG_SYNC_REQUEST`. We use **bit 1** as a vendor extension
to signal "device is in provisioning mode" so a scanner can filter for it.

**Ask.** Reserve a bit officially (or bless bit 1) so provisioning-aware
scanners across implementations interoperate.

---

## 5. Proposal: reactive uplink (stream responses without CCC re-toggling)

**What.** Pouch's uplink is a device-initiated batch that auto-closes after
`POUCH_UPLINK_HANDLER`s run (`src/uplink.c` event handler →
`pouch_uplink_close`). A device cannot push entries into an already-open
uplink pouch reactively, so a request/response RPC needs one CCC-subscribe
cycle per direction per exchange (see our
[RPC model](protocol.md#rpc-model)).

**Proposal.** A `pouch_bearer_ready()`-style kick on uplink enqueue plus an
opt-out of the auto-close would let a long-lived subscription stream
responses as they're produced — lower latency and fewer BLE operations for
interactive flows like provisioning.

**Impact for us.** Would simplify the client session loop and remove the
empty-pouch "retry later" polling. Non-blocking today; filed as an
enhancement.
