---
title: "Wire version and message type: explicit bytes for trait, method, version, and leg"
owner: "@decrypto21"
---

# RFC 0028: Wire Version and Message Type: Explicit Bytes for Trait, Method, Version, and Leg

|                 |                                                                                                                  |
| --------------- | ---------------------------------------------------------------------------------------------------------------- |
| **RFC Number**  | 28                                                                                                                 |
| **Start Date**  | 2026-08-31                                                                                                         |
| **Description** | Replace the flat `(trait, method)` wire discriminant with `(trait, method, version, message_type)`, so method ids run as a dense per-trait sequence instead of a request/response pair or subscription quartet spread, and a frame's version is readable without decoding its payload. |
| **Authors**     | Nidish                                                                                                             |

## Summary

The `(trait, method)` pair that addresses every TrUAPI frame is the same shape as a Substrate extrinsic's `(pallet_index, call_index)`: one byte names the module, the other names the operation within it. Codec 2's envelope (`[requestId][trait: u8][method: u8][payload]`) still spends that per-trait operation budget on which leg of a method's exchange a frame carries, not just the operation: a request/response method reserves two consecutive ids, a subscription reserves four. This RFC adds two outer bytes — `version`, then `message_type` — that name the payload's protocol version and the leg directly — `Request`/`Response` for request/response methods, `Start`/`Receive`/`Interrupt`/`Stop` for subscriptions — so the `(trait, method)` address stays exactly as flat as it is today (one `MethodIds` constant per method, unchanged as the dispatcher's routing key) while each method costs exactly one id regardless of how many legs its exchange has. Both bytes sit beside `trait` and `method` in the outer envelope rather than nested inside the payload, so a frame's version and leg are legible without decoding a single byte of its payload. Version comes first because version selects a method's *shape*: a later version may turn a plain call into a subscription, which changes which message types are legal for it.

## Motivation

Codec 2 already fixed the *global* fragmentation problem: every trait now owns a contiguous 256-value method-id block instead of competing for one flat byte. But within a trait, the id budget is still spent two-at-a-time or four-at-a-time on something that is not really part of the method's identity: which leg of the exchange a given frame carries. `system_get_product_context` is method ids 8 and 9; a four-frame subscription like `account_connection_status_subscribe` is ids 0 through 3. That pattern means:

- **The 256-value ceiling arrives twice as fast for request/response methods, four times as fast for subscriptions.** A trait with 60 subscription methods exhausts its id space at 15 methods, not 60.
- **A method's shape is locked in by its ids, not by anything reversible.** If `foo_request` needs to grow an interrupt leg between request and response after it has already shipped, that is not additive under the current scheme: it is a new set of wire ids replacing the old pair, i.e. a breaking removal plus a breaking addition, and it pushes back every other method's id in the same trait that follows it. There is no way to express "this method grew a leg" without touching the wire table.
- **Public release is the last point this can move for free.** Once products in the field are decoding on any fixed shape of this envelope, every registered id becomes permanent; this restructuring is free today and a second breaking wire cutover after release.

This RFC folds those concerns into the outer envelope, at the same moment codec 2's own cutover (`WIRE_CODEC_VERSION` 1 → 2) is already in flight and unreleased.

- **Version is addressable nowhere.** A method's version lives entirely inside its payload — `versioned::account::HostAccountGetRequest::V1(...)` — and the wire address that routed the frame there has already forgotten it. For a `Response` or `Interrupt` leg it is buried deeper still, under the `Result`/`Option` tag that comes first. Debug tooling and wire dumps see only `(trait, method)`; the version that actually decided the payload's shape is one or more `Decode` calls away, invisible until the frame fully round-trips. That is the opposite of what version is for: it selects which shape the following bytes have, so it has to be readable *before* them.

The original nested-enum sketch in the review thread makes both points at once: `LocaleMethod::V1(Request<Req, Res>)` puts version above the request/response enum, which flattened on the wire is exactly `[trait][method][version][message_type]`.

## Detailed Design

### Current shape (codec 2)

```text
[requestId: SCALE str][trait: u8][method: u8][payload bytes]
```

`method` is not one id per method: `n` for a request, `n+1` for its response, or `n..n+3` for a subscription's start/stop/interrupt/receive. Routing happens on those bytes alone; which leg a frame carries is only knowable by which id it arrived on.

### Proposed shape

```text
[requestId: SCALE str][trait: u8][method: u8][version: u8][message_type: u8][payload bytes]
```

One method id now serves every version and every leg a method has. `version` is 1-based, matching the payload wrapper's own `V1`/`V2`/... numbering, so `0` names no version any peer can decode and is refused at the frame boundary alongside the trait and method checks. It precedes `message_type` because it selects the shape the message type is then read against. `message_type` is a plain `u8`, not a SCALE enum tag on some shared generic — the dispatcher already knows, from a method's own registration, which shape (request/response or subscription) it expects, so the two families reuse the same small integers rather than spreading across one combined space:

```text
MESSAGE_TYPE_REQUEST   = 0   MESSAGE_TYPE_START     = 0
MESSAGE_TYPE_RESPONSE  = 1   MESSAGE_TYPE_RECEIVE   = 1
                             MESSAGE_TYPE_INTERRUPT = 2
                             MESSAGE_TYPE_STOP      = 3
```

`Request` and `Start` share `0`, `Response` and `Receive` share `1`, in the same position, so a subscription's first two legs partly decode the same way a request/response method's frames do.

There is no generic wrapper type carrying a leg's payload, and no version tag inside one: the header's `version` byte is the only version on the wire, and a peer reconstructs the wrapper variant from it. Each leg's payload bytes are:

- **Request**: `{Method}Request`'s own encoding (its `V1`/`V2`/... tag is the sole version signal for this leg).
- **Response**: `Result<{Method}Response, CallError<{Method}Error>>`, both sides already-versioned wrappers.
- **Start**: the request wrapper's own encoding, or zero bytes when the subscription takes no request at all.
- **Receive**: the item wrapper's own encoding.
- **Interrupt**: `Option<CallError<{Method}Error>>` — `None` is natural completion, `Some(err)` is a failure, replacing the previous silent-empty-frame convention with an explicit, decodable case. A subscription with no domain-specific error uses a bare `GenericError` in the same position.
- **Stop**: zero bytes, unconditionally — there is nothing left to version once a subscription is being torn down.

A frame's `version` byte describes its own payload, not the exchange. Because a method's legs version independently, a request at v2 can only be answered in a version the response wrapper actually has: if that wrapper stopped at v1, the response frame says `1`. Echoing the request's version instead would name a variant the bytes do not contain, and the peer would fail to decode an answer that is otherwise correct. Frames carrying nothing versioned — a `Stop`, a clean `Interrupt`, a framework-only error — report the version their caller asked in. The version appears exactly once; the payload never restates it, so the two can never disagree.

Stripping it is mechanical rather than structural. A versioned wrapper's SCALE encoding is `[version - 1][payload]`, since `versioned_type!` assigns positional codec indices alongside 1-based version numbers, so encoding drops that leading byte and decoding restores it from the header. For the `Response` and `Interrupt` legs the tag is not the payload's first byte — it sits behind the `Result`'s `Ok`/`Err` byte, and on the error side behind `CallError::Domain` — so those legs splice at a fixed offset instead. Framework errors (`Denied`, `Unsupported`, `MalformedFrame`, `HostFailure`) hold no versioned payload and pass through untouched. Both invariants are pinned by tests rather than trusted from a distance.

### Routing is unchanged

The dispatcher still keys on `(trait_id, method_id)`, one lookup. `message_type` is a second-level check the handler for that method already expects: a request/response registration accepts `Request` inbound and answers `Response`; a subscription registration accepts `Start`/`Stop` inbound and answers `Receive`/`Interrupt`. A frame carrying a `message_type` its registered handler does not expect (an outbound-shaped tag arriving inbound, or an unrecognized value) is a protocol violation, answered with `CallError::MalformedFrame`, exactly as an undecodable payload is today.

The reserved `(255, 255)` address is the exception, because it is the one address every peer answers on. A protocol error whose variant index this build does not recognize settles the correlated call and leaves the frame and the connection intact, rather than being rejected: a peer that refused an unfamiliar payload here could never be told anything new without the connection dying, which would freeze that channel at whatever shape shipped first. A recognized variant stays strict, since a malformed one is corruption rather than a newer peer.

### Adding a leg or a version later

Because `message_type` is not derived from a method's ids, growing a method's shape — the interrupt-after-a-few-months case that motivated this RFC — is purely additive: a new `message_type` value and a new encode/decode arm in that method's dispatch entry, with no change to `(trait, method)` and no pressure on any other method's id in the same trait. Because `version` precedes it, a later version of a method can change which legs it even has — turning a plain call into a subscription — and a peer can tell which shape it is being handed from the header alone.

### Compatibility

This folds into codec 2: `WIRE_CODEC_VERSION` stays `2`, and `MIN_TRAIT_ID`/`MAX_CODEC_1_METHOD_ID` are untouched, since the codec-1/codec-2 boundary is entirely about the first (trait) byte. Codec 2 has not shipped yet, so this is a zero-cost renumbering: there is no codec-2 peer anywhere to break a second time. Folding it into the same unreleased cutover avoids a third wire-breaking version bump before public release.

## Drawbacks

- One more byte on every frame on balance: `message_type` is new, while `version` moves out of the payload rather than being added to it, so a request frame is the same size it was.
- Payloads are no longer self-describing. A payload's bytes are meaningless without the frame header that states their version, so a payload cannot be stored, forwarded or logged on its own and decoded later. TrUAPI payloads never travel apart from their frame, so nothing in the protocol relies on that property today.
- The encode/decode path splices a byte in and out at a leg-dependent offset, rather than handing whole values to `Encode`/`Decode`. It rests on two invariants — a versioned wrapper's tag is `version - 1`, and `CallError::Domain` is the first variant — that a future change to the macro or the enum could silently break, which is why both are pinned by tests.
- Codegen must special-case each method's leg set explicitly — a per-method match over `message_type` — rather than decoding through one shared generic. This is more codegen surface per method than a single `Request<Req, Res>`/`Subscription<Start, Item, Err>` wrapper would need, but it removes the generic entirely from the generated client's call sites: a generated method calls a leg's own wrapper codec directly rather than constructing a `Request::Request(...)`/`Subscription::Start(...)` variant first.
- A subscription's `Interrupt` leg needs its own error type parameter per method (or the shared `GenericError` fallback) at the codegen layer, rather than inheriting one fixed `Err` slot from a single generic — a small amount of additional bookkeeping in the generator, not in generated or hand-written call sites.

## Testing, Security, and Privacy

Regenerating the golden and fixture tests listed above is the primary verification surface: byte-level goldens (`golden-account-get.bin`, the wire-table/dispatcher parity tests) must be recomputed, not relaxed, exactly as codec 2's own cutover recomputed them rather than loosening their assertions. No new security surface is introduced; `CallError::MalformedFrame` is the correct response to a `Response`/`Receive`/`Interrupt`/`Stop` tag arriving where a `Request`/`Start` tag is expected, rather than accepting it silently. One migration consequence is worth stating: a codec-1 peer's three-byte header is now a *truncated* frame rather than one that happens to parse, so it is dropped at the codec instead of being answered with an unsupported-pair protocol error.

## Performance, Ergonomics, and Compatibility

### Performance

Routing remains a single `HashMap<(u8, u8), _>` lookup, unchanged in complexity. The added cost is one extra single-byte read per frame plus a byte splice on each payload, negligible next to decoding the payload itself, and it removes work elsewhere: reading a frame's version no longer requires decoding into the payload at all.

### Ergonomics

Method ids become a dense, gap-free per-trait sequence (0, 1, 2, ...) instead of today's 0, 2, 4, 6, 8 pattern, which is easier to read off a wire dump and easier to eyeball for accidental collisions in review. `version` and `message_type` are both legible directly off the outer envelope, before any payload decode, which is what makes debug tooling (`truapi-debugger`) able to resolve a frame's role and version from the wire alone rather than peeking into payload bytes. A method that starts as plain request/response and later needs a streaming or control leg expresses that as a new `message_type` value and dispatch arm, rather than as a set of wire ids replacing another set.

### Compatibility

Covered above: folds into codec 2, no additional version bump.

## Future Directions and Related Material

Once every trait's method ids are dense and gap-free under this scheme, a later RFC could reconsider whether trait ids need the same permanent `MIN_TRAIT_ID` reservation once no codec-1 peer remains in the field.
