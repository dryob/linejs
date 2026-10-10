# Incoming audio calls

`client.call.answerIncoming(event, options)` explicitly answers an ordinary 1:1
incoming audio call. Listening alone never answers. Use the `call:incoming` event
from a logged-in client, check `event.audio`, and apply your own admission policy
before calling it. Unsupported, video, group and unclassified operations are not
answerable. The existing raw event remains available for other applications.

```ts
client.on("call:incoming", (event) => {
	if (!event.audio) return;
	// Ask the user before invoking answerIncoming; see the complete helper below.
});
```

[`example/call/incoming.ts`](../example/call/incoming.ts) installs an admission
callback and a media callback on an already authenticated client. The returned
`PlanetTransport` sends and receives encoded Opus packets using `send()` and
`receive()`. Use the existing audio/Opus helpers for PCM conversion. `ended`
resolves on local close or remote release; always call `close()` in cleanup.
Node and Deno UDP runtimes are supported, not browser UDP.

## Identity and lifetime

Pass `deviceId` as a stable, application-owned installation identifier: generate
32 random bytes once, encode them as base64, and persist them in the application's
private storage. Do not use an account token or copy a device ID from another
client. The library does not choose a filesystem or provision Android identity.
The user agent comes from the logged-in client's device details. Incoming audio
uses the same `freecall.audio` service selector as outgoing audio.

The answer helper reparses the authenticated operation and binds caller, call ID,
route credential and local profile. Do not feed it JSON from an unauthenticated
HTTP endpoint. `param1` identifies the caller, `param3.vs` the call, and `param2`
must match `param3.n`; `k=CA` identifies ordinary audio. The route and credential
are sensitive and should not be logged.

Only one incoming answer is pending/active per call client; an immediately
repeated call ID is rejected. Applications must coordinate their outgoing sessions
and longer-lived replay/admission policy. `signal` aborts verification, answering
or an active call. `timeoutMs` bounds each signaling stage (default 10 seconds).
An abort during socket binding waits for binding cleanup; binding has its own
finite timeout. Malformed offers, rejected replies, unresolved endpoints and
signaling timeouts close the transport rather than leaving an answer half-open.

## Protocol scope and evidence

The callee sends VERIFY, accepts only a matching authenticated transaction, then
sends CONN with a fresh E2EE-only audio answer. A provisional CONN reply does not
enable media. Replies must match the call, session, channels, nonces and current
transaction. When final CONN omits `mAddr`, media uses the authenticated,
correlated VERIFY UDP peer. An explicit invalid `mAddr` fails; neither the local
NAT address nor unauthenticated RTP traffic can redirect this endpoint. Send SSRC
comes from the local answer's field 11, not the caller offer's field 61.

The source JavaScript implementation was live-tested for audible incoming audio.
This TypeScript port is verified with synthetic encrypted UDP and SRTP tests,
including the public answer helper, SSRC, no-address routing, provisional replies,
abort, timeout and remote release. It has not had a separate live phone-call test.

CANCEL_CALL operation correlation is not established, so the helper does not
infer cancellation from a caller alone. Use explicit application abort or the
correlated PLANET release. Alternate BEPI/P2P migration, group/video calls and
full native media-KDF byte equality remain outside this implementation's verified
scope. Existing outgoing signaling and release behavior are preserved.
