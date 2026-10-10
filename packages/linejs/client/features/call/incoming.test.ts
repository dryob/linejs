import { assert, assertEquals } from "@std/assert";
import { parseIncomingAudioCall } from "./incoming.ts";
import { generateEphemeralKeypair, sha256 } from "./planet/crypto.ts";

const caller = `u${"1".repeat(32)}`;
const self = `u${"2".repeat(32)}`;

Deno.test("incoming audio binds native operation identity, CID and credential", () => {
	const params = {
		k: "CA",
		n: "synthetic-token",
		vs: "synthetic-call",
		vfz: "JP",
		vtz: "JP",
		h: "127.0.0.1",
		p: "9000",
		vc: JSON.stringify({
			mpkey: btoa(String.fromCharCode(...generateEphemeralKeypair().publicKey)),
		}),
	};
	const operation = {
		type: "NOTIFIED_RECEIVED_CALL",
		param1: caller,
		param2: params.n,
		param3: JSON.stringify(params),
		createdTime: 1,
	};
	const call = parseIncomingAudioCall(operation, self);
	assert(call);
	assertEquals(call.callId, params.vs);
	assertEquals(call.callerMid, caller);
	assertEquals(call.localMid, self);
	assertEquals(call.route.toMid, caller);
	assertEquals(
		call.credential,
		sha256(
			new TextEncoder().encode([caller, self, params.n, params.vs].join("::")),
		),
	);
	for (
		const patch of [
			{ k: "CV" },
			{ k: undefined },
			{ g: "group" },
			{ sei: "group" },
			{ n: "other" },
			{ vs: "" },
			{ p: "0" },
			{ h: "bad/host" },
			{ vc: "{}" },
			{ vc: "not-json" },
		]
	) {
		assertEquals(
			parseIncomingAudioCall({
				...operation,
				param3: JSON.stringify({ ...params, ...patch }),
			}, self),
			undefined,
		);
	}
	assertEquals(parseIncomingAudioCall(operation, caller), undefined);
	assertEquals(parseIncomingAudioCall(operation, ""), undefined);
	assertEquals(
		parseIncomingAudioCall(
			{ ...operation, param1: `c${"1".repeat(32)}` },
			self,
		),
		undefined,
	);
	assertEquals(
		parseIncomingAudioCall({ ...operation, type: "CANCEL_CALL" }, self),
		undefined,
	);
});
