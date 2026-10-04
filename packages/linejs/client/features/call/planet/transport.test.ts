import { assert, assertEquals, assertRejects } from "@std/assert";
import { Buffer } from "node:buffer";
import { createSocket, type RemoteInfo, type Socket } from "node:dgram";
import {
	aesCtrDecrypt,
	aesCtrEncrypt,
	buildDirectionLabel,
	buildPlanetCtrIv,
	deriveCallKeys,
	derivePlanetMediaKeys,
	derivePlanetMediaStreamKeying,
	type EphemeralKeypair,
	generateEphemeralKeypair,
	hmacTag,
	tagEquals,
	type TransportKeys,
} from "./crypto.ts";
import { makeChunkHdr } from "./framing.ts";
import {
	CC_MSG,
	decodeFields,
	decodeMcDataReq,
	decodeMcDataRsp,
	decodePlanetMsg,
	encodeVarint,
	MC_MSG,
	packCcConnReq,
	packCcInfoReq,
	packCcSetupRsp,
	packMcDataReq,
	packNativeSetupOffer,
	packPlanetCcMsg,
	packPlanetMcMsg,
	packPlanetMsg,
	type PlanetSetupOfferMaterial,
	wrapCcMsg,
	wrapMcMsg,
} from "./schema.ts";
import { PlanetTransport } from "./transport.ts";
import { packetizeNativeGroupOpusPairs } from "../audio.ts";
import { deriveSrtpContext, parseRtp, srtpDecrypt } from "../srtp.ts";

type CallRouteLike = Parameters<PlanetTransport["connect"]>[0]["route"];

const HEADER_LEN = 6;
const BOOTSTRAP_PREFIX_LEN = 51;
const BOOTSTRAP_SEC_HEADER_LEN = 5;
const REGULAR_TAIL_CONTROL_BASE = 0x18;

function bytesToBase64(bytes: Uint8Array): string {
	let raw = "";
	for (const b of bytes) raw += String.fromCharCode(b);
	return btoa(raw);
}

function makeRoute(peer = generateEphemeralKeypair(), port = 9): CallRouteLike {
	return {
		voipAddress: "127.0.0.1",
		voipUdpPort: port,
		voipAddress6: "",
		toMid: "u-peer",
		fromToken: "from-token",
		fromZone: "JP",
		toZone: "JP",
		commParam: JSON.stringify({ mpkey: bytesToBase64(peer.publicKey) }),
		stid: "stid",
		stnpk: "stnpk",
	} as unknown as CallRouteLike;
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
	const len = parts.reduce((n, p) => n + p.length, 0);
	const out = new Uint8Array(len);
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}

function buildBootstrapSecHeader(plaintextLen: number): Uint8Array {
	return new Uint8Array([
		0,
		0,
		0,
		0x28 | ((plaintextLen >>> 8) & 0x07),
		plaintextLen & 0xff,
	]);
}

function buildBootstrapFrameHeader(
	totalLen: number,
	sequence: number,
): Uint8Array {
	const chunkLogical = ((((totalLen - 4) << 5) | 0x1d) & 0xffff) >>> 0;
	const chunk = makeChunkHdr(chunkLogical);
	return new Uint8Array([
		chunk & 0xff,
		(chunk >>> 8) & 0xff,
		(sequence >>> 8) & 0xff,
		sequence & 0xff,
		0x06,
		0x02,
	]);
}

function buildRegularFrameHeader(
	totalLen: number,
	sequence: number,
	plaintextLen: number,
): Uint8Array {
	const chunkLogical = ((((totalLen - 4) << 5) | 0x0d) & 0xffff) >>> 0;
	const chunk = makeChunkHdr(chunkLogical);
	const tail16 = (((REGULAR_TAIL_CONTROL_BASE |
		((plaintextLen >>> 8) & 0x07)) << 8) | (plaintextLen & 0xff)) & 0xffff;
	return new Uint8Array([
		chunk & 0xff,
		(chunk >>> 8) & 0xff,
		(sequence >>> 8) & 0xff,
		sequence & 0xff,
		(tail16 >>> 8) & 0xff,
		tail16 & 0xff,
	]);
}

function buildServerWire(
	keys: TransportKeys,
	plaintext: Uint8Array,
	sequence: number,
	opts: { bootstrap?: { label: number; seed: Uint8Array; pub: Uint8Array } } =
		{},
): Uint8Array {
	const ct = aesCtrEncrypt(
		keys.encKey,
		buildPlanetCtrIv(keys.ctrBase, sequence),
		plaintext,
	);
	const tagLen = 16;
	if (opts.bootstrap) {
		const prefix = concatBytes([
			buildDirectionLabel(opts.bootstrap.label),
			opts.bootstrap.seed,
			opts.bootstrap.pub,
		]);
		assertEquals(prefix.length, BOOTSTRAP_PREFIX_LEN);
		const sec = buildBootstrapSecHeader(plaintext.length);
		assertEquals(sec.length, BOOTSTRAP_SEC_HEADER_LEN);
		const totalLen = HEADER_LEN + prefix.length + sec.length + ct.length +
			tagLen;
		const hdr = buildBootstrapFrameHeader(totalLen, sequence);
		const macInput = concatBytes([hdr, prefix, sec, ct]);
		return concatBytes([macInput, hmacTag(keys.macKey, macInput)]);
	}
	const totalLen = HEADER_LEN + ct.length + tagLen;
	const hdr = buildRegularFrameHeader(totalLen, sequence, plaintext.length);
	const macInput = concatBytes([hdr, ct]);
	return concatBytes([macInput, hmacTag(keys.macKey, macInput)]);
}

function buildControlPlain(opts: {
	bodyTag: number;
	bodyBytes: Uint8Array;
	msgId: number;
	sessId: Uint8Array;
	locNonce: bigint;
	cid: string;
	srcChanId: bigint;
	dstChanId?: bigint;
}): Uint8Array {
	const tranId = new Uint8Array(16);
	tranId.fill(opts.msgId & 0xff);
	return packPlanetMsg(
		{
			userId: "u-server",
			msgId: opts.msgId,
			sessId: opts.sessId,
			tranId,
			tranSeq: opts.msgId,
			locNonce: opts.locNonce,
			rmtNonce: 0n,
		},
		{
			kind: "cc",
			data: packPlanetCcMsg(
				{
					cid: opts.cid,
					srcChanId: opts.srcChanId,
					dstChanId: opts.dstChanId ?? 0n,
				},
				wrapCcMsg(opts.bodyTag, opts.bodyBytes),
			),
		},
	);
}

function buildMediaControlPlain(opts: {
	bodyTag: number;
	bodyBytes: Uint8Array;
	msgId: number;
	sessId: Uint8Array;
	locNonce: bigint;
	cid: string;
	srcChanId: bigint;
	dstChanId?: bigint;
}): Uint8Array {
	const tranId = new Uint8Array(16);
	tranId.fill(opts.msgId & 0xff);
	return packPlanetMsg(
		{
			userId: "u-server",
			msgId: opts.msgId,
			sessId: opts.sessId,
			tranId,
			tranSeq: opts.msgId,
			locNonce: opts.locNonce,
			rmtNonce: 0n,
		},
		{
			kind: "mc",
			data: packPlanetMcMsg(
				{
					cid: opts.cid,
					srcChanId: opts.srcChanId,
					dstChanId: opts.dstChanId ?? 0n,
				},
				wrapMcMsg(opts.bodyTag, opts.bodyBytes),
			),
		},
	);
}

function extractBootstrapClientPub(wire: Uint8Array): Uint8Array {
	return wire.subarray(
		HEADER_LEN + 2 + 16,
		HEADER_LEN + 2 + 16 + 33,
	);
}

function extractBootstrapClientLabel(wire: Uint8Array): number {
	return ((wire[HEADER_LEN] << 8) | wire[HEADER_LEN + 1]) & 0xffff;
}

function extractBootstrapClientSeed(wire: Uint8Array): Uint8Array {
	return new Uint8Array(wire.subarray(HEADER_LEN + 2, HEADER_LEN + 18));
}

function decryptRegularWire(
	keys: TransportKeys,
	wire: Uint8Array,
): Uint8Array | undefined {
	const tag = wire.subarray(wire.length - 16);
	const macInput = wire.subarray(0, wire.length - 16);
	const expected = hmacTag(keys.macKey, macInput);
	if (!tagEquals(tag, expected)) return undefined;
	const seq = ((wire[2] << 8) | wire[3]) & 0xffff;
	const ct = wire.subarray(HEADER_LEN, wire.length - 16);
	return aesCtrDecrypt(keys.encKey, buildPlanetCtrIv(keys.ctrBase, seq), ct);
}

function isRtpLike(wire: Uint8Array): boolean {
	return wire.length >= 12 && (wire[0] & 0xc0) === 0x80;
}

async function bindUdpServer(): Promise<Socket> {
	const server = createSocket("udp4");
	await new Promise<void>((resolve) =>
		server.bind({ address: "127.0.0.1", port: 0 }, () => resolve())
	);
	return server;
}

async function sendUdp(
	server: Socket,
	packet: Uint8Array,
	rinfo: RemoteInfo,
): Promise<void> {
	await new Promise<void>((resolve, reject) =>
		server.send(
			Buffer.from(packet),
			rinfo.port,
			rinfo.address,
			(err) => err ? reject(err) : resolve(),
		)
	);
}

function withTimeout<T>(
	promise: Promise<T>,
	timeoutMs: number,
	label: string,
): Promise<T> {
	return new Promise((resolve, reject) => {
		const timeout = setTimeout(
			() => reject(new Error(`${label} timeout`)),
			timeoutMs,
		);
		promise.then(
			(value) => {
				clearTimeout(timeout);
				resolve(value);
			},
			(err) => {
				clearTimeout(timeout);
				reject(err);
			},
		);
	});
}

// Synthetic relay fields: no account routes, captured packets, or keys.
function groupField(tag: number, value: number | Uint8Array): Uint8Array {
	return value instanceof Uint8Array
		? concatBytes([
			encodeVarint((tag << 3) | 2),
			encodeVarint(value.length),
			value,
		])
		: concatBytes([encodeVarint(tag << 3), encodeVarint(value)]);
}

function groupAnswer(invalidStream = false): Uint8Array {
	return concatBytes([
		...["A", "V", "D"].map((name, index) =>
			groupField(
				1,
				concatBytes([
					groupField(
						1,
						concatBytes([
							groupField(1, new TextEncoder().encode(name)),
							groupField(3, 1),
						]),
					),
					groupField(
						2,
						concatBytes([
							groupField(1, 96 + index),
							groupField(11, 1001 + index),
							groupField(61, invalidStream && index === 2 ? 0 : 2001 + index),
						]),
					),
				]),
			)
		),
		groupField(2, groupField(2, groupField(1, new Uint8Array(30).fill(7)))),
	]);
}

function groupRelay(responseBody: Uint8Array, afterProvisional = false) {
	const peer = generateEphemeralKeypair();
	const registrations: ReturnType<typeof decodePlanetMsg>[] = [];
	const media: Uint8Array[] = [];
	let receiveKeys: TransportKeys;
	const transport = new PlanetTransport({
		localMid: "u-local",
		timeoutMs: 30,
		groupDataSessionAfterProvisional: afterProvisional,
		wireSend(wire, endpoint) {
			if (endpoint.bootstrap) {
				const request = decodePlanetMsg(endpoint.plaintext);
				assertEquals(request.cc?.bodyTag, CC_MSG.PARTICIPATE_REQ);
				const clientPub = extractBootstrapClientPub(wire);
				const label = extractBootstrapClientLabel(wire);
				const seed = extractBootstrapClientSeed(wire);
				receiveKeys = deriveCallKeys({
					mpkey: clientPub,
					local: peer,
					bootstrapSeed: seed,
					sendLabel: label,
					recvLabel: label,
				}).recv;
				const replySeed = new Uint8Array(16).fill(3);
				const replyLabel = 2;
				const sendKeys = deriveCallKeys({
					mpkey: clientPub,
					local: peer,
					bootstrapSeed: replySeed,
					sendLabel: replyLabel,
					recvLabel: replyLabel,
				}).send;
				return buildServerWire(
					sendKeys,
					buildControlPlain({
						bodyTag: CC_MSG.PARTICIPATE_RSP,
						bodyBytes: responseBody,
						msgId: 1,
						sessId: new Uint8Array(16).fill(4),
						locNonce: 9n,
						cid: request.cc!.hdr!.cid!,
						srcChanId: 77n,
					}),
					1,
					{
						bootstrap: {
							label: replyLabel,
							seed: replySeed,
							pub: peer.publicKey,
						},
					},
				);
			}
			if (isRtpLike(wire)) {
				media.push(new Uint8Array(wire));
				return;
			}
			const plain = decryptRegularWire(receiveKeys, wire);
			assert(plain, "outbound control authenticates");
			// Pinhole probes are raw transport payloads rather than protobuf.
			if (plain.length === 519 || plain.length === 10) return;
			const msg = decodePlanetMsg(plain);
			if (msg.mc?.bodyTag === MC_MSG.DATA_REQ) registrations.push(msg);
		},
	});
	const oneToOneRoute = makeRoute(peer);
	assert("toMid" in oneToOneRoute);
	const { toMid: _toMid, ...baseRoute } = oneToOneRoute;
	// Only route fields consumed by the transport are needed by this fake relay.
	const route = {
		...baseRoute,
		token: "synthetic-group-token",
	} as unknown as CallRouteLike;
	return { transport, route, registrations, media };
}

Deno.test("group final answer binds registration and AUDIO/DATA wire SSRCs", async () => {
	const relay = groupRelay(
		concatBytes([
			groupField(1, 0),
			groupField(6, groupAnswer()),
			groupField(7, 88),
		]),
	);
	const { transport } = relay;
	try {
		await transport.connect({ route: relay.route });
		const joined = await transport.joinGroupDetailed({ roomId: "c-room" });
		assert(joined.mediaReady);
		assertEquals(relay.registrations.length, 1);
		const registration = relay.registrations[0].mc!;
		assertEquals(registration.hdr?.dstChanId, 88n); // media, not CC channel 77
		const data = decodeMcDataReq(registration.bodyBytes!).data!;
		const specLength = (data[4] << 8) | data[5];
		const fields = decodeFields(data.subarray(8, 8 + specLength));
		const sources = (tag: number) =>
			fields.filter((f) => f.tag === tag).map((f) => {
				assert(f.value instanceof Uint8Array);
				return Number(decodeFields(f.value).find((v) => v.tag === 1)?.value);
			});
		assertEquals(sources(1), [1001, 1002, 1003]);
		assertEquals(sources(6), [2001, 2002]);
		const local = transport.localMediaOffer!;
		const audioContext = await deriveSrtpContext(
			derivePlanetMediaStreamKeying(local.material.mediaSecret, "AUDIO"),
		);
		const dataContext = await deriveSrtpContext(
			derivePlanetMediaStreamKeying(local.material.mediaSecret, "DATA"),
		);
		const [payload] = packetizeNativeGroupOpusPairs([
			new Uint8Array([0xf8, 1]),
			new Uint8Array([0xf8, 2]),
		], { inputPrefixBytes: 0, frameActivity: [true, true] });
		for (let i = 0; i < 6; i++) {
			await transport.send(payload, { timestampStep: 1920 });
		}
		const audio = relay.media.filter((wire) => (wire[1] & 0x7f) === 96);
		assertEquals(audio.length, 6);
		for (const [i, wire] of audio.entries()) {
			const packet = parseRtp(await srtpDecrypt(audioContext, wire));
			assertEquals(packet.ssrc, 2001);
			assertEquals(packet.timestamp, 960 + i * 1920);
			assertEquals(packet.payload, payload);
		}
		const dataPackets = relay.media.filter((wire) => (wire[1] & 0x7f) === 101);
		assertEquals(dataPackets.length, 1);
		assertEquals(
			parseRtp(await srtpDecrypt(dataContext, dataPackets[0])).ssrc,
			2003,
		);
	} finally {
		await transport.close();
	}
});

Deno.test("group rejects failed/incomplete answers without registering or sending media", async (t) => {
	const answer = groupField(6, groupAnswer());
	const channel = groupField(7, 88);
	for (
		const [name, fields, error] of [
			[
				"failure",
				[groupField(1, 1), answer, channel],
				"group participation rejected or incomplete",
			],
			[
				"release",
				[groupField(1, 0), groupField(2, 1), answer, channel],
				"group participation rejected or incomplete",
			],
			[
				"missing result",
				[answer, channel],
				"group participation rejected or incomplete",
			],
			[
				"missing media channel",
				[groupField(1, 0), answer],
				"group participation rejected or incomplete",
			],
			[
				"missing answer",
				[groupField(1, 0), channel],
				"group answer stream IDs missing",
			],
			["invalid DATA source", [
				groupField(1, 0),
				groupField(6, groupAnswer(true)),
				channel,
			], "group answer stream IDs missing"],
			["provisional only", [channel], "PLANET reply timeout"],
		] as const
	) {
		await t.step(name, async () => {
			const relay = groupRelay(concatBytes([...fields]), true);
			try {
				await relay.transport.connect({ route: relay.route });
				await assertRejects(
					() => relay.transport.joinGroupDetailed({ roomId: "c-room" }),
					Error,
					error,
				);
				assertEquals(relay.registrations.length, 0);
				assertEquals(relay.media.length, 0);
			} finally {
				await relay.transport.close();
			}
		});
	}
});

Deno.test("PlanetTransport.close does not send REL before SETUP/INVITE", async () => {
	let sends = 0;
	const transport = new PlanetTransport({
		localMid: "u-local",
		wireSend() {
			sends++;
		},
	});

	await transport.connect({ route: makeRoute() });
	await transport.close();

	assertEquals(sends, 0);
});

Deno.test("PlanetTransport retains generated media offer material for SRTP setup", async () => {
	let sends = 0;
	let setupMsgId = 0;
	const transport = new PlanetTransport({
		localMid: "u-local",
		timeoutMs: 1,
		wireSend(_packet, endpoint) {
			sends++;
			if (endpoint.bootstrap) {
				setupMsgId = decodePlanetMsg(endpoint.plaintext).hdr?.msgId ?? 0;
			}
		},
	});

	await transport.connect({ route: makeRoute() });
	try {
		await transport.invite({ to: "u-peer" });
	} catch (e) {
		assert(e instanceof Error);
		assert(e.message.includes("PLANET reply timeout"));
	}

	const media = transport.localMediaOffer;
	assert(media);
	assertEquals(sends, 1);
	assertEquals(setupMsgId, 0x2141);
	assertEquals(media.keypair.publicKey.length, 33);
	assertEquals(media.keypair.privateKey.length, 32);
	assertEquals(media.material.mediaPubKey.length, 33);
	assertEquals(media.material.mediaNonce.length, 16);
	assertEquals(media.material.mediaSecret.length, 30);
	assertEquals(media.offer.length, 311);
});

Deno.test("PlanetTransport learns RTP source and sends decryptable SRTP media", async () => {
	const routePeer = generateEphemeralKeypair();
	const server = await bindUdpServer();
	const mediaServer = await bindUdpServer();
	const addr = server.address();
	const mediaAddr = mediaServer.address();
	const port = typeof addr === "string" ? 0 : addr.port;
	const mediaPort = typeof mediaAddr === "string" ? 0 : mediaAddr.port;
	const route = makeRoute(routePeer, port);
	const transport = new PlanetTransport({
		localMid: "u-local",
		timeoutMs: 1000,
		keepaliveIntervalMs: 20,
	});

	const peerMedia = generateEphemeralKeypair();
	const peerMaterial: PlanetSetupOfferMaterial = {
		mediaPubKey: peerMedia.publicKey,
		mediaKeyId: 0x33445566,
		mediaNonce: new Uint8Array(16).fill(0x23),
		mediaSecret: new Uint8Array(30).fill(0x42),
	};
	const sessId = new Uint8Array(16).fill(0x7a);
	const replySeed = new Uint8Array(16).fill(0x34);
	const replyLabel = 0x4567;
	const cid = "test-call";
	const setupRspPlain = buildControlPlain({
		bodyTag: CC_MSG.SETUP_RSP,
		bodyBytes: packCcSetupRsp({
			result: 0,
			aliveRptInterval: 5,
			noAnsToSec: 30,
		}),
		msgId: 1,
		sessId,
		locNonce: 0x123456n,
		cid,
		srcChanId: 0x1001n,
	});
	const connReqPlain = buildControlPlain({
		bodyTag: CC_MSG.CONN_REQ,
		bodyBytes: packCcConnReq({
			answer: packNativeSetupOffer(peerMaterial),
			mChanId: 0x2002n,
			netType: 1,
			unavailToSec: 120,
			oCapas: [1, 2, 3],
			features: [],
		}),
		msgId: 2,
		sessId,
		locNonce: 0x123456n,
		cid,
		srcChanId: 0x1001n,
		dstChanId: 0x2002n,
	});
	const infoReqPlain = buildControlPlain({
		bodyTag: CC_MSG.INFO_REQ,
		bodyBytes: packCcInfoReq({
			bodyType: "profile",
			body: new Uint8Array([1, 2, 3]),
			targets: ["u-local"],
			source: "u-peer",
			sourceSvcId: "freecall.audio",
			tgtUe: [],
		}),
		msgId: 3,
		sessId,
		locNonce: 0x123456n,
		cid,
		srcChanId: 0x1001n,
		dstChanId: 0x2002n,
	});
	const mcDataReqPlain = buildMediaControlPlain({
		bodyTag: MC_MSG.DATA_REQ,
		bodyBytes: packMcDataReq({
			srcType: 0,
			dstType: 0,
			dispatchId: 2,
			data: new Uint8Array([0]),
		}),
		msgId: 0x3189,
		sessId,
		locNonce: 0x123456n,
		cid,
		srcChanId: 0x2002n,
		dstChanId: 0x3003n,
	});

	let setupHandled = false;
	let clientRinfo: RemoteInfo | undefined;
	let serverRecvKeys: TransportKeys | undefined;
	let serverMessages = 0;
	let serverError: unknown;
	let connReqWireForRetry: Uint8Array | undefined;
	let connRspCount = 0;
	const pinholePlainLengths: number[] = [];
	let resolveMedia!: (packet: Uint8Array) => void;
	let resolvePinholeReport!: () => void;
	let resolveSecondConnRsp!: () => void;
	let resolveInfoReq!: (bodyTag: number) => void;
	let resolveInfoRsp!: (bodyTag: number) => void;
	let resolveMcDataRsp!: (
		rsp: { dispatchId: number; dataLength: number; bodyLength: number },
	) => void;
	let resolveRelReq!: (req: { bodyTag: number; dstChanId: string }) => void;
	let resolveKeepalive!: (bodyTag: number) => void;
	const mediaWire = new Promise<Uint8Array>((resolve) => {
		resolveMedia = resolve;
	});
	const pinholeReport = new Promise<void>((resolve) => {
		resolvePinholeReport = resolve;
	});
	const secondConnRsp = new Promise<void>((resolve) => {
		resolveSecondConnRsp = resolve;
	});
	const infoReq = new Promise<number>((resolve) => {
		resolveInfoReq = resolve;
	});
	const infoRsp = new Promise<number>((resolve) => {
		resolveInfoRsp = resolve;
	});
	const mcDataRsp = new Promise<
		{ dispatchId: number; dataLength: number; bodyLength: number }
	>((resolve) => {
		resolveMcDataRsp = resolve;
	});
	const relReq = new Promise<{ bodyTag: number; dstChanId: string }>(
		(resolve) => {
			resolveRelReq = resolve;
		},
	);
	const keepalive = new Promise<number>((resolve) => {
		resolveKeepalive = resolve;
	});
	mediaServer.on("message", (buf: Buffer) => {
		resolveMedia(new Uint8Array(buf));
	});
	server.on("message", (buf: Buffer, rinfo: RemoteInfo) => {
		try {
			clientRinfo = rinfo;
			serverMessages++;
			const wire = new Uint8Array(buf);
			if (isRtpLike(wire)) {
				serverError = new Error("media packet was sent to signaling socket");
				return;
			}
			if (setupHandled && serverRecvKeys) {
				const plain = decryptRegularWire(serverRecvKeys, wire);
				if (!plain) return;
				if (plain.length === 519 || plain.length === 10) {
					pinholePlainLengths.push(plain.length);
					if (plain.length === 10) resolvePinholeReport();
					return;
				}
				const msg = decodePlanetMsg(plain);
				if (msg.cc?.bodyTag === CC_MSG.CONN_RSP) {
					connRspCount++;
					if (connRspCount >= 2) resolveSecondConnRsp();
				}
				if (msg.cc?.bodyTag === CC_MSG.INFO_REQ) {
					resolveInfoReq(msg.cc.bodyTag);
				}
				if (msg.cc?.bodyTag === CC_MSG.INFO_RSP) {
					resolveInfoRsp(msg.cc.bodyTag);
				}
				if (msg.cc?.bodyTag === CC_MSG.REL_REQ) {
					resolveRelReq({
						bodyTag: msg.cc.bodyTag,
						dstChanId: String(msg.cc.hdr?.dstChanId ?? 0n),
					});
				}
				if (msg.mc?.bodyTag === MC_MSG.DATA_RSP && msg.mc.bodyBytes) {
					const rsp = decodeMcDataRsp(msg.mc.bodyBytes);
					const data = rsp.data ?? new Uint8Array();
					resolveMcDataRsp({
						dispatchId: rsp.dispatchId ?? 0,
						dataLength: data.length,
						bodyLength: data.length >= 6 ? ((data[4] << 8) | data[5]) : 0,
					});
				}
				if (msg.scBytes) {
					resolveKeepalive(decodeFields(msg.scBytes)[0]?.tag ?? 0);
				}
				return;
			}
			if (setupHandled) return;
			setupHandled = true;
			const clientPub = extractBootstrapClientPub(wire);
			const clientLabel = extractBootstrapClientLabel(wire);
			const clientSeed = extractBootstrapClientSeed(wire);
			const serverKeys = deriveCallKeys({
				mpkey: clientPub,
				local: routePeer,
				bootstrapSeed: replySeed,
				sendLabel: replyLabel,
				recvLabel: replyLabel,
			}).send;
			serverRecvKeys = deriveCallKeys({
				mpkey: clientPub,
				local: routePeer,
				bootstrapSeed: clientSeed,
				sendLabel: clientLabel,
				recvLabel: clientLabel,
			}).recv;
			const setupRspWire = buildServerWire(
				serverKeys,
				setupRspPlain,
				0x5101,
				{
					bootstrap: {
						label: replyLabel,
						seed: replySeed,
						pub: routePeer.publicKey,
					},
				},
			);
			const connReqWire = buildServerWire(serverKeys, connReqPlain, 0x5102);
			connReqWireForRetry = connReqWire;
			const infoReqWire = buildServerWire(serverKeys, infoReqPlain, 0x5103);
			const mcDataReqWire = buildServerWire(serverKeys, mcDataReqPlain, 0x5104);
			void sendUdp(server, setupRspWire, rinfo).then(() =>
				new Promise((resolve) => setTimeout(resolve, 5))
			).then(() => sendUdp(server, connReqWire, rinfo)).then(() =>
				new Promise((resolve) => setTimeout(resolve, 5))
			).then(() => sendUdp(server, infoReqWire, rinfo)).then(() =>
				new Promise((resolve) => setTimeout(resolve, 5))
			).then(() => sendUdp(server, mcDataReqWire, rinfo));
		} catch (e) {
			serverError = e;
		}
	});

	let transportClosed = false;
	try {
		await transport.connect({ route });
		const invite = await transport.inviteDetailed({ to: "u-peer" }).catch(
			(e) => {
				throw new Error(
					`invite failed after ${serverMessages} server messages: ${
						serverError instanceof Error
							? serverError.message
							: String(serverError ?? e)
					}`,
				);
			},
		);
		assertEquals(invite.setupRsp?.result, 0);
		const answer = await transport.waitForAnswerDetailed({ timeoutMs: 1000 });
		assert(answer.mediaReady);
		assertEquals(answer.connRspSent, true);
		await withTimeout(pinholeReport, 1000, "pinhole_report");
		assertEquals(pinholePlainLengths.filter((len) => len === 519).length, 16);
		assertEquals(pinholePlainLengths.filter((len) => len === 10).length, 1);
		assertEquals(await withTimeout(infoReq, 1000, "info_req"), CC_MSG.INFO_REQ);
		assertEquals(await withTimeout(infoRsp, 1000, "info_rsp"), CC_MSG.INFO_RSP);
		assertEquals(await withTimeout(mcDataRsp, 1000, "mc_data_rsp"), {
			dispatchId: 2,
			dataLength: 148,
			bodyLength: 139,
		});
		assertEquals(await withTimeout(keepalive, 1000, "keepalive"), 1);
		assert(clientRinfo);
		assert(connReqWireForRetry);
		await sendUdp(server, connReqWireForRetry, clientRinfo);
		await withTimeout(secondConnRsp, 1000, "duplicate_conn_rsp");
		await sendUdp(
			mediaServer,
			new Uint8Array([0x80, 0x60, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]),
			clientRinfo,
		);
		await new Promise((resolve) => setTimeout(resolve, 10));

		const localMedia = transport.localMediaOffer;
		assert(localMedia);
		const peerKeys = derivePlanetMediaKeys({
			local: {
				privateKey: peerMedia.privateKey,
				publicKey: peerMaterial.mediaPubKey,
				mediaKeyId: peerMaterial.mediaKeyId,
				mediaNonce: peerMaterial.mediaNonce,
			},
			peer: {
				publicKey: localMedia.material.mediaPubKey,
				mediaKeyId: localMedia.material.mediaKeyId,
				mediaNonce: localMedia.material.mediaNonce,
			},
		});
		const peerRecv = await deriveSrtpContext(peerKeys.recvKeying);
		const opus = new Uint8Array([0xf8, 0xff, 0xfe]);
		await transport.send(opus);
		const receivedWire = await withTimeout(mediaWire, 1000, "media");
		const rtp = await srtpDecrypt(peerRecv, receivedWire);
		assertEquals(parseRtp(rtp).payload, opus);
		await transport.close();
		transportClosed = true;
		assertEquals(await withTimeout(relReq, 1000, "rel_req"), {
			bodyTag: CC_MSG.REL_REQ,
			dstChanId: String(0x1001n),
		});
	} finally {
		if (!transportClosed) await transport.close();
		await new Promise<void>((resolve) => server.close(() => resolve()));
		await new Promise<void>((resolve) => mediaServer.close(() => resolve()));
	}
});
