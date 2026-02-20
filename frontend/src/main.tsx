import "preact/debug";

import { render } from "preact";
import { signal } from "@preact/signals";
import "./index.css";
import Sockette from "sockette";
import * as nacl from "tweetnacl";
import { decode, encode } from "cbor-x";
import { Renderer, parse } from "marked";
import DOMPurify from "dompurify";
import { useEffect, useRef } from "preact/hooks";
import QRCode from "qrcode";

if (location.href.indexOf("#") === -1) {
  location.hash = "lobby";
}

const renderer = new Renderer();
renderer.image = ({ href, title, text }) => {
  if (href.startsWith("data:image/")) {
    if (title) return `<img src="${href}" alt="${text}" title="${title}" />`;
    else return `<img src="${href}" alt="${text}" />`;
  }
  if (title) {
    return `![${text}](${href} "${title}")`;
  }
  return `![${text}](${href})`;
};

// WebRTC constants
const ICE_SERVERS: RTCConfiguration = {
  iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
};
const peerId = Math.random().toString(36).substring(2);
const peerConnections = new Map<string, RTCPeerConnection>();
let localStream: MediaStream | null = null;

interface State {
  pass?: string;
  boxKP?: nacl.BoxKeyPair;
  chan?: string;
  count?: number;
  sock?: Sockette;
  msgs: [string, string][];
  pending: [string, string];
  zoomCanvas: boolean;
  inCall: boolean;
  remoteStreams: Record<string, MediaStream>;
  audioEnabled: boolean;
  videoEnabled: boolean;
}

const state = signal<State>({
  msgs: [],
  pending: [
    localStorage.getItem("nick") ||
      ([
        localStorage.setItem("nick", Math.random().toString(36).substring(4)),
        localStorage.getItem("nick"),
      ][1] as string),
    "",
  ],
  zoomCanvas: false,
  inCall: false,
  remoteStreams: {},
  audioEnabled: true,
  videoEnabled: true,
});

addEventListener("hashchange", reconnect);
reconnect().catch(console.error);

function randomChannelName() {
  return btoa(String.fromCharCode(...nacl.randomBytes(64))).replace(/=/g, "");
}

// Signaling helpers

function encryptSignal(data: any): string {
  const s = state.value;
  if (!s.boxKP) throw new Error("No key pair");
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const payload = nacl.box(
    new TextEncoder().encode(JSON.stringify(data)),
    nonce,
    s.boxKP.publicKey,
    s.boxKP.secretKey
  );
  return btoa(String.fromCharCode(...encode([nonce, payload])));
}

function decryptSignal(b64: string): any {
  const s = state.value;
  if (!s.boxKP) return null;
  try {
    const [nonce, payload] = decode(
      Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
    );
    const raw = nacl.box.open(
      payload,
      nonce,
      s.boxKP.publicKey,
      s.boxKP.secretKey
    );
    if (!raw) return null;
    return JSON.parse(new TextDecoder().decode(raw));
  } catch {
    return null;
  }
}

function sendSignal(data: any) {
  state.value.sock?.json({ sig: encryptSignal(data) });
}

// Peer connection management

function createPeerConnection(remotePid: string): RTCPeerConnection {
  const pc = new RTCPeerConnection(ICE_SERVERS);
  peerConnections.set(remotePid, pc);

  if (localStream) {
    localStream
      .getTracks()
      .forEach((track) => pc.addTrack(track, localStream!));
  }

  pc.ontrack = (evt) => {
    const stream = evt.streams[0] || new MediaStream([evt.track]);
    state.value = {
      ...state.value,
      remoteStreams: { ...state.value.remoteStreams, [remotePid]: stream },
    };
  };

  pc.onicecandidate = (evt) => {
    if (evt.candidate) {
      sendSignal({
        t: "ice",
        from: peerId,
        to: remotePid,
        candidate: evt.candidate,
      });
    }
  };

  let disconnectTimer: ReturnType<typeof setTimeout> | null = null;
  pc.oniceconnectionstatechange = () => {
    if (pc.iceConnectionState === "disconnected") {
      disconnectTimer = setTimeout(() => removePeer(remotePid), 5000);
    } else if (
      pc.iceConnectionState === "connected" ||
      pc.iceConnectionState === "completed"
    ) {
      if (disconnectTimer) {
        clearTimeout(disconnectTimer);
        disconnectTimer = null;
      }
    } else if (
      pc.iceConnectionState === "failed" ||
      pc.iceConnectionState === "closed"
    ) {
      if (disconnectTimer) clearTimeout(disconnectTimer);
      removePeer(remotePid);
    }
  };

  return pc;
}

function removePeer(remotePid: string) {
  const pc = peerConnections.get(remotePid);
  if (pc) {
    pc.close();
    peerConnections.delete(remotePid);
  }
  const { [remotePid]: _, ...rest } = state.value.remoteStreams;
  state.value = { ...state.value, remoteStreams: rest };
}

function teardownCall() {
  peerConnections.forEach((pc) => pc.close());
  peerConnections.clear();
  if (localStream) {
    localStream.getTracks().forEach((t) => t.stop());
    localStream = null;
  }
  state.value = {
    ...state.value,
    inCall: false,
    remoteStreams: {},
    audioEnabled: true,
    videoEnabled: true,
  };
}

// Call actions

async function joinCall() {
  try {
    localStream = await navigator.mediaDevices.getUserMedia({
      audio: true,
      video: true,
    });
  } catch {
    try {
      localStream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: false,
      });
      state.value = { ...state.value, videoEnabled: false };
    } catch {
      alert("Could not access microphone or camera.");
      return;
    }
  }
  state.value = { ...state.value, inCall: true };
  sendSignal({ t: "join", from: peerId });
}

function leaveCall() {
  sendSignal({ t: "leave", from: peerId });
  teardownCall();
}

function toggleAudio() {
  if (!localStream) return;
  const enabled = !state.value.audioEnabled;
  localStream.getAudioTracks().forEach((t) => (t.enabled = enabled));
  state.value = { ...state.value, audioEnabled: enabled };
}

function toggleVideo() {
  if (!localStream) return;
  const enabled = !state.value.videoEnabled;
  localStream.getVideoTracks().forEach((t) => (t.enabled = enabled));
  state.value = { ...state.value, videoEnabled: enabled };
}

// Signal handler (perfect negotiation: lower peerId = polite)

async function handleSignal(sig: any) {
  const { t, from, to } = sig;

  if (from === peerId) return;
  if (to && to !== peerId) return;

  switch (t) {
    case "join": {
      if (!state.value.inCall) return;
      if (peerConnections.has(from)) removePeer(from);
      const pc = createPeerConnection(from);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      sendSignal({
        t: "offer",
        from: peerId,
        to: from,
        sdp: pc.localDescription,
      });
      break;
    }
    case "leave": {
      removePeer(from);
      break;
    }
    case "offer": {
      let pc = peerConnections.get(from);
      if (!pc) {
        if (!state.value.inCall) return;
        pc = createPeerConnection(from);
      }
      const polite = peerId < from;
      const collision = pc.signalingState !== "stable";
      if (!polite && collision) return;
      await pc.setRemoteDescription(new RTCSessionDescription(sig.sdp));
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      sendSignal({
        t: "answer",
        from: peerId,
        to: from,
        sdp: pc.localDescription,
      });
      break;
    }
    case "answer": {
      const pc = peerConnections.get(from);
      if (!pc) return;
      await pc.setRemoteDescription(new RTCSessionDescription(sig.sdp));
      break;
    }
    case "ice": {
      const pc = peerConnections.get(from);
      if (!pc) return;
      try {
        await pc.addIceCandidate(new RTCIceCandidate(sig.candidate));
      } catch {}
      break;
    }
  }
}

// Send leave signal on tab close
addEventListener("beforeunload", () => {
  if (state.value.inCall) {
    sendSignal({ t: "leave", from: peerId });
  }
});

async function reconnect() {
  const pass = location.hash.slice(1);
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(pass),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: new TextEncoder().encode("offrecord.ca"),
      iterations: 100000,
    },
    key,
    256
  );
  const seed = new Uint8Array(bits);
  const boxKP = nacl.box.keyPair.fromSecretKey(seed);
  const chan = btoa(String.fromCharCode(...boxKP.publicKey));

  const previous = state.value.chan;
  if (previous !== chan) {
    if (state.value.inCall) leaveCall();
    state.value.sock?.close();
    const sock = new Sockette(`wss://${window.location.host}/ws/${chan}`, {
      onreconnect: () => {
        teardownCall();
        state.value = { ...state.value, msgs: [], count: undefined };
      },
      onmessage: (evt) => {
        const payload = JSON.parse(evt.data);
        if (payload.cl) {
          state.value = { ...state.value, msgs: [] };
        } else if (payload.ct) {
          state.value = { ...state.value, count: payload.ct };
        } else if (payload.sig !== undefined) {
          const sig = decryptSignal(payload.sig);
          if (sig) handleSignal(sig);
        } else {
          state.value = {
            ...state.value,
            msgs: [...state.value.msgs, ...payload],
          };
        }
      },
    });
    state.value = {
      ...state.value,
      pass,
      boxKP,
      chan,
      sock,
      msgs: [],
      count: undefined,
    };
  }
}

function Video({
  stream,
  muted,
}: {
  stream: MediaStream;
  muted?: boolean;
}) {
  const ref = useRef<HTMLVideoElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.srcObject = stream;
  }, [stream]);
  return <video ref={ref} autoPlay playsInline muted={muted} />;
}

const App = () => {
  const s = state.value;
  const qr = useRef<HTMLCanvasElement>(null);
  const msg = useRef<HTMLTextAreaElement>(null);

  // Load QR into canvas when ref not undefined
  useEffect(() => {
    if (qr)
      QRCode.toCanvas(qr.current, location.href, {
        errorCorrectionLevel: "L",
        scale: s.zoomCanvas ? 8 : 1,
      });
  }, [qr, s.zoomCanvas, location.href]);

  useEffect(() => {
    if (window.self === window.top) msg.current?.focus();
  }, [msg]);

  const messageView = s.msgs.map((msg) => {
    if (!s.boxKP) return <></>;
    const [nonce, payload] = decode(
      Uint8Array.from(atob(msg[1]), (c) => c.charCodeAt(0))
    );
    const raw = nacl.box.open(
      payload,
      nonce,
      s.boxKP.publicKey,
      s.boxKP.secretKey
    );
    if (raw === null) {
      return (
        <>
          <dt>{new Date(msg[0]).toLocaleString()}</dt>
          <dd>
            <em>bad message</em>
          </dd>
        </>
      );
    }
    let json = JSON.parse(new TextDecoder().decode(raw));
    return (
      <>
        <dt>
          {new Date(msg[0]).toLocaleString()} <b>{json[0]}:</b>
        </dt>
        <dd
          dangerouslySetInnerHTML={{
            __html: DOMPurify.sanitize(
              parse(json[1], {
                async: false,
                pedantic: false,
                gfm: true,
                breaks: true,
                renderer,
              })
            ),
          }}
        />
      </>
    );
  });

  return (
    <>
      <header>
        <h1>
          Channel{" "}
          <input
            id="channel"
            type="text"
            value={s.pass}
            onInput={async (evt) => {
              location.hash = `#${(evt.target as HTMLInputElement).value}`;
              await reconnect();
            }}
          />
        </h1>
        <p>
          <button
            onClick={() => {
              navigator
                .share({
                  text: "Join my off-the-record chat",
                  url: location.href,
                })
                .catch(console.error);
            }}
          >
            share
          </button>
          <button onClick={() => state.value.sock?.json({ clear: true })}>
            wipe
          </button>
          <button onClick={() => (location.hash = randomChannelName())}>
            random
          </button>
          <button onClick={() => (location.hash = "#lobby")}>lobby</button>
          {s.inCall ? (
            <button onClick={leaveCall}>hang up</button>
          ) : (
            <button onClick={joinCall}>call</button>
          )}
        </p>
        {s.count !== undefined && <p id="count">{s.count} online</p>}
        <canvas
          id="qr"
          ref={qr}
          onClick={() => {
            state.value = { ...state.value, zoomCanvas: !s.zoomCanvas };
          }}
        />
      </header>
      {s.inCall && (
        <section id="call">
          <div id="call-controls">
            <button onClick={toggleAudio}>
              {s.audioEnabled ? "mute" : "unmute"}
            </button>
            <button onClick={toggleVideo}>
              {s.videoEnabled ? "cam off" : "cam on"}
            </button>
          </div>
          <div
            id="call-videos"
            style={{
              "--video-cols": Math.ceil(
                Math.sqrt(
                  (localStream ? 1 : 0) + Object.keys(s.remoteStreams).length
                )
              ),
            } as any}
          >
            {localStream && s.videoEnabled && (
              <Video stream={localStream} muted />
            )}
            {Object.entries(s.remoteStreams).map(([pid, stream]) => (
              <Video key={pid} stream={stream} />
            ))}
          </div>
        </section>
      )}
      <main>
        <dl>{messageView}</dl>
        <article>
          <p>
            Select a channel name above; it is only visible to its participants,
            and used as the encryption key for every message. Nobody can read
            messages without it.
          </p>
          <p>
            At most 10 timestamped encrypted messages are kept on the server. No
            IP or identifiable information, not even the nickname, are kept in
            clear.
          </p>
          <p>
            Anybody can wipe channels whenever they'd like. Server restarts wipe
            everything as history is only in-memory.
          </p>
          <p>
            You do not have to trust me and can run your own instance if you
            prefer.{" "}
            <a href="https://github.com/pcarrier/offrecord.ca" target="_blank">
              Sources.
            </a>
          </p>
        </article>
      </main>
      <footer>
        <form
          onSubmit={(evt) => {
            if (!s.boxKP || !s.pending[0] || !s.pending[1]) {
              return;
            }
            const nonce = nacl.randomBytes(nacl.box.nonceLength);
            const payload = nacl.box(
              new TextEncoder().encode(JSON.stringify(s.pending)),
              nonce,
              s.boxKP.publicKey,
              s.boxKP.secretKey
            );
            state.value.sock?.send(encode([nonce, payload]));
            state.value = {
              ...state.value,
              pending: [state.value.pending[0], ""],
            };
            evt.preventDefault();
            document.getElementById("msg")?.focus();
          }}
        >
          <input
            id="nick"
            type="text"
            value={s.pending[0]}
            onInput={(evt) => {
              let nick = (evt.target as HTMLInputElement).value;
              localStorage.setItem("nick", nick);
              state.value = {
                ...state.value,
                pending: [nick, s.pending[1]],
              };
            }}
          />
          <textarea
            id="msg"
            ref={msg}
            value={s.pending[1]}
            onInput={(evt) => {
              const tgt = evt.target as HTMLTextAreaElement;
              state.value = {
                ...state.value,
                pending: [s.pending[0], tgt.value],
              };
            }}
            onKeyDown={(evt) => {
              if (
                evt.key === "Enter" &&
                (evt.shiftKey || evt.ctrlKey || evt.metaKey)
              ) {
                evt.preventDefault();
                const tgt = evt.target as HTMLTextAreaElement;
                tgt.form?.requestSubmit();
              }
            }}
            style={s.pending[1].split("\n").length > 1 ? { height: "5em" } : {}}
          />{" "}
          <input type="submit" value="send" />
        </form>
      </footer>
    </>
  );
};

render(<App />, document.getElementById("app")!);
