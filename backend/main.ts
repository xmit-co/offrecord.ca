import { ServerWebSocket } from "bun";

type Message = [Date, any];

const channels: Map<string, Channel> = new Map();

function attemptSend(socket: ServerWebSocket<{ url: string }>, data: string) {
  socket.send(data);
}

class Channel {
  topic: string;
  listeners: Set<ServerWebSocket<{ url: string }>> = new Set();
  messages: Message[] = [];

  constructor(topic: string) {
    this.topic = topic;
  }

  post(payload: any) {
    let msg = [new Date(), payload];
    this.messages.push(msg);
    if (this.messages.length > 10) this.messages.shift();
    const json = JSON.stringify([msg]);
    this.listeners.forEach((l) => attemptSend(l, json));
  }

  clear() {
    this.messages = [];
    this.listeners.forEach((l) => attemptSend(l, JSON.stringify({ cl: true })));
  }

  onOpen(socket: ServerWebSocket<{ url: string }>) {
    this.listeners.add(socket);
    attemptSend(socket, JSON.stringify(this.messages));
    this._sendCounts();
  }

  onClose(socket: ServerWebSocket<{ url: string }>) {
    this.listeners.delete(socket);
    if (this.listeners.size > 0) this._sendCounts();
  }

  _sendCounts() {
    const json = JSON.stringify({ ct: this.listeners.size });
    this.listeners.forEach((l) => attemptSend(l, json));
  }
}

setInterval(() => {
  channels.forEach((channel) => channel._sendCounts());
}, 15000);

setInterval(() => {
  const oneMinuteAgo = new Date(Date.now() - 60000);
  let messageCount = 0;
  channels.forEach((channel) => {
    messageCount += channel.messages.filter((msg) => msg[0] > oneMinuteAgo).length;
  });
  console.log(`Messages in last minute: ${messageCount}`);
}, 60000);

Bun.serve({
  port: 8084,
  fetch(req, server) {
    const url = new URL(req.url).pathname;
    if (server.upgrade(req, { data: { url } })) {
      return;
    }
    return new Response("Upgrade failed", { status: 500 });
  },
  websocket: {
    open(ws) {
      const url = ws.data.url;
      const channel = channels.get(url) || new Channel(url);
      channels.set(url, channel);
      channel.onOpen(ws);
    },
    message(ws, message) {
      const url = ws.data.url;
      const channel = channels.get(url);
      if (!channel) return;

      if (typeof message === "string") {
        if (message.length > 1048576) {
          ws.close(1009, "Message too long");
          return;
        }
        try {
          const json = JSON.parse(message);
          if (json.clear) channel.clear();
          else channel.post(json);
        } catch (err: any) {
          ws.close(1007, "Failure: " + err.message);
        }
      } else {
        if (message.byteLength > 1048576) {
          ws.close(1009, "Message too long");
          return;
        }
        const b64 = btoa(String.fromCharCode(...new Uint8Array(message as ArrayBuffer)));
        channel.post(b64);
      }
    },
    close(ws) {
      const url = ws.data.url;
      const channel = channels.get(url);
      if (channel) channel.onClose(ws);
    },
  },
});
