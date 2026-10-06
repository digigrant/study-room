// A scripted OpenAI-compatible chat-completions server for hermetic tests.
// Pi's `openai` provider is pointed at it through models.json, so no real
// provider, credential or network is involved. Every request is logged so
// tests can assert what each Pi process (teacher or researcher) sent.

import * as http from "node:http";
import type { AddressInfo } from "node:net";

export interface LoggedRequest {
  at: number;
  model: string;
  auth: string | undefined;
  tools: string[];
  system: string;
  messages: Array<{ role: string; text: string }>;
  last: { role: string; text: string };
}

export type Reply =
  | { text: string; delayMs?: number }
  | { tool: { name: string; args: Record<string, unknown> } }
  | { hang: true }
  | { status: number };

export type Script = (req: LoggedRequest) => Reply;

function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.map((p: any) => (typeof p === "string" ? p : p?.text ?? "")).join("");
  return "";
}

export class FakeProvider {
  readonly log: LoggedRequest[] = [];
  private server: http.Server | null = null;
  private readonly scripts: Record<string, Script>;
  private open = new Set<http.ServerResponse>();
  port = 0;

  constructor(scripts: Record<string, Script>) {
    this.scripts = scripts;
  }

  async start(): Promise<number> {
    this.server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => this.handle(body, req, res));
    });
    await new Promise<void>((resolve) => this.server!.listen(0, "127.0.0.1", () => resolve()));
    this.port = (this.server!.address() as AddressInfo).port;
    return this.port;
  }

  async stop(): Promise<void> {
    for (const res of this.open) res.destroy();
    this.server?.closeAllConnections();
    await new Promise<void>((resolve) => this.server?.close(() => resolve()) ?? resolve());
  }

  private handle(body: string, req: http.IncomingMessage, res: http.ServerResponse) {
    let parsed: any = {};
    try {
      parsed = JSON.parse(body);
    } catch {
      res.writeHead(400).end();
      return;
    }
    const messages = (parsed.messages ?? []).map((m: any) => ({ role: String(m.role), text: textOf(m.content) || (m.tool_calls ? JSON.stringify(m.tool_calls) : "") }));
    const entry: LoggedRequest = {
      at: Date.now(),
      model: String(parsed.model),
      auth: req.headers.authorization,
      tools: (parsed.tools ?? []).map((t: any) => t?.function?.name).filter(Boolean),
      system: messages.find((m: any) => m.role === "system" || m.role === "developer")?.text ?? "",
      messages,
      last: messages[messages.length - 1] ?? { role: "", text: "" },
    };
    this.log.push(entry);
    const script = this.scripts[entry.model];
    const reply: Reply = script ? script(entry) : { text: `no script for ${entry.model}` };
    if ("status" in reply) {
      res.writeHead(reply.status, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "fake failure" } }));
      return;
    }
    this.open.add(res);
    res.on("close", () => this.open.delete(res));
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
    if ("hang" in reply) {
      res.write(": holding\n\n");
      return; // until the client goes away or stop()
    }
    const send = () => {
      const base = { id: "chatcmpl-fake", object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: entry.model };
      const chunk = (choice: object) => res.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, ...choice }] })}\n\n`);
      if ("tool" in reply) {
        chunk({
          delta: {
            role: "assistant",
            tool_calls: [{ index: 0, id: `call_${this.log.length}`, type: "function", function: { name: reply.tool.name, arguments: JSON.stringify(reply.tool.args) } }],
          },
          finish_reason: null,
        });
        chunk({ delta: {}, finish_reason: "tool_calls" });
      } else {
        chunk({ delta: { role: "assistant", content: reply.text }, finish_reason: null });
        chunk({ delta: {}, finish_reason: "stop" });
      }
      res.write(`data: ${JSON.stringify({ ...base, choices: [], usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 } })}\n\n`);
      res.end("data: [DONE]\n\n");
    };
    if ("text" in reply && reply.delayMs) setTimeout(send, reply.delayMs);
    else send();
  }

  requestsFor(model: string): LoggedRequest[] {
    return this.log.filter((r) => r.model === model);
  }

  /** Any request (by any model) whose messages contain `needle`. */
  sawText(needle: string, model?: string): boolean {
    return this.log.some((r) => (!model || r.model === model) && r.messages.some((m) => m.text.includes(needle)));
  }
}

export function modelsJson(port: number, models: string[]): string {
  return JSON.stringify(
    {
      providers: {
        openai: {
          baseUrl: `http://127.0.0.1:${port}/v1`,
          api: "openai-completions",
          apiKey: "$OPENAI_API_KEY",
          models: models.map((id) => ({ id, reasoning: false, contextWindow: 128000, maxTokens: 4096 })),
        },
      },
    },
    null,
    2,
  );
}
