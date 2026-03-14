import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createFeishuClientMockModule,
  createFeishuRuntimeMockModule,
} from "./monitor.test-mocks.js";
import {
  buildWebhookConfig,
  getFreePort,
  withRunningWebhookMonitor,
} from "./monitor.webhook.test-helpers.js";

const probeFeishuMock = vi.hoisted(() => vi.fn());

vi.mock("./probe.js", () => ({
  probeFeishu: probeFeishuMock,
}));

vi.mock("./client.js", () => createFeishuClientMockModule());
vi.mock("./runtime.js", () => createFeishuRuntimeMockModule());

vi.mock("@larksuiteoapi/node-sdk", () => ({
  adaptDefault: vi.fn(
    () => (_req: unknown, res: { statusCode?: number; end: (s: string) => void }) => {
      res.statusCode = 200;
      res.end("ok");
    },
  ),
}));

import {
  clearFeishuWebhookRateLimitStateForTest,
  getFeishuWebhookRateLimitStateSizeForTest,
  isWebhookRateLimitedForTest,
  monitorFeishuProvider,
  stopFeishuMonitor,
} from "./monitor.js";

afterEach(() => {
  clearFeishuWebhookRateLimitStateForTest();
  stopFeishuMonitor();
});

describe("Feishu webhook security hardening", () => {
  it("rejects webhook mode without verificationToken", async () => {
    probeFeishuMock.mockResolvedValue({ ok: true, botOpenId: "bot_open_id" });

    const cfg = buildWebhookConfig({
      accountId: "missing-token",
      path: "/hook-missing-token",
      port: await getFreePort(),
    });

    await expect(monitorFeishuProvider({ config: cfg })).rejects.toThrow(
      /requires verificationToken/i,
    );
  });

  it("accepts webhook mode without encryptKey (Lark international)", async () => {
    probeFeishuMock.mockResolvedValue({ ok: true, botOpenId: "bot_open_id" });
    const port = await getFreePort();
    const cfg = buildWebhookConfig({
      accountId: "no-encrypt-key",
      path: "/hook-no-encrypt",
      port,
      verificationToken: "verify_token",
    });

    const abortController = new AbortController();
    const runtime = { log: vi.fn(), error: vi.fn(), exit: vi.fn() };
    const monitorPromise = monitorFeishuProvider({
      config: cfg,
      runtime,
      abortSignal: abortController.signal,
    });

    // Wait briefly for server startup, then abort — no throw means it started successfully
    await new Promise((resolve) => setTimeout(resolve, 200));
    abortController.abort();
    await monitorPromise;
  });

  it("returns 415 for POST requests without json content type", async () => {
    probeFeishuMock.mockResolvedValue({ ok: true, botOpenId: "bot_open_id" });
    await withRunningWebhookMonitor(
      {
        accountId: "content-type",
        path: "/hook-content-type",
        verificationToken: "verify_token",
        encryptKey: "encrypt_key",
      },
      monitorFeishuProvider,
      async (url) => {
        const response = await fetch(url, {
          method: "POST",
          headers: { "content-type": "text/plain" },
          body: "{}",
        });

        expect(response.status).toBe(415);
        expect(await response.text()).toBe("Unsupported Media Type");
      },
    );
  });

  it("rate limits webhook burst traffic with 429", async () => {
    probeFeishuMock.mockResolvedValue({ ok: true, botOpenId: "bot_open_id" });
    await withRunningWebhookMonitor(
      {
        accountId: "rate-limit",
        path: "/hook-rate-limit",
        verificationToken: "verify_token",
        encryptKey: "encrypt_key",
      },
      monitorFeishuProvider,
      async (url) => {
        let saw429 = false;
        for (let i = 0; i < 130; i += 1) {
          const response = await fetch(url, {
            method: "POST",
            headers: { "content-type": "text/plain" },
            body: "{}",
          });
          if (response.status === 429) {
            saw429 = true;
            expect(await response.text()).toBe("Too Many Requests");
            break;
          }
        }

        expect(saw429).toBe(true);
      },
    );
  });

  it("caps tracked webhook rate-limit keys to prevent unbounded growth", () => {
    const now = 1_000_000;
    for (let i = 0; i < 4_500; i += 1) {
      isWebhookRateLimitedForTest(`/feishu-rate-limit:key-${i}`, now);
    }
    expect(getFeishuWebhookRateLimitStateSizeForTest()).toBeLessThanOrEqual(4_096);
  });

  it("prunes stale webhook rate-limit state after window elapses", () => {
    const now = 2_000_000;
    for (let i = 0; i < 100; i += 1) {
      isWebhookRateLimitedForTest(`/feishu-rate-limit-stale:key-${i}`, now);
    }
    expect(getFeishuWebhookRateLimitStateSizeForTest()).toBe(100);

    isWebhookRateLimitedForTest("/feishu-rate-limit-stale:fresh", now + 60_001);
    expect(getFeishuWebhookRateLimitStateSizeForTest()).toBe(1);
  });
});
