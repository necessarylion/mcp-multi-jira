import { expect, test } from "bun:test";
import type { TokenSet } from "../src/types.ts";

const originalEndpoint = process.env.MCP_JIRA_ENDPOINT;
process.env.MCP_JIRA_ENDPOINT = "https://example.com/v1/mcp";

const { refreshTokensIfNeeded } = await import("../src/oauth/atlassian.ts");

class MemoryTokenStore {
  private readonly tokens = new Map<string, TokenSet>();

  get(alias: string) {
    return Promise.resolve(this.tokens.get(alias) ?? null);
  }

  set(alias: string, tokens: TokenSet) {
    this.tokens.set(alias, tokens);
    return Promise.resolve();
  }

  remove(alias: string) {
    this.tokens.delete(alias);
    return Promise.resolve();
  }
}

test("refreshTokensIfNeeded uses root auth server fallback", async () => {
  const store = new MemoryTokenStore();
  const alias = "example";
  await store.set(alias, {
    accessToken: "expired-access",
    expiresAt: Date.now() - 1000,
    refreshToken: "refresh-token",
    scopes: ["offline_access"],
    tokenType: "Bearer",
  });

  const requests: string[] = [];
  const originalFetch = globalThis.fetch;

  globalThis.fetch = (input: RequestInfo | URL, _init?: RequestInit) => {
    let url: string;
    if (typeof input === "string") {
      url = input;
    } else if (input instanceof URL) {
      url = input.toString();
    } else {
      url = input.url;
    }
    requests.push(url);

    if (url.includes("/.well-known/oauth-protected-resource")) {
      return Promise.resolve(new Response("Not Found", { status: 404 }));
    }
    if (url.includes("/.well-known/oauth-authorization-server")) {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            authorization_endpoint: "https://auth.example.com/authorize",
            code_challenge_methods_supported: ["S256", "plain"],
            grant_types_supported: ["authorization_code", "refresh_token"],
            issuer: "https://auth.example.com",
            registration_endpoint: "https://auth.example.com/register",
            response_modes_supported: ["query"],
            response_types_supported: ["code"],
            revocation_endpoint: "https://auth.example.com/token",
            token_endpoint: "https://auth.example.com/token",
            token_endpoint_auth_methods_supported: [
              "client_secret_post",
              "none",
            ],
          }),
          {
            headers: { "Content-Type": "application/json" },
            status: 200,
          }
        )
      );
    }
    if (url === "https://auth.example.com/token") {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            access_token: "new-access",
            expires_in: 3600,
            refresh_token: "new-refresh",
            scope: "offline_access",
            token_type: "Bearer",
          }),
          { headers: { "Content-Type": "application/json" }, status: 200 }
        )
      );
    }
    return Promise.resolve(new Response("Not Found", { status: 404 }));
  };

  try {
    const refreshed = await refreshTokensIfNeeded({
      alias,
      scopes: ["offline_access"],
      staticClientInfo: { clientId: "client" },
      tokenStore: store,
    });

    expect(refreshed.accessToken).toBe("new-access");
    expect(refreshed.refreshToken).toBe("new-refresh");
    expect(
      requests.includes(
        "https://example.com/.well-known/oauth-authorization-server"
      )
    ).toBe(true);
    expect(
      requests.some((url) =>
        url.includes("/.well-known/oauth-authorization-server/v1/mcp")
      )
    ).toBe(false);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalEndpoint === undefined) {
      Reflect.deleteProperty(process.env, "MCP_JIRA_ENDPOINT");
    } else {
      process.env.MCP_JIRA_ENDPOINT = originalEndpoint;
    }
  }
});
