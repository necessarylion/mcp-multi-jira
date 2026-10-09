import crypto from "node:crypto";
import http from "node:http";
import type { Socket } from "node:net";
import { URL } from "node:url";
import {
  auth,
  discoverAuthorizationServerMetadata,
  discoverOAuthProtectedResourceMetadata,
  type OAuthClientProvider,
  refreshAuthorization,
  selectResourceURL,
} from "@modelcontextprotocol/sdk/client/auth.js";
import type {
  OAuthClientInformationMixed,
  OAuthProtectedResourceMetadataSchema,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import getPort from "get-port";
import open from "open";
import type { z } from "zod";
import type { TokenStore } from "../security/token-store.js";
import type { TokenSet } from "../types.js";
import { debug, info, warn } from "../utils/log.js";
import {
  deleteClientInfo,
  readClientInfo,
  writeClientInfo,
} from "./client-info-store.js";

export const DEFAULT_SCOPES = [
  "offline_access",
  "read:me",
  "read:account",
  "read:jira:agent-interface",
  "write:jira:agent-interface",
  "search:jira:agent-interface",
  "read:confluence:agent-interface",
  "write:confluence:agent-interface",
  "search:confluence:agent-interface",
  "search:rovo:agent-interface",
];

export const MCP_SERVER_URL =
  process.env.MCP_JIRA_ENDPOINT ?? "https://mcp.atlassian.com/v2/mcp";

// v2 hides the real tools behind `discover` and `execute` by default.
// `tools=all` gives the full tool list, which this proxy needs.
export function getMcpTransportUrl() {
  const url = new URL(MCP_SERVER_URL);
  url.searchParams.set("tools", "all");
  return url;
}

export type StaticClientInfo = {
  clientId: string;
  clientSecret?: string;
};

export function getStaticClientInfoFromEnv(options?: {
  clientId?: string;
  clientSecret?: string;
}): StaticClientInfo | null {
  const clientId =
    options?.clientId ||
    process.env.MCP_JIRA_CLIENT_ID ||
    process.env.ATLASSIAN_CLIENT_ID;
  const clientSecret =
    options?.clientSecret ||
    process.env.MCP_JIRA_CLIENT_SECRET ||
    process.env.ATLASSIAN_CLIENT_SECRET;
  if (!clientId) {
    return null;
  }
  return { clientId, clientSecret };
}

export function isInvalidGrantError(err: unknown) {
  if (!err || typeof err !== "object") {
    return false;
  }
  const name = (err as { name?: unknown }).name;
  if (name === "InvalidGrantError") {
    return true;
  }
  const message = String(err).toLowerCase();
  return (
    message.includes("invalidgranterror") || message.includes("invalid_grant")
  );
}

function toTokenSet(tokens: OAuthTokens, fallbackScopes: string[]): TokenSet {
  const scopes = tokens.scope
    ? tokens.scope.split(" ").filter(Boolean)
    : fallbackScopes;
  const expiresIn = tokens.expires_in ?? 0;
  return {
    accessToken: tokens.access_token,
    expiresAt: Date.now() + expiresIn * 1000,
    refreshToken: tokens.refresh_token,
    scopes,
    tokenType: tokens.token_type,
  };
}

function toOAuthTokens(set: TokenSet): OAuthTokens {
  const expiresIn = Math.max(
    0,
    Math.floor((set.expiresAt - Date.now()) / 1000)
  );
  return {
    access_token: set.accessToken,
    expires_in: expiresIn,
    refresh_token: set.refreshToken,
    scope: set.scopes.join(" "),
    token_type: set.tokenType ?? "Bearer",
  };
}

export class LocalOAuthProvider implements OAuthClientProvider {
  private readonly alias: string;
  private readonly tokenStore: TokenStore;
  private readonly scopes: string[];
  private readonly allowRedirect: boolean;
  private readonly staticClientInfo: StaticClientInfo | null;
  private readonly stateValue = crypto.randomUUID();
  private codeVerifierValue?: string;
  private clientInfoCache?: OAuthClientInformationMixed | null;
  private redirectUrlValue?: string;

  constructor(options: {
    alias: string;
    tokenStore: TokenStore;
    scopes: string[];
    allowRedirect: boolean;
    staticClientInfo: StaticClientInfo | null;
  }) {
    this.alias = options.alias;
    this.tokenStore = options.tokenStore;
    this.scopes = options.scopes;
    this.allowRedirect = options.allowRedirect;
    this.staticClientInfo = options.staticClientInfo;
  }

  setRedirectUrl(url: string) {
    this.redirectUrlValue = url;
  }

  getState() {
    return this.stateValue;
  }

  get redirectUrl() {
    return this.redirectUrlValue;
  }

  get clientMetadata() {
    return {
      client_name: "mcp-jira",
      client_uri: "https://github.com/",
      grant_types: ["authorization_code", "refresh_token"],
      redirect_uris: this.redirectUrlValue ? [this.redirectUrlValue] : [],
      response_types: ["code"],
      scope: this.scopes.join(" "),
      token_endpoint_auth_method: this.staticClientInfo?.clientSecret
        ? "client_secret_post"
        : "none",
    };
  }

  state() {
    return this.stateValue;
  }

  async clientInformation() {
    if (this.staticClientInfo) {
      return {
        client_id: this.staticClientInfo.clientId,
        client_secret: this.staticClientInfo.clientSecret,
        token_endpoint_auth_method: this.staticClientInfo.clientSecret
          ? "client_secret_post"
          : "none",
      };
    }
    if (this.clientInfoCache !== undefined) {
      return this.clientInfoCache ?? undefined;
    }
    const stored = await readClientInfo(MCP_SERVER_URL);
    this.clientInfoCache = stored;
    return stored ?? undefined;
  }

  async saveClientInformation(clientInfo: OAuthClientInformationMixed) {
    this.clientInfoCache = clientInfo;
    await writeClientInfo(MCP_SERVER_URL, clientInfo);
  }

  async tokens() {
    const tokens = await this.tokenStore.get(this.alias);
    if (!tokens) {
      return;
    }
    return toOAuthTokens(tokens);
  }

  async saveTokens(tokens: OAuthTokens) {
    const set = toTokenSet(tokens, this.scopes);
    await this.tokenStore.set(this.alias, set);
  }

  async redirectToAuthorization(authorizationUrl: URL) {
    if (!this.allowRedirect) {
      throw new Error(
        "Authorization required. Run `mcp-multi-jira login <alias>` to reauthenticate."
      );
    }
    info("Open the following URL in your browser to authorize:");
    info(authorizationUrl.toString());
    try {
      await open(authorizationUrl.toString());
    } catch (err) {
      warn(`Failed to open browser automatically: ${String(err)}`);
    }
  }

  saveCodeVerifier(codeVerifier: string) {
    this.codeVerifierValue = codeVerifier;
  }

  codeVerifier() {
    if (!this.codeVerifierValue) {
      throw new Error("Missing OAuth code verifier.");
    }
    return this.codeVerifierValue;
  }

  async invalidateCredentials(scope: "all" | "client" | "tokens" | "verifier") {
    if (scope === "verifier" || scope === "all") {
      this.codeVerifierValue = undefined;
    }

    if (scope === "tokens" || scope === "all") {
      await this.tokenStore.remove(this.alias);
    }

    if ((scope === "client" || scope === "all") && !this.staticClientInfo) {
      this.clientInfoCache = null;
      await deleteClientInfo(MCP_SERVER_URL);
    }
  }
}

function extractRedirectUriFromClientInfo(
  clientInfo: OAuthClientInformationMixed | null | undefined
) {
  if (!clientInfo || typeof clientInfo !== "object") {
    return;
  }
  const redirectUris = (clientInfo as Record<string, unknown>).redirect_uris;
  if (!Array.isArray(redirectUris)) {
    return;
  }
  const first = redirectUris[0];
  if (typeof first !== "string" || first.length === 0) {
    return;
  }
  return first;
}

export async function startCallbackServer(
  expectedState: string,
  options?: { redirectUri?: string }
) {
  let redirectUri = options?.redirectUri;
  if (!redirectUri) {
    const port = await getPort({ port: 3334 });
    redirectUri = `http://127.0.0.1:${port}/oauth/callback`;
  }
  const redirectUrl = new URL(redirectUri);
  if (redirectUrl.protocol !== "http:") {
    throw new Error(`Invalid redirect URI protocol: ${redirectUri}`);
  }
  if (redirectUrl.pathname !== "/oauth/callback") {
    throw new Error(`Invalid redirect URI path: ${redirectUri}`);
  }
  const port = Number(redirectUrl.port);
  if (!port || Number.isNaN(port)) {
    throw new Error(
      `Redirect URI must include an explicit port (e.g. http://127.0.0.1:3334/oauth/callback), got: ${redirectUri}`
    );
  }
  const hostname = redirectUrl.hostname;
  const server = http.createServer();
  let closed = false;
  const sockets = new Set<Socket>();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  const close = () =>
    new Promise<void>((resolve) => {
      if (closed) {
        resolve();
        return;
      }
      closed = true;
      for (const socket of sockets) {
        socket.destroy();
      }
      server.close(() => resolve());
    });
  const codePromise = new Promise<string>((resolve, reject) => {
    server.on("request", (req, res) => {
      try {
        const url = new URL(req.url ?? "", redirectUri);
        if (url.pathname !== "/oauth/callback") {
          res.writeHead(404);
          res.end("Not found");
          return;
        }
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        if (!code || state !== expectedState) {
          res.writeHead(400);
          res.end("Invalid OAuth response.");
          reject(new Error("Invalid OAuth response"));
          return;
        }
        res.writeHead(200, {
          connection: "close",
          "content-type": "text/plain",
        });
        res.end("Authentication complete. You can return to the CLI.");
        resolve(code);
      } catch (err) {
        reject(err);
      } finally {
        setTimeout(() => {
          close().catch(() => undefined);
        }, 100);
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (err: unknown) => {
      reject(err);
    };
    server.once("error", onError);
    server.listen(port, hostname, () => {
      server.off("error", onError);
      resolve();
    });
  }).catch((err: unknown) => {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "EADDRINUSE") {
      throw new Error(
        `OAuth callback port ${port} is already in use (redirect URI: ${redirectUri}). Close the other process using it and retry.`
      );
    }
    throw err;
  });

  return { close, codePromise, redirectUri };
}

export async function loginWithDynamicOAuth(options: {
  alias: string;
  tokenStore: TokenStore;
  scopes: string[];
  staticClientInfo: StaticClientInfo | null;
}) {
  const provider = new LocalOAuthProvider({
    alias: options.alias,
    allowRedirect: true,
    scopes: options.scopes,
    staticClientInfo: options.staticClientInfo,
    tokenStore: options.tokenStore,
  });
  const redirectUriFromEnv = process.env.MCP_JIRA_REDIRECT_URI;
  let redirectUri = redirectUriFromEnv;
  if (!redirectUri) {
    if (options.staticClientInfo) {
      redirectUri = "http://127.0.0.1:3334/oauth/callback";
    } else {
      const clientInfo = await provider.clientInformation();
      redirectUri = extractRedirectUriFromClientInfo(clientInfo);
    }
  }
  const {
    redirectUri: callbackRedirectUri,
    codePromise,
    close,
  } = await startCallbackServer(provider.getState(), { redirectUri });
  try {
    provider.setRedirectUrl(callbackRedirectUri);
    const result = await auth(provider, {
      scope: options.scopes.join(" "),
      serverUrl: MCP_SERVER_URL,
    });
    if (result !== "REDIRECT") {
      await close();
      return;
    }
    const code = await codePromise;
    await auth(provider, {
      authorizationCode: code,
      scope: options.scopes.join(" "),
      serverUrl: MCP_SERVER_URL,
    });
  } finally {
    await close();
  }
}

export async function refreshTokensIfNeeded(options: {
  alias: string;
  tokenStore: TokenStore;
  scopes: string[];
  staticClientInfo: StaticClientInfo | null;
}) {
  const existing = await options.tokenStore.get(options.alias);
  if (!existing) {
    throw new Error("Missing stored tokens.");
  }
  const now = Date.now();
  if (existing.expiresAt > now + 5 * 60 * 1000) {
    return existing;
  }
  if (!existing.refreshToken) {
    throw new Error("No refresh token available. Please login again.");
  }
  const provider = new LocalOAuthProvider({
    alias: options.alias,
    allowRedirect: false,
    scopes: options.scopes,
    staticClientInfo: options.staticClientInfo,
    tokenStore: options.tokenStore,
  });
  const clientInfo = await provider.clientInformation();
  if (!clientInfo) {
    throw new Error("Missing OAuth client registration. Please login again.");
  }
  type OAuthProtectedResourceMetadata = z.infer<
    typeof OAuthProtectedResourceMetadataSchema
  >;
  let resourceMetadata: OAuthProtectedResourceMetadata | undefined;
  try {
    resourceMetadata =
      await discoverOAuthProtectedResourceMetadata(MCP_SERVER_URL);
  } catch (err) {
    debug(`Protected resource metadata lookup failed: ${String(err)}`);
  }
  const authServerUrl =
    resourceMetadata?.authorization_servers?.[0] ??
    new URL("/", MCP_SERVER_URL);
  const metadata = await discoverAuthorizationServerMetadata(authServerUrl);
  const resource = await selectResourceURL(
    MCP_SERVER_URL,
    {} as OAuthClientProvider,
    resourceMetadata
  );
  const refreshed = await refreshAuthorization(authServerUrl, {
    clientInformation: clientInfo,
    metadata,
    refreshToken: existing.refreshToken,
    resource,
  });
  const updated = toTokenSet(refreshed, options.scopes);
  await options.tokenStore.set(options.alias, updated);
  return updated;
}
