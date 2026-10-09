import type {
  SessionManagerLike,
  ToolDefinition,
} from "../../src/mcp/types.ts";
import type { AccountConfig } from "../../src/types.ts";

const account: AccountConfig = {
  alias: "mock",
  cloudId: "mock",
  site: "mock://jira",
};

const tools: ToolDefinition[] = [
  {
    description: "Echoes arguments back as JSON.",
    inputSchema: {
      properties: {
        cloudId: { type: "string" },
        jql: { type: "string" },
      },
      required: ["cloudId", "jql"],
      type: "object",
    },
    name: "mockEcho",
  },
  {
    description: "Second tool for pass-through tests.",
    inputSchema: {
      properties: {
        cloudId: { type: "string" },
        query: { type: "string" },
      },
      required: ["cloudId", "query"],
      type: "object",
    },
    name: "mockSecondTool",
  },
];

const session = {
  callTool(_name: string, args: Record<string, unknown>) {
    return Promise.resolve({
      content: [
        {
          text: JSON.stringify(args),
          type: "text",
        },
      ],
      structuredContent: args,
    });
  },
  listTools() {
    return Promise.resolve(tools);
  },
};

export function createMockSessionManager(): SessionManagerLike {
  return {
    // Uses `this` on purpose. It fails if the server calls it unbound.
    getAccountAuthStatus() {
      this.listAccounts();
      return Promise.resolve({ status: "ok" });
    },
    getSession(alias: string) {
      if (alias === account.alias) {
        return session;
      }
      return null;
    },
    listAccounts() {
      return [account];
    },
  };
}
