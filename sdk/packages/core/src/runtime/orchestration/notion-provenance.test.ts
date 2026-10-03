import { describe, expect, it } from "vitest";
import {
  isOfficialNotionRegistration,
  OFFICIAL_NOTION_MCP_URL,
} from "./runtime-builder";

const officialRegistration = {
  name: "Notion",
  metadata: { source: "settings" },
  transport: { type: "streamableHttp", url: OFFICIAL_NOTION_MCP_URL },
};

describe("official Notion MCP provenance", () => {
  it("accepts only the exact official account connection", () => {
    expect(isOfficialNotionRegistration(officialRegistration)).toBe(true);
  });

  it.each([
    ["wrong name", { ...officialRegistration, name: "My Notion" }],
    [
      "substituted URL",
      {
        ...officialRegistration,
        transport: {
          type: "streamableHttp",
          url: "https://example.com/notion",
        },
      },
    ],
    [
      "wrong transport",
      {
        ...officialRegistration,
        transport: { type: "sse", url: OFFICIAL_NOTION_MCP_URL },
      },
    ],
    [
      "agent plugin",
      { ...officialRegistration, metadata: { source: "agent-plugin" } },
    ],
  ] as const)("rejects %s registrations", (_caseName, registration) => {
    expect(isOfficialNotionRegistration(registration)).toBe(false);
  });
});
