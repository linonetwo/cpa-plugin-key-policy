import { describe, expect, it } from "vitest";
import type {
  ApiKeyAlias,
  CatalogModel,
  ClassifyRule,
  NativeIdentity,
} from "../types";
import {
  nativeGroupOptions,
  nativeIdentityAlias,
  rawAPIKeyHash,
  groupNativeGrants,
} from "./nativeAccessModel";

describe("native access display metadata", () => {
  it("joins a CPAMP alias to the prefixed plugin hash without storing a name", () => {
    const hash = "0123456789abcdef".repeat(4);
    const identity: NativeIdentity = {
      key_hash: "sha256:" + hash,
      key_preview: "sk-one...ative",
      managed: true,
    };
    const aliases: ApiKeyAlias[] = [
      { apiKeyHash: hash.toUpperCase(), alias: "  User One  " },
    ];

    expect(rawAPIKeyHash(identity.key_hash)).toBe(hash);
    expect(nativeIdentityAlias(identity, aliases)).toBe("User One");
    expect(identity).not.toHaveProperty("name");
    expect(identity).not.toHaveProperty("alias");
  });

  it("falls back when CPAMP has no display alias for the identity", () => {
    const identity: NativeIdentity = {
      key_hash: "sha256:" + "a".repeat(64),
      key_preview: "sk-two...ative",
      managed: false,
    };
    expect(nativeIdentityAlias(identity, [])).toBe("");
  });

  it("accepts the snake_case alias shape used by older Manager builds", () => {
    const identity: NativeIdentity = {
      key_hash: "sha256:abc123",
      key_preview: "cp******",
      managed: true,
    };
    expect(nativeIdentityAlias(identity, [
      { api_key_hash: "abc123", alias: "Legacy Manager Alias" },
    ])).toBe("Legacy Manager Alias");
  });
});

describe("native credential group suggestions", () => {
  const catalog: CatalogModel[] = [
    { provider: "codex", model: "gpt-5.6-sol", group: "classify:csil" },
    { provider: "codex", model: "gpt-5.6-sol", group: "team" },
    { provider: "codex", model: "gpt-5.6-mini", group: "free" },
    { provider: "claude", model: "claude-opus", group: "classify:anthropic" },
  ];
  const rules: ClassifyRule[] = [
    {
      name: "legacy",
      field: "filename",
      pattern: "legacy",
      group: "Legacy",
      enabled: true,
    },
    {
      name: "off",
      field: "filename",
      pattern: "off",
      group: "disabled-group",
      enabled: false,
    },
  ];

  it("filters catalog candidates by provider and model without leaking unrelated classify rules", () => {
    expect(nativeGroupOptions(
      { provider: "codex", model: "gpt-5.6-sol" },
      catalog,
      rules,
    )).toEqual(["classify:csil", "team"]);
  });

  it("keeps all provider groups searchable until a model is selected", () => {
    expect(nativeGroupOptions(
      { provider: "codex", model: "" },
      catalog,
      [],
    )).toEqual(["classify:csil", "free", "team"]);
  });

  it("shows no credential subgroup when a provider has no classified credentials", () => {
    expect(nativeGroupOptions(
      { provider: "kimi", model: "kimi-k3" },
      catalog,
      rules,
    )).toEqual([]);
  });
});

describe("native grant summaries", () => {
  it("groups long permission lists by provider", () => {
    expect(groupNativeGrants([
      { provider: "kimi", model: "kimi-k3" },
      { provider: "codex", model: "gpt-5.6-sol" },
      { provider: "kimi", model: "kimi-k2.7-code" },
    ])).toEqual([
      { provider: "codex", indexes: [1] },
      { provider: "kimi", indexes: [0, 2] },
    ]);
  });
});
