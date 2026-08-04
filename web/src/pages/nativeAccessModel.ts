import type {
  ApiKeyAlias,
  CatalogModel,
  ClassifyRule,
  NativeGrant,
  NativeIdentity,
} from "../types";

const SHA256_PREFIX = "sha256:";
const CLASSIFY_PREFIX = "classify:";

export function rawAPIKeyHash(keyHash: string): string {
  const normalized = keyHash.trim().toLowerCase();
  return normalized.startsWith(SHA256_PREFIX)
    ? normalized.slice(SHA256_PREFIX.length)
    : normalized;
}

export function nativeIdentityAlias(
  identity: NativeIdentity,
  aliases: ApiKeyAlias[],
): string {
  const target = rawAPIKeyHash(identity.key_hash);
  return aliases.find(
    (item) =>
      rawAPIKeyHash(item.apiKeyHash ?? item.api_key_hash ?? "") === target &&
      item.alias.trim() !== "",
  )?.alias.trim() ?? "";
}

function classifyGroup(group: string): string {
  const normalized = group.trim().toLowerCase();
  if (!normalized) return "";
  return normalized.startsWith(CLASSIFY_PREFIX)
    ? normalized
    : CLASSIFY_PREFIX + normalized;
}

// Suggestions are constrained by the selected provider/model when catalog
// metadata is available. Enabled configured classify groups are also offered
// so an administrator can select a valid group before a matching credential
// happens to expose models in the catalog. The input remains a datalist-backed
// free-text field, so new/manual groups are still accepted.
export function nativeGroupOptions(
  grant: NativeGrant,
  catalog: CatalogModel[],
  rules: ClassifyRule[],
): string[] {
  const provider = grant.provider.trim().toLowerCase();
  const model = grant.model.trim().toLowerCase();
  const groups = new Set<string>();

  for (const item of catalog) {
    if (!item.group) continue;
    if (provider && provider !== "*" && item.provider.toLowerCase() !== provider) continue;
    if (model && item.model.toLowerCase() !== model) continue;
    groups.add(item.group.trim().toLowerCase());
  }
  for (const rule of rules) {
    if (!rule.enabled) continue;
    const group = classifyGroup(rule.group);
    if (group) groups.add(group);
  }

  return Array.from(groups).sort((a, b) => a.localeCompare(b));
}
