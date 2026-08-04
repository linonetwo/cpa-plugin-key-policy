import type {
  ApiKeyAlias,
  CatalogModel,
  ClassifyRule,
  NativeGrant,
  NativeIdentity,
} from "../types";

const SHA256_PREFIX = "sha256:";

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

// Suggestions are constrained by the selected provider/model when catalog
// metadata is available. Rules that belong to another provider are not offered:
// an empty group already means "all credentials for this provider", while a
// classify group is meaningful only after the catalog confirms a matching
// credential. The input remains datalist-backed so manual values are accepted.
export function nativeGroupOptions(
  grant: NativeGrant,
  catalog: CatalogModel[],
  _rules: ClassifyRule[],
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
  return Array.from(groups).sort((a, b) => a.localeCompare(b));
}

export interface NativeGrantGroup {
  provider: string;
  indexes: number[];
}

export function groupNativeGrants(grants: NativeGrant[]): NativeGrantGroup[] {
  const groups = new Map<string, number[]>();
  grants.forEach((grant, index) => {
    const provider = grant.provider.trim() || "*";
    const indexes = groups.get(provider) ?? [];
    indexes.push(index);
    groups.set(provider, indexes);
  });
  return Array.from(groups, ([provider, indexes]) => ({ provider, indexes }))
    .sort((left, right) => left.provider.localeCompare(right.provider));
}
