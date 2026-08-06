import { useCallback, useEffect, useState } from "react";
import {
  continueNativeRotation,
  listApiKeyAliases,
  listNativeIdentities,
  listNativePolicies,
  saveNativePolicy,
} from "../api/nativeAccess";
import { fetchCatalog } from "../api/models";
import { fetchClassifyRules } from "../api/mappings";
import type {
  ApiKeyAlias,
  CatalogModel,
  ClassifyRule,
  NativeGrant,
  NativeIdentity,
  NativePolicy,
} from "../types";
import { useT } from "../i18n";
import {
  groupNativeGrants,
  nativeGroupOptions,
  nativeIdentityAlias,
} from "./nativeAccessModel";

const emptyGrant = (): NativeGrant => ({ provider: "", model: "" });
const numberValue = (value: string): number => {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
};

export default function NativeAccess() {
  const t = useT();
  const [identities, setIdentities] = useState<NativeIdentity[]>([]);
  const [policies, setPolicies] = useState<NativePolicy[]>([]);
  const [catalog, setCatalog] = useState<CatalogModel[]>([]);
  const [aliases, setAliases] = useState<ApiKeyAlias[]>([]);
  const [classifyRules, setClassifyRules] = useState<ClassifyRule[]>([]);
  const [editing, setEditing] = useState<NativePolicy | null>(null);
  const [rotationTarget, setRotationTarget] = useState<NativeIdentity | null>(null);
  const [rotationSource, setRotationSource] = useState("");
  const [rotating, setRotating] = useState(false);
  const [toggling, setToggling] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [nextIdentities, nextPolicies, nextCatalog, nextAliases, nextRules] = await Promise.all([
        listNativeIdentities(),
        listNativePolicies(),
        fetchCatalog(),
        // CPAMP-only display metadata is optional when the plugin UI is opened
        // directly against CPA or an older manager build.
        listApiKeyAliases().catch(() => []),
        fetchClassifyRules().catch(() => []),
      ]);
      setIdentities(nextIdentities);
      setPolicies(nextPolicies);
      setCatalog(nextCatalog);
      setAliases(nextAliases);
      setClassifyRules(nextRules);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const edit = (identity: NativeIdentity) => {
    const current = policies.find((item) =>
      (identity.principal_id && item.principal_id === identity.principal_id) ||
      item.key_hash === identity.key_hash
    );
    setEditing(current ? structuredClone(current) : {
      key_hash: identity.key_hash,
      enabled: true,
      grants: [emptyGrant()],
    });
  };

  const retiredPrincipals = identities.filter((identity) =>
    identity.managed && identity.active === false && identity.principal_id
  );

  const beginRotation = (identity: NativeIdentity) => {
    setRotationTarget(identity);
    setRotationSource(retiredPrincipals.length === 1 ? retiredPrincipals[0].principal_id ?? "" : "");
    setError("");
  };

  const continueRotation = async () => {
    if (!rotationTarget || !rotationSource) return;
    setRotating(true);
    setError("");
    try {
      await continueNativeRotation(rotationSource, rotationTarget.key_hash);
      setRotationTarget(null);
      setRotationSource("");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setRotating(false);
    }
  };

  const togglePolicy = async (policy: NativePolicy) => {
    setToggling(policy.key_hash);
    setError("");
    try {
      const next = { ...policy, enabled: !policy.enabled };
      await saveNativePolicy(next);
      setPolicies((current) =>
        current.map((item) => item.key_hash === next.key_hash ? next : item),
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setToggling("");
    }
  };

  return (
    <div>
      <div className="fp-head" style={{ margin: "0 0 16px" }}>
        <div>
          <h1>{t("native.title")}</h1>
          <div className="muted">{t("native.identityHint")}</div>
        </div>
        <button className="btn sm" onClick={() => void load()}>{t("keys.refresh")}</button>
      </div>
      {error && <div className="error">{error}</div>}
      {loading ? <div className="muted">{t("keys.loading")}</div> : (
        <div className="card-stack">
          {identities.map((identity) => {
            const policy = policies.find((item) =>
              (identity.principal_id && item.principal_id === identity.principal_id) ||
              item.key_hash === identity.key_hash
            );
            const alias = nativeIdentityAlias(identity, aliases);
            return (
              <div className="card" key={identity.key_hash}>
                <div className="fp-head">
                  <div>
                    <strong>{alias || identity.key_preview}</strong>
                    {alias && <div className="muted mono">{identity.key_preview}</div>}
                    <div className="muted mono">{identity.key_hash.slice(0, 19)}…</div>
                  </div>
                  {identity.active === false ? (
                    <span className="badge">{t("native.retiredCredential")}</span>
                  ) : policy ? (
                    <label className="switch" aria-label={policy.enabled ? t("keys.enabled") : t("keys.disabled")}>
                      <input
                        type="checkbox"
                        role="switch"
                        checked={policy.enabled}
                        disabled={toggling === policy.key_hash}
                        onChange={() => void togglePolicy(policy)}
                      />
                      <span className="track"><span className="thumb" /></span>
                      {policy.enabled ? t("keys.enabled") : t("keys.disabled")}
                    </label>
                  ) : (
                    <span className="badge">{t("native.unmanaged")}</span>
                  )}
                </div>
                {policy && (
                  <details className="native-grant-summary">
                    <summary>
                      <span>{t("native.ruleCount", { n: policy.grants.length })}</span>
                      <span className="chip-row compact">
                        {groupNativeGrants(policy.grants).map((group) => (
                          <span className="chip" key={group.provider}>
                            {group.provider} · {group.indexes.length}
                          </span>
                        ))}
                      </span>
                    </summary>
                    <div className="native-grant-list">
                      {policy.grants.map((grant, index) => (
                        <div className="native-grant-line" key={`${grant.provider}-${grant.model}-${index}`}>
                          <strong>{grant.provider}</strong>
                          <span>{grant.model}</span>
                          {grant.group && <span className="muted">{grant.group.replace(/^classify:/, "")}</span>}
                        </div>
                      ))}
                    </div>
                  </details>
                )}
                <div className="native-card-actions">
                  {identity.active !== false && (
                    <button className="btn sm" onClick={() => edit(identity)}>{t("native.edit")}</button>
                  )}
                  {identity.active !== false && !identity.managed && retiredPrincipals.length > 0 && (
                    <button className="btn sm primary" onClick={() => beginRotation(identity)}>
                      {t("native.continueRotation")}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
      {editing && (
        <NativePolicyEditor
          policy={editing}
          catalog={catalog}
          classifyRules={classifyRules}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); void load(); }}
        />
      )}
      {rotationTarget && (
        <div className="modal-overlay">
          <div className="modal native-rotation-modal">
            <div className="modal-header">
              <div>
                <h2>{t("native.rotationTitle")}</h2>
                <div className="muted">{t("native.rotationHint")}</div>
              </div>
            </div>
            <div className="modal-body">
              <label>
                {t("native.newCredential")}
                <input className="input mono" value={rotationTarget.key_preview} readOnly />
              </label>
              <label>
                {t("native.previousIdentity")}
                <select
                  className="input"
                  value={rotationSource}
                  onChange={(event) => setRotationSource(event.target.value)}
                >
                  <option value="">{t("native.selectPreviousIdentity")}</option>
                  {retiredPrincipals.map((identity) => {
                    const alias = nativeIdentityAlias(identity, aliases);
                    return (
                      <option value={identity.principal_id} key={identity.principal_id}>
                        {alias || identity.key_preview || identity.principal_id}
                      </option>
                    );
                  })}
                </select>
              </label>
              <div className="muted">{t("native.rotationAuditHint")}</div>
            </div>
            <div className="modal-actions modal-footer">
              <button className="btn" disabled={rotating} onClick={() => setRotationTarget(null)}>
                {t("mapping.cancel")}
              </button>
              <button
                className="btn primary"
                disabled={rotating || !rotationSource}
                onClick={() => void continueRotation()}
              >
                {t("native.confirmRotation")}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function NativePolicyEditor({
  policy: initial,
  catalog,
  classifyRules,
  onClose,
  onSaved,
}: {
  policy: NativePolicy;
  catalog: CatalogModel[];
  classifyRules: ClassifyRule[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const t = useT();
  const [policy, setPolicy] = useState(initial);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const grantGroups = groupNativeGrants(policy.grants);
  const updateGrant = (index: number, patch: Partial<NativeGrant>) => {
    setPolicy((current) => ({
      ...current,
      grants: current.grants.map((grant, grantIndex) =>
        grantIndex === index ? { ...grant, ...patch } : grant
      ),
    }));
  };
  const save = async () => {
    const grants = policy.grants
      .filter((grant) => grant.provider.trim() && grant.model.trim())
      .map((grant) => ({
        provider: grant.provider.trim(),
        model: grant.model.trim(),
        ...(grant.group?.trim() ? { group: grant.group.trim() } : {}),
      }));
    if (grants.length === 0) {
      setError(t("native.grantRequired"));
      return;
    }
    setSaving(true);
    setError("");
    try {
      await saveNativePolicy({ ...policy, grants });
      onSaved();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSaving(false);
    }
  };
  const quota = (field: keyof NativePolicy, label: string) => (
    <label>
      {label}
      <input
        className="input"
        type="number"
        min={0}
        value={String(policy[field] ?? 0)}
        onChange={(event) => setPolicy({ ...policy, [field]: numberValue(event.target.value) })}
      />
    </label>
  );
  return (
    <div className="modal-overlay">
      <div className="modal native-policy-modal">
        <div className="modal-header">
          <div>
            <h2>{t("native.editTitle")}</h2>
            <div className="muted mono">{initial.key_hash.slice(0, 24)}…</div>
          </div>
          <label className="switch">
            <input
              type="checkbox"
              role="switch"
              checked={policy.enabled}
              onChange={(event) => setPolicy({ ...policy, enabled: event.target.checked })}
            />
            <span className="track"><span className="thumb" /></span>
            <span>{t("native.enabled")}</span>
          </label>
        </div>
        <div className="modal-body">
          <div className="muted native-policy-hint">{t("native.upstreamOpaqueHint")}</div>
          <div className="native-rule-toolbar">
            <strong>{t("native.ruleCount", { n: policy.grants.length })}</strong>
            <button className="btn sm" onClick={() => setPolicy({ ...policy, grants: [...policy.grants, emptyGrant()] })}>+ {t("native.addGrant")}</button>
          </div>
          <div className="native-rule-groups">
            {grantGroups.map((group) => (
              <details className="native-rule-group" key={group.provider} open>
                <summary>
                  <strong>{group.provider}</strong>
                  <span className="badge">{group.indexes.length}</span>
                </summary>
                {group.indexes.map((index) => {
                  const grant = policy.grants[index];
                  const groupOptions = nativeGroupOptions(grant, catalog, classifyRules);
                  return (
                    <div className="native-rule-row" key={index}>
                      <div className="form-grid native-rule-fields">
                        <label>
                          <span>{t("native.provider")}</span>
                          <input className="input" list={`native-providers-${index}`} value={grant.provider} onChange={(e) => updateGrant(index, { provider: e.target.value })} />
                        </label>
                        <datalist id={`native-providers-${index}`}>
                          <option value="*" />
                          {[...new Set(catalog.map((item) => item.provider))].map((provider) => <option value={provider} key={provider} />)}
                        </datalist>
                        <label>
                          <span>{t("native.model")}</span>
                          <input className="input" list={`native-models-${index}`} value={grant.model} onChange={(e) => updateGrant(index, { model: e.target.value })} />
                        </label>
                        <datalist id={`native-models-${index}`}>
                          {[...new Set(catalog.filter((item) => grant.provider === "*" || item.provider === grant.provider).map((item) => item.model))].map((model) => <option value={model} key={model} />)}
                        </datalist>
                        <label>
                          <span>{t("native.groupScope")}</span>
                          <input
                            className="input"
                            list={`native-groups-${index}`}
                            value={grant.group ?? ""}
                            placeholder={groupOptions.length ? t("native.groupOptional") : t("native.groupAll", { provider: grant.provider || t("native.providerAny") })}
                            onChange={(e) => updateGrant(index, { group: e.target.value || undefined })}
                          />
                        </label>
                        <datalist id={`native-groups-${index}`}>
                          {groupOptions.map((groupName) => (
                            <option value={groupName} label={groupName.replace(/^classify:/, "")} key={groupName} />
                          ))}
                        </datalist>
                      </div>
                      <button
                        className="btn sm danger-outline native-rule-delete"
                        onClick={() => setPolicy({ ...policy, grants: policy.grants.filter((_, i) => i !== index) })}
                      >
                        {t("keys.delete")}
                      </button>
                    </div>
                  );
                })}
              </details>
            ))}
          </div>
          <div className="form-grid two native-quotas">
            {quota("rpm", t("native.rpm"))}
            {quota("daily_calls", t("native.dailyCalls"))}
            {quota("weekly_calls", t("native.weeklyCalls"))}
            {quota("daily_tokens", t("native.dailyTokens"))}
            {quota("weekly_tokens", t("native.weeklyTokens"))}
          </div>
          <div className="muted">{t("native.zeroUnlimited")}</div>
          {error && <div className="error">{error}</div>}
        </div>
        <div className="modal-actions modal-footer">
          <button className="btn" onClick={onClose} disabled={saving}>{t("mapping.cancel")}</button>
          <button className="btn primary" onClick={() => void save()} disabled={saving}>{t("mapping.save")}</button>
        </div>
      </div>
    </div>
  );
}
