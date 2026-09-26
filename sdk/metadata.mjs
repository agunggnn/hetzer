const SAFE_METADATA_KEYS = [
    "id",
    "projectId",
    "keyName",
    "label",
    "realm",
    "authType",
    "scope",
    "accessRole",
    "allowedActions",
    "headerName",
    "createdAt",
    "updatedAt",
    "lastUsedAt",
    "expiresAt",
    "source",
    "hasSecret",
    "ageDays",
];

export function toSafeCredentialMetadata(entry) {
    if (!entry || typeof entry !== "object") return null;
    const metadata = {};
    for (const key of SAFE_METADATA_KEYS) {
        if (!(key in entry)) continue;
        metadata[key] = key === "allowedActions"
            ? [...(Array.isArray(entry[key]) ? entry[key] : [])]
            : entry[key];
    }
    return Object.freeze(metadata);
}

export function toSafeCredentialList(entries) {
    return Object.freeze((Array.isArray(entries) ? entries : [])
        .map(toSafeCredentialMetadata)
        .filter(Boolean));
}
