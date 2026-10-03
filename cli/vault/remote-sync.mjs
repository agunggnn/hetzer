import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Grimoire } from "./hetzer-vault.mjs";

/**
 * Remote sync adapter for Cloudflare D1 Zero-Knowledge Vault mesh
 */

function sha256(text) {
  return crypto.createHash("sha256").update(String(text)).digest("hex");
}

export function deriveKey(masterKey, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : Buffer.from("hetzer-grimoire-v1");
  return crypto.hkdfSync("sha256", String(masterKey), salt, "grimoire-remote-key", 32);
}

export function encryptPayload(masterKey, plaintext) {
  const salt = crypto.randomBytes(16);
  const key = deriveKey(masterKey, salt.toString("hex"));
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    salt: salt.toString("base64")
  };
}

export function decryptPayload(masterKey, { ciphertext, iv, tag, salt }) {
  const saltBuf = Buffer.from(salt, "base64");
  const key = deriveKey(masterKey, saltBuf.toString("hex"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(ciphertext, "base64")), decipher.final()]);
  return plaintext.toString("utf8");
}

export async function pushVaultToRemote({ root, endpointUrl, apiKey, masterKey, hostId = "global" }) {
  const vault = new Grimoire({ root, masterKey });
  const entries = vault.list();
  if (entries.length === 0) {
    return { ok: true, pushed: 0, message: "No credentials in local vault to sync" };
  }

  const payloadEntries = [];
  for (const entry of entries) {
    const secret = vault.reveal(entry.id);
    if (!secret) continue;
    const encrypted = encryptPayload(masterKey, JSON.stringify({
      id: entry.id,
      module: entry.module,
      secret,
      description: entry.description,
      allowedRoles: entry.allowedRoles,
      allowedActions: entry.allowedActions,
      scope: entry.scope,
      realm: entry.realm
    }));

    payloadEntries.push({
      ref_id: entry.id,
      scope: "global",
      target_host: hostId,
      purpose: entry.module || "core",
      ...encrypted,
      algorithm: "AES-GCM-256",
      version: 1
    });
  }

  const res = await fetch(`${endpointUrl.replace(/\/$/, '')}/api/v1/vault/sync`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ entries: payloadEntries })
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Remote sync failed (${res.status}): ${errText}`);
  }

  return await res.json();
}

export async function pullVaultFromRemote({ root, endpointUrl, apiKey, masterKey, hostId = "vps" }) {
  const url = new URL(`${endpointUrl.replace(/\/$/, '')}/api/v1/vault/pull`);
  url.searchParams.set("host_id", hostId);

  const res = await fetch(url.toString(), {
    headers: {
      "Authorization": `Bearer ${apiKey}`
    }
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Remote pull failed (${res.status}): ${errText}`);
  }

  const data = await res.json();
  const entries = data.entries || [];
  const vault = new Grimoire({ root, masterKey });
  let imported = 0;

  for (const item of entries) {
    try {
      const decryptedJson = decryptPayload(masterKey, item);
      const parsed = JSON.parse(decryptedJson);
      vault.set(parsed.id, parsed.secret, {
        module: parsed.module,
        description: parsed.description,
        roles: parsed.allowedRoles,
        actions: parsed.allowedActions,
        scope: parsed.scope,
        realm: parsed.realm
      });
      imported++;
    } catch (err) {
      console.error(`Failed to decrypt/import entry ${item.ref_id}: ${err.message}`);
    }
  }

  return { ok: true, imported, total: entries.length };
}
