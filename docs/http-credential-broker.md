# HTTP credential broker

The HTTP credential broker is a bounded alternative to placing a long-lived credential in a child process environment. A compatible HTTP client receives a random, short-lived capability and a loopback base URL. Hetzer replaces that capability with one vault credential only when forwarding a request permitted by a reviewed policy.

This feature is not a general network sandbox or a StrongDM-compatible infrastructure proxy. The child can ignore the broker and use other network paths, and a process with sufficient access to the same OS account may read or alter Hetzer files. Use OS-level egress and filesystem controls when those paths are in the threat model.

## Policy

Create a policy containing references and routing metadata, never plaintext credentials:

```json
{
  "version": 1,
  "target": "https://api.example.com",
  "credential": "secretRef:service-api-key",
  "baseUrlEnv": "SERVICE_BASE_URL",
  "tokenEnv": "SERVICE_API_KEY",
  "basePath": "/v1",
  "clientAuth": {
    "header": "authorization",
    "scheme": "Bearer"
  },
  "upstreamAuth": {
    "header": "x-api-key",
    "scheme": ""
  },
  "allowedMethods": ["GET", "POST"],
  "allowedPathPrefixes": ["/v1"],
  "forwardHeaders": ["accept", "content-type", "user-agent"],
  "ttlSeconds": 300,
  "maxRequests": 100,
  "maxRequestBytes": 1048576,
  "maxResponseBytes": 8388608,
  "timeoutMs": 30000
}
```

Treat this policy as security-sensitive configuration. The target must be an HTTPS origin without a path, query, embedded credential, or fragment. Broker v1 rejects the root path as an allowlist, unsupported methods, hop-by-hop headers, redirects, and non-text responses.

## Execution

Store the referenced credential through the masked prompt, then launch a compatible client:

```text
hetzer creds set service-api-key
hetzer broker --policy ./broker-policy.json -- trusted-http-client
```

For mediated-by-default execution, place the reviewed policy at `.hetzer/brokers/<credential-id>.json` and select that credential explicitly:

```text
hetzer exec --allow service-api-key --strict -- trusted-http-client
```

Alternatively, pass one or more reviewed policies with `--broker-policy <file>`. The child receives the policy's `baseUrlEnv` and `tokenEnv`; when exactly one broker is active it also receives `HETZER_BROKER_URL` and `HETZER_BROKER_CAPABILITY`. Per-credential variants are always available as `HETZER_BROKER_URL_<ID>` and `HETZER_BROKER_CAPABILITY_<ID>` with the ID normalized to uppercase underscores.

If no broker policy exists, execution fails closed. A genuinely local or non-brokerable credential requires both selection and the explicit opt-out:

```text
hetzer exec --allow local-passphrase --allow-raw-unmediated local-passphrase --strict -- trusted-local-client
```

Raw opt-outs create a `process.raw-unmediated` vault audit event. Declarative execution policies deny the opt-out unless the credential is also listed in `allowRawUnmediated`.

The child environment contains `SERVICE_BASE_URL` pointing to a random loopback port and `SERVICE_API_KEY` containing the short-lived broker capability. The referenced vault credential remains in the parent broker and is inserted into the configured upstream header.

Hetzer does not set `HTTP_PROXY` or `HTTPS_PROXY`. Generic HTTPS proxying uses `CONNECT`, which prevents this application-layer broker from safely inspecting paths or injecting upstream authentication. Clients must support the base URL and token environment variables named by the broker policy. AWS SigV4, arbitrary TCP, binary downloads, and clients with fixed upstream URLs are not transparently brokered by v1.

The broker always starts the child with Hetzer's strict base environment. It closes when the child exits or the configured TTL ends. The TTL prevents new connections after expiry; an already accepted request may finish within its request timeout.

## Enforced boundary

- listener address fixed to `127.0.0.1`;
- 256-bit random capability compared with constant-time equality;
- fixed HTTPS upstream origin;
- exact method and normalized path-prefix allowlists;
- bounded request and response sizes;
- redirects blocked rather than followed;
- selected request and response headers only;
- text and JSON responses only;
- exact credential redaction in response bodies, selected response headers, and broker errors;
- capability and credential redaction if the child prints them through piped stdout or stderr; and
- vault expiry, target, and `process.start` action checks before broker startup.

## Remaining risks

- The policy determines where the credential is sent. An attacker able to replace trusted policy files can redirect future broker runs.
- The authorized upstream receives the real credential.
- A prompt-injected or hostile child can perform any operation that the allowed HTTP methods, paths, request bodies, and upstream account permissions permit. Keep each policy and upstream credential narrowly scoped.
- The broker process holds the decrypted credential in memory for its lifetime.
- DNS, certificate authorities, the upstream service, Node.js, and the host OS remain trusted dependencies.
- There is no transparent support for database, SSH, RDP, Kubernetes, arbitrary TCP, streaming, or binary protocols.
- Output filtering does not cover direct terminal-device writes, files, IPC, debuggers, or unrelated processes.
