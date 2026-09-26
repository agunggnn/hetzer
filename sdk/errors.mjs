export const SDK_ERROR_CODES = Object.freeze({
    INVALID_CONFIG: "ERR_SDK_INVALID_CONFIG",
    INVALID_CREDENTIAL_ID: "ERR_CREDENTIAL_ID_INVALID",
    INVALID_REFERENCE: "ERR_CREDENTIAL_REFERENCE_INVALID",
    NOT_FOUND: "ERR_CREDENTIAL_NOT_FOUND",
    TARGET_MISMATCH: "ERR_CREDENTIAL_TARGET_MISMATCH",
    NOT_ALLOWED: "ERR_CREDENTIAL_NOT_ALLOWED",
    EXPIRED: "ERR_CREDENTIAL_EXPIRED",
});

export class HetzerSdkError extends Error {
    constructor(code, message, options = {}) {
        super(message, options.cause ? { cause: options.cause } : undefined);
        this.name = "HetzerSdkError";
        this.code = code;
    }
}

export function invalidSdkConfig(message, options = {}) {
    return new HetzerSdkError(SDK_ERROR_CODES.INVALID_CONFIG, message, options);
}

export function invalidCredentialId(message = "credential id must use lowercase kebab-case.") {
    return new HetzerSdkError(SDK_ERROR_CODES.INVALID_CREDENTIAL_ID, message);
}

export function invalidCredentialReference(message = "credential reference must use secretRef:<credential-id>.") {
    return new HetzerSdkError(SDK_ERROR_CODES.INVALID_REFERENCE, message);
}
