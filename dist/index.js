"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.configure = void 0;
exports.checkInputFast = checkInputFast;
exports.checkInputModeration = checkInputModeration;
exports.checkInput = checkInput;
exports.checkOutput = checkOutput;
const config_1 = require("./config");
Object.defineProperty(exports, "configure", { enumerable: true, get: function () { return config_1.configure; } });
const moderation_1 = require("./moderation");
const secrets_1 = require("./secrets");
const injection_1 = require("./injection");
const INPUT_REFUSAL = "I'm not able to help with that message. Could you rephrase what you're looking for?";
const OUTPUT_REFUSAL = "I'm unable to respond to that request. Could you try asking in a different way?";
function log(cfg, stage, guardType, reason, preview) {
    cfg.logger?.warn('[heimdall] ' + stage + ' blocked', {
        guardType,
        reason,
        preview,
    });
}
function checkInputFast(text) {
    const cfg = (0, config_1.getConfig)();
    const secretsResult = (0, secrets_1.checkSecrets)(text);
    const injectionResult = (0, injection_1.checkInjection)(text);
    const blocked = secretsResult.flagged
        ? { type: 'secrets', reason: secretsResult.reason }
        : injectionResult.flagged
            ? { type: 'injection', reason: injectionResult.reason }
            : null;
    if (blocked) {
        log(cfg, 'input', blocked.type, blocked.reason, text.slice(0, 200));
        return { blocked: true, reason: INPUT_REFUSAL };
    }
    return { blocked: false };
}
async function checkInputModeration(text) {
    const cfg = (0, config_1.getConfig)();
    const modResult = await (0, moderation_1.checkModeration)(text, cfg.moderationApiKey)
        .catch(() => ({ flagged: false, reason: undefined }));
    if (modResult.flagged) {
        log(cfg, 'input', 'moderation', modResult.reason, text.slice(0, 200));
        return { blocked: true, reason: INPUT_REFUSAL };
    }
    return { blocked: false };
}
async function checkInput(text) {
    const cfg = (0, config_1.getConfig)();
    const apiKey = cfg.moderationApiKey;
    const [modResult, secretsResult, injectionResult] = await Promise.all([
        (0, moderation_1.checkModeration)(text, apiKey).catch(() => ({ flagged: false, reason: undefined })),
        Promise.resolve((0, secrets_1.checkSecrets)(text)),
        Promise.resolve((0, injection_1.checkInjection)(text)),
    ]);
    const blocked = modResult.flagged
        ? { type: 'moderation', reason: modResult.reason }
        : secretsResult.flagged
            ? { type: 'secrets', reason: secretsResult.reason }
            : injectionResult.flagged
                ? { type: 'injection', reason: injectionResult.reason }
                : null;
    if (blocked) {
        log(cfg, 'input', blocked.type, blocked.reason, text.slice(0, 200));
        return { blocked: true, reason: INPUT_REFUSAL };
    }
    return { blocked: false };
}
async function checkOutput(text) {
    const cfg = (0, config_1.getConfig)();
    const apiKey = cfg.moderationApiKey;
    const [modResult, secretsResult] = await Promise.all([
        (0, moderation_1.checkModeration)(text, apiKey).catch(() => ({ flagged: false, reason: undefined })),
        Promise.resolve((0, secrets_1.checkSecrets)(text)),
    ]);
    const blocked = modResult.flagged
        ? { type: 'moderation', reason: modResult.reason }
        : secretsResult.flagged
            ? { type: 'secrets', reason: secretsResult.reason }
            : null;
    if (blocked) {
        log(cfg, 'output', blocked.type, blocked.reason, text.slice(0, 200));
        return { blocked: true, reason: OUTPUT_REFUSAL };
    }
    return { blocked: false };
}
//# sourceMappingURL=index.js.map