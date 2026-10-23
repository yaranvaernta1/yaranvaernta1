const crypto = require('crypto');

// ═══════════════════════════════════════════════════════════════════
// CONFIG — static. JANGAN taruh rng/token di sini (Netlify warm reuse).
// ═══════════════════════════════════════════════════════════════════
const CONFIG = {
    // 'always_ok' : semua user_key diterima
    // 'mirror'    : hanya validKeys yang diterima
    mode: 'not_ok',

    validKeys: ['tele@asylumfoundation_'],

    // SALT dari payload MD5_Update real (15 char, TANPA 's' ekstra)
    tokenSalt: 'jsah39043kasdsfd',

    // Metadata response (statis)
    chronos: {
        // title:    'Coop Mod',
        title: 'AsylumFoundationPresident',
        subtitle: 'v2.2.16.12322',
        expired:  '3000-12-31',
        btdata: 'm_bInTeamBattle'
    },

    // Timeout request (opsional)
    maxBodyBytes: 64 * 1024,
};

// ═══════════════════════════════════════════════════════════════════
// Helper
// ═══════════════════════════════════════════════════════════════════
function jsonResp(status, headers, body) {
    return {
        statusCode: status,
        headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
            ...headers,
        },
        body: JSON.stringify(body),
    };
}

function getHeader(headers, ...names) {
    for (const name of names) {
        if (headers[name]) return headers[name];
    }
    // fallback case-insensitive
    const lower = Object.keys(headers).reduce((acc, k) => {
        acc[k.toLowerCase()] = headers[k];
        return acc;
    }, {});
    for (const name of names) {
        const v = lower[name.toLowerCase()];
        if (v) return v;
    }
    return '';
}

function log(reqId, ...args) {
    console.log(`[${reqId}]`, ...args);
}

// ═══════════════════════════════════════════════════════════════════
// Handler
// ═══════════════════════════════════════════════════════════════════
exports.handler = async (event) => {
    const reqId = crypto.randomBytes(4).toString('hex');
    const t0 = Date.now();

    log(reqId, '═══════════════════════════════════════');
    log(reqId, 'method =', event.httpMethod, 'path =', event.path);

    // ── CORS preflight ──────────────────────────────────────────
    if (event.httpMethod === 'OPTIONS') {
        return jsonResp(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Public-Key, User-Agent',
        }, '');
    }
    if (event.httpMethod !== 'POST') {
        return jsonResp(405, {}, { error: 'Method Not Allowed' });
    }

    try {
        // ═══════════════════════════════════════════════════════
        // 1. Public-Key header
        // ═══════════════════════════════════════════════════════
        const headers   = event.headers || {};
        const pubKeyB64 = getHeader(headers, 'public-key', 'Public-Key', 'PUBLIC-KEY');
        if (!pubKeyB64) {
            log(reqId, 'ERROR: missing Public-Key');
            return jsonResp(400, {}, { error: 'Missing Public-Key header' });
        }

        const publicKeyPem = Buffer.from(pubKeyB64, 'base64').toString('utf8');
        if (!publicKeyPem.includes('BEGIN PUBLIC KEY')) {
            log(reqId, 'ERROR: invalid Public-Key (not PEM)');
            return jsonResp(400, {}, { error: 'Invalid Public-Key (not PEM)' });
        }

        // ═══════════════════════════════════════════════════════
        // 2. Parse body
        // ═══════════════════════════════════════════════════════
        if (event.body && event.body.length > CONFIG.maxBodyBytes) {
            log(reqId, 'ERROR: body too large');
            return jsonResp(413, {}, { error: 'Payload too large' });
        }

        let body;
        try {
            body = JSON.parse(event.body || '{}');
        } catch (e) {
            log(reqId, 'ERROR: invalid JSON:', e.message);
            return jsonResp(400, {}, { error: 'Invalid JSON' });
        }

        const d       = body.data || {};
        const userKey = d.user_key || '';
        const serial  = d.serial   || '';
        const nonce   = d.nonce    || '';
        const version = d.version  || '';

        if (!serial) {
            log(reqId, 'ERROR: missing serial');
            return jsonResp(400, {}, { error: 'Missing serial in body.data' });
        }

        // ═══════════════════════════════════════════════════════
        // 3. Nonce untuk MD5 = User-Agent (dari payload real)
        // ═══════════════════════════════════════════════════════
        const uaForToken = getHeader(headers, 'user-agent', 'User-Agent', 'USER-AGENT');
        if (!uaForToken) {
            log(reqId, 'WARNING: User-Agent kosong, token MD5 akan mismatch');
        }

        // ═══════════════════════════════════════════════════════
        // 4. Cek allowed (always_ok / mirror)
        // ═══════════════════════════════════════════════════════
        const allowed = CONFIG.mode === 'always_ok' || userKey.startsWith("tele@asylumfoundation_");

        // ═══════════════════════════════════════════════════════
        // 5. Token MD5 dinamis
        //    Formula: MD5( user_key + serial + salt + nonce )
        // ═══════════════════════════════════════════════════════
        const tokenPayload = `${userKey}${serial}${CONFIG.tokenSalt}${uaForToken}`;
        const token = crypto.createHash('md5').update(tokenPayload).digest('hex');

        // ═══════════════════════════════════════════════════════
        // 6. Susun JSON response (rng per request)
        // ═══════════════════════════════════════════════════════
        const rng = Math.floor(Date.now() / 1000);

        const respObj = allowed
            ? {
                status: true,
                data: {
                    token,
                    instance: 'chronos-instance-' + crypto.randomBytes(6).toString('hex'),
                    title:    CONFIG.chronos.title,
                    subtitle: CONFIG.chronos.subtitle,
                    expired:  CONFIG.chronos.expired,
                    btdata: CONFIG.chronos.btdata,
                    rng,
                },
            }
            : {
                status: false,
                reason: 'Key must starts with tele@asylumfoundation_ inside',
                data: { rng },
            };

        // ═══════════════════════════════════════════════════════
        // 7. AES-128-CBC encrypt
        // ═══════════════════════════════════════════════════════
        const aesKey    = crypto.randomBytes(16);
        const iv        = crypto.randomBytes(16);
        const plaintext = JSON.stringify(respObj);
        const cipher    = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
        const ed        = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);

        // ═══════════════════════════════════════════════════════
        // 8. RSA-OAEP-SHA1 encrypt AES key
        // ═══════════════════════════════════════════════════════
        const eak = crypto.publicEncrypt(
            {
                key: publicKeyPem,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha1',
            },
            aesKey
        );

        const ivB64  = iv.toString('base64');
        const edB64  = ed.toString('base64');
        const eakB64 = eak.toString('base64');

        // ═══════════════════════════════════════════════════════
        // 9. HMAC-SHA256 atas B64 CONCAT (bukan raw!)
        // ═══════════════════════════════════════════════════════
        const hmacHex = crypto
            .createHmac('sha256', aesKey)
            .update(ivB64 + edB64 + eakB64)
            .digest('hex');
        const hmacB64 = Buffer.from(hmacHex).toString('base64');

        // ═══════════════════════════════════════════════════════
        // 10. Build response
        // ═══════════════════════════════════════════════════════
        const response = {
            iv:                ivB64,
            encrypted_data:    edB64,
            encrypted_aes_key: eakB64,
            hmac:              hmacB64,
        };

        // ═══════════════════════════════════════════════════════
        // Debug mode (?debug=1)
        // ═══════════════════════════════════════════════════════
        const debug = event.queryStringParameters?.debug === '1';
        if (debug) {
            response._debug = {
                user_key:      userKey,
                serial,
                ua_for_token:  uaForToken,
                nonce_body:    nonce,
                version,
                token_payload: tokenPayload,
                token,
                rng,
                allowed,
                mode:          CONFIG.mode,
                plaintext:     plaintext,
                aes_key_hex:   aesKey.toString('hex'),
                iv_hex:        iv.toString('hex'),
                hmac_hex:      hmacHex,
                elapsed_ms:    Date.now() - t0,
            };
        }

        // ═══════════════════════════════════════════════════════
        // Log summary
        // ═══════════════════════════════════════════════════════
        log(reqId, '┌─ RESULT ─────────────────────────────');
        log(reqId, '│ mode      :', CONFIG.mode);
        log(reqId, '│ user_key  :', userKey);
        log(reqId, '│ serial    :', serial.slice(0, 16) + '...');
        log(reqId, '│ UA used   :', uaForToken || '(empty)');
        log(reqId, '│ token     :', token);
        log(reqId, '│ rng       :', rng);
        log(reqId, '│ allowed   :', allowed);
        log(reqId, '│ status    :', respObj.status);
        log(reqId, '│ pt size   :', Buffer.byteLength(plaintext), 'B');
        log(reqId, '│ hmac      :', hmacHex.slice(0, 16) + '...');
        log(reqId, '│ elapsed   :', Date.now() - t0, 'ms');
        log(reqId, '└──────────────────────────────────────');

        return jsonResp(200, {}, response);

    } catch (err) {
        console.error(`[${reqId}] FATAL:`, err);
        return jsonResp(500, {}, { error: err.message || 'Internal error' });
    }
};
