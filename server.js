const path = require("node:path");
require("dotenv").config({ path: path.join(__dirname, ".env") });

const dns = require("node:dns");
const tls = require("node:tls");
// Prefer IPv4 first because some local networks/hosts reject outbound SMTP over IPv6.
dns.setDefaultResultOrder("ipv4first");


const express = require("express");
const crypto = require("crypto");
const session = require("express-session");
const bcrypt = require("bcrypt");
const fs = require("fs");
const nodemailer = require("nodemailer");
const multer = require("multer");
const { GoogleAIFileManager } = require("@google/generative-ai/server");



const app = express();

// Netlify runs each request in a short-lived function. Persistent records must live
// in Netlify Blobs; direct `npm start` keeps the simple local filesystem store.
const IS_NETLIFY = String(process.env.NETLIFY || "").toLowerCase() === "true";
let blobsApi = null;
function getBlobStore(name) {
    if (!IS_NETLIFY) return null;
    if (!blobsApi) blobsApi = require("@netlify/blobs");
    return blobsApi.getStore({ name, region: "ap-southeast-1", consistency: "strong" });
}
const userBlobStore = IS_NETLIFY ? getBlobStore("omnimun-users") : null;
const mediaBlobStore = IS_NETLIFY ? getBlobStore("omnimun-media") : null;
const fileBlobStore = IS_NETLIFY ? getBlobStore("omnimun-uploads") : null;

class NetlifyBlobSessionStore extends session.Store {
    constructor() {
        super();
        this.store = getBlobStore("omnimun-sessions");
    }
    get(sid, callback) {
        this.store.get(sid, { type: "json" }).then(value => {
            if (!value) return callback(null, null);
            const expiry = value.cookie?.expires ? new Date(value.cookie.expires).getTime() : 0;
            if (expiry && expiry <= Date.now()) {
                return this.store.delete(sid).then(() => callback(null, null), callback);
            }
            callback(null, value);
        }).catch(callback);
    }
    set(sid, value, callback = () => {}) {
        this.store.setJSON(sid, value).then(() => callback()).catch(callback);
    }
    touch(sid, value, callback = () => {}) {
        this.set(sid, value, callback);
    }
    destroy(sid, callback = () => {}) {
        this.store.delete(sid).then(() => callback()).catch(callback);
    }
}

function serializeGenerationJob(job) {
    return {
        requestId: job.requestId, owner: job.owner, kind: job.kind, model: job.model,
        status: job.status, createdAt: job.createdAt, finishedAt: job.finishedAt || null,
        result: job.result || null, error: job.error || null, options: job.options || null
    };
}

async function persistGenerationJob(job) {
    if (!IS_NETLIFY || !mediaBlobStore || !job?.requestId) return;
    await mediaBlobStore.setJSON(`job:${job.requestId}`, serializeGenerationJob(job));
}

async function readGenerationJob(requestId) {
    if (IS_NETLIFY) return mediaBlobStore.get(`job:${requestId}`, { type: "json" });
    return generationJobs.get(requestId) || null;
}

async function saveGeneratedMedia(filename, buffer, contentType, owner) {
    if (IS_NETLIFY) {
        await mediaBlobStore.set(`generated:${filename}`, buffer, {
            metadata: { owner: String(owner || ""), contentType: String(contentType || "application/octet-stream"), createdAt: String(Date.now()) }
        });
    } else {
        await fs.promises.writeFile(path.join(GENERATED_MEDIA_DIR, filename), buffer, { mode: 0o600 });
        generatedMediaOwners.set(filename, String(owner || ""));
    }
}

async function setUploadOwner(id, owner) {
    if (IS_NETLIFY) await fileBlobStore.setJSON(`upload:${id}`, { owner: String(owner || ""), createdAt: Date.now() });
    else mediaOwners.set(id, String(owner || ""));
}

async function getUploadOwner(id) {
    if (IS_NETLIFY) {
        const value = await fileBlobStore.get(`upload:${id}`, { type: "json" });
        return value?.owner || null;
    }
    return mediaOwners.get(id) || null;
}

async function deleteUploadOwner(id) {
    if (IS_NETLIFY) return fileBlobStore.delete(`upload:${id}`);
    mediaOwners.delete(id);
}

if (process.env.NODE_ENV === "production" && !process.env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET wajib diatur pada environment production.");
}
if (process.env.NODE_ENV === "production" || IS_NETLIFY) {
    // Dibutuhkan agar secure session cookie tetap bekerja di belakang reverse proxy HTTPS.
    app.set("trust proxy", 1);
}

app.disable("x-powered-by");
app.use((req, res, next) => {
    res.set("X-Content-Type-Options", "nosniff");
    res.set("X-Frame-Options", "DENY");
    res.set("Referrer-Policy", "strict-origin-when-cross-origin");
    res.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    next();
});

// ==========================
// BASIC SETUP
// ==========================


app.use(express.json({

    limit:"20mb"

}));


app.use(express.urlencoded({

    extended:true

}));



// Static pages are mounted after the private generated-media route below.
// This prevents stale files in public/generated from bypassing ownership checks.

// ==========================
// SESSION
// ==========================


app.use(session({
    ...(IS_NETLIFY ? { store: new NetlifyBlobSessionStore() } : {}),
    secret: process.env.SESSION_SECRET || "omnimun-local-development-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        path: "/",
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}));

function requireAuth(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({
            success: false,
            error: "Silakan login dulu"
        });
    }
    next();
}

// Basic per-IP throttling for endpoints that are commonly abused.
// This is intentionally dependency-free; use a shared store for multi-instance deployments.
const rateLimitStore = new Map();
function rateLimit({ windowMs, max, message }) {
    return (req, res, next) => {
        const now = Date.now();
        const ip = req.ip || req.socket?.remoteAddress || "unknown";
        const key = `${ip}:${req.baseUrl || ""}${req.path}`;
        let bucket = rateLimitStore.get(key);
        if (!bucket || bucket.resetAt <= now) {
            bucket = { count: 0, resetAt: now + windowMs };
            rateLimitStore.set(key, bucket);
        }
        bucket.count += 1;

        if (rateLimitStore.size > 5000) {
            for (const [storedKey, storedBucket] of rateLimitStore) {
                if (storedBucket.resetAt <= now) rateLimitStore.delete(storedKey);
            }
        }

        if (bucket.count > max) {
            res.set("Retry-After", String(Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))));
            return res.status(429).json({ success: false, error: message });
        }
        next();
    };
}

const registrationRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: "Terlalu banyak percobaan pendaftaran dari jaringan ini. Coba lagi dalam 15 menit."
});
const loginRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: "Terlalu banyak percobaan login. Tunggu 15 menit sebelum mencoba lagi."
});

// ==========================
// FILE UPLOAD SYSTEM
// ==========================


const UPLOAD_DIR = IS_NETLIFY ? (process.env.TMPDIR || "/tmp") : path.join(__dirname, "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
    dest: UPLOAD_DIR,
    limits: { fileSize: 20 * 1024 * 1024 }
});

// ID file bersifat acak; map ini membatasi penghapusan ke pemilik sesi yang mengunggahnya.
const mediaOwners = new Map();


// ==========================
 // GEMINI VISION + THINKING
// ==========================

/**
 * Normalize model values copied into .env. The REST endpoint already adds
 * /models/, so values like "models/gemini-3.8-flash" must be stripped first.
 */
function normalizeGeminiModel(value, defaultModel) {
    const original = String(value || "").trim();
    if (!original) return defaultModel;

    let model = original.replace(/^(["'])|(["'])$/g, "").trim();
    if (/^https?:\/\//i.test(model)) {
        try {
            const parsed = new URL(model);
            const match = parsed.pathname.match(/\/models\/([^/:?#]+)/i);
            if (match) model = match[1];
        } catch {
            // Invalid URLs are handled by validation below.
        }
    }
    model = model.replace(/^models\//i, "").replace(/:generateContent$/i, "").trim();

    if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(model)) {
        console.warn(`[Gemini] Format model "${original}" tidak valid; memakai ${defaultModel}.`);
        return defaultModel;
    }
    return model;
}

const configuredGeminiModel = normalizeGeminiModel(process.env.GEMINI_MODEL, "gemini-3.8-flash");
// Redirect the previous Argon configuration to Flash as requested.
const GEMINI_MODEL = configuredGeminiModel.toLowerCase() === "gemini-4-argon"
    ? "gemini-3.8-flash"
    : configuredGeminiModel;

const configuredFallbackModel = normalizeGeminiModel(
    process.env.GEMINI_FALLBACK_MODEL,
    "gemini-3.6-flash"
);
const GEMINI_FALLBACK_MODEL =
    configuredFallbackModel.toLowerCase() === "gemini-4-argon" || configuredFallbackModel === GEMINI_MODEL
        ? "gemini-3.6-flash"
        : configuredFallbackModel;

const requestedThinkingLevel = String(process.env.GEMINI_THINKING_LEVEL || "high").toLowerCase();
const GEMINI_THINKING_LEVEL = ["low", "medium", "high"].includes(requestedThinkingLevel)
    ? requestedThinkingLevel
    : "high";

const fileManager = process.env.GEMINI_API_KEY
    ? new GoogleAIFileManager(process.env.GEMINI_API_KEY)
    : null;

function isGeminiTransientError(status, message) {
    return [500, 502, 503, 504].includes(Number(status)) ||
        /high demand|overload(?:ed)?|temporarily unavailable|service unavailable|backend error|try again later|capacity exhausted/i.test(String(message || ""));
}

function friendlyGeminiError(status, message, model) {
    const raw = String(message || "");
    if (/unexpected model name format|invalid.*model name|model.*name.*format/i.test(raw)) {
        return `Format nama model Gemini "${model}" tidak valid. Gunakan ID model saja, misalnya gemini-3.8-flash. Awalan "models/" dibersihkan otomatis; periksa GEMINI_MODEL di .env.`;
    }
    if (status === 429 || /quota|limit:\s*0|resource_exhausted|too many requests/i.test(raw)) {
        return `Kuota Gemini untuk model ${model} tidak tersedia atau sudah habis. Periksa kuota dan billing di Google AI Studio. Model cadangan yang dikonfigurasi: ${GEMINI_FALLBACK_MODEL}.`;
    }
    if (status === 404 || /model.*not found|not found.*model/i.test(raw)) {
        return `Model Gemini "${model}" tidak ditemukan atau tidak tersedia untuk project ini. Pilih ID model yang tersedia di Google AI Studio.`;
    }
    if (status === 403 || /permission denied|permission_denied|api key.*invalid|unauthorized/i.test(raw)) {
        return "Gemini menolak akses API. Periksa GEMINI_API_KEY, project Google AI Studio, dan status billing.";
    }
    if (isGeminiTransientError(status, raw)) {
        return `Layanan Gemini sedang padat atau sementara tidak tersedia (model ${model}). Server sudah mencoba ulang dan menggunakan model cadangan jika tersedia. Tunggu sebentar lalu coba lagi.`;
    }
    return "Gemini gagal memproses permintaan. Detail teknis tersedia di terminal server.";
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Call Gemini Generate Content REST API. Retry transient service errors once,
 * then try the configured fallback model for quota/model/availability errors.
 */
async function generateGeminiText(contents, systemInstruction, options = {}) {
    if (!process.env.GEMINI_API_KEY) {
        const error = new Error("GEMINI_API_KEY belum diatur di file .env.");
        error.statusCode = 503;
        error.userMessage = error.message;
        throw error;
    }

    const instruction = typeof systemInstruction === "string" && systemInstruction.trim()
        ? systemInstruction.trim()
        : SYSTEM;
    const models = [...new Set([GEMINI_MODEL, GEMINI_FALLBACK_MODEL].filter(Boolean))];
    const callerSignal = options.signal;
    const timeoutMs = Math.min(30000, Math.max(5000, Number(options.timeoutMs) || 22000));
    let lastFailure = null;

    for (let index = 0; index < models.length; index++) {
        if (callerSignal?.aborted) {
            const cancelled = new Error("Permintaan dibatalkan oleh pengguna.");
            cancelled.statusCode = 499;
            cancelled.userMessage = cancelled.message;
            throw cancelled;
        }

        const model = models[index];
        const controller = new AbortController();
        const abortFromCaller = () => controller.abort("client-disconnected");

        if (callerSignal) {
            callerSignal.addEventListener("abort", abortFromCaller, { once: true });
        }

        const timer = setTimeout(() => controller.abort("timeout"), timeoutMs);
        let response;
        let data;

        try {
            response = await fetch(
                `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "x-goog-api-key": process.env.GEMINI_API_KEY
                    },
                    body: JSON.stringify({
                        contents,
                        systemInstruction: { parts: [{ text: instruction }] },
                        generationConfig: {
                            maxOutputTokens: Number.isInteger(options.maxOutputTokens)
                                ? options.maxOutputTokens
                                : 4096,
                            thinkingConfig: { thinkingLevel: GEMINI_THINKING_LEVEL }
                        }
                    }),
                    signal: controller.signal
                }
            );
            data = await response.json().catch(() => ({}));
        } catch (networkError) {
            if (callerSignal?.aborted) {
                const cancelled = new Error("Permintaan dibatalkan oleh pengguna.");
                cancelled.statusCode = 499;
                cancelled.userMessage = cancelled.message;
                throw cancelled;
            }

            const timedOut = controller.signal.aborted && controller.signal.reason === "timeout";
            const message = timedOut
                ? `Model ${model} tidak merespons dalam ${Math.round(timeoutMs / 1000)} detik.`
                : (networkError.message || "Tidak dapat terhubung ke Gemini API.");

            lastFailure = { status: timedOut ? 504 : 502, message, model };
            console.warn(`[Gemini] ${message} ${index < models.length - 1 ? `Mencoba model cadangan ${models[index + 1]}.` : ""}`);
            continue;
        } finally {
            clearTimeout(timer);
            if (callerSignal) callerSignal.removeEventListener("abort", abortFromCaller);
        }

        if (!response.ok) {
            const message = data?.error?.message || `Gemini API mengembalikan HTTP ${response.status}.`;
            const modelNameFormatError = /unexpected model name format|invalid.*model name|model.*name.*format/i.test(message);
            const transient = isGeminiTransientError(response.status, message);
            lastFailure = { status: response.status, message, model };

            const retryable = [400, 404, 429, 500, 502, 503, 504].includes(response.status) &&
                (response.status !== 400 || modelNameFormatError);

            if (index < models.length - 1 && (
                retryable ||
                /quota|limit:\s*0|resource_exhausted|model.*not found|high demand/i.test(message)
            )) {
                console.warn(`[Gemini] Model ${model} gagal (HTTP ${response.status}); langsung beralih ke ${models[index + 1]}. Detail: ${message}`);
                continue;
            }

            const error = new Error(message);
            error.statusCode = response.status === 429 ? 429
                : response.status === 403 ? 403
                : response.status === 404 ? 404
                : response.status === 400 && modelNameFormatError ? 400
                : transient ? 503
                : 502;
            error.userMessage = transient && index === models.length - 1
                ? "Gemini sedang sibuk atau merespons terlalu lama. Model utama dan cadangan sudah dicoba. Coba lagi beberapa saat nanti."
                : friendlyGeminiError(response.status, message, model);
            throw error;
        }

        const parts = data?.candidates?.[0]?.content?.parts || [];
        const output = parts
            .filter(part => typeof part?.text === "string" && part.thought !== true)
            .map(part => part.text)
            .join("")
            .trim();

        if (output) {
            if (model !== GEMINI_MODEL) {
                console.warn(`[Gemini] Berhasil menggunakan model cadangan ${model}.`);
            }
            return output;
        }

        const blockReason = data?.promptFeedback?.blockReason;
        const message = blockReason
            ? `Permintaan tidak dapat diproses oleh Gemini (${blockReason}).`
            : "Gemini tidak mengembalikan teks.";
        lastFailure = { status: 502, message, model };

        if (index < models.length - 1) {
            console.warn(`[Gemini] Model ${model} tidak mengembalikan teks; mencoba model cadangan ${models[index + 1]}.`);
            continue;
        }

        const error = new Error(message);
        error.statusCode = 502;
        error.userMessage = message;
        throw error;
    }

    const failure = lastFailure || {
        status: 503,
        message: "Kedua model Gemini gagal merespons.",
        model: GEMINI_MODEL
    };
    const error = new Error(failure.message);
    error.statusCode = failure.status === 429 ? 429
        : failure.status === 403 ? 403
        : failure.status === 404 ? 404
        : failure.status === 504 ? 504
        : isGeminiTransientError(failure.status, failure.message) ? 503
        : 502;

    if (error.statusCode === 504 || error.statusCode === 503) {
        error.userMessage = "Gemini sedang sibuk atau merespons terlalu lama. Model utama dan cadangan sudah dicoba. Coba lagi beberapa saat nanti.";
    } else {
        error.userMessage = friendlyGeminiError(failure.status, failure.message, failure.model);
    }
    throw error;
}

async function analyzeWithGeminiFile(file, prompt) {
    if (!fileManager) {
        const error = new Error("GEMINI_API_KEY belum diatur di file .env.");
        error.statusCode = 503;
        throw error;
    }

    let uploadedFile;
    try {
        const uploadResult = await fileManager.uploadFile(file.path, {
            mimeType: file.mimetype,
            displayName: file.originalname
        });
        uploadedFile = uploadResult.file;

        let readyFile = uploadedFile;
        const deadline = Date.now() + 120000;
        while (readyFile.state === "PROCESSING" && Date.now() < deadline) {
            await new Promise(resolve => setTimeout(resolve, 2000));
            readyFile = await fileManager.getFile(readyFile.name);
        }

        if (readyFile.state === "FAILED") {
            throw new Error("Gemini gagal memproses file yang diunggah.");
        }
        if (readyFile.state && readyFile.state !== "ACTIVE") {
            throw new Error("File belum siap diproses oleh Gemini. Silakan coba lagi.");
        }

        return await generateGeminiText(
            [{
                role: "user",
                parts: [
                    {
                        fileData: {
                            mimeType: readyFile.mimeType || file.mimetype,
                            fileUri: readyFile.uri
                        }
                    },
                    { text: prompt }
                ]
            }],
            SYSTEM,
            { maxOutputTokens: 8192 }
        );
    } finally {
        if (uploadedFile?.name && fileManager) {
            try {
                await fileManager.deleteFile(uploadedFile.name);
            } catch (cleanupError) {
                console.warn("Gagal menghapus file sementara di Gemini:", cleanupError.message);
            }
        }
    }
}

// ==========================
// GEMINI IMAGE / VIDEO GENERATION
// ==========================

const GEMINI_IMAGE_MODEL = normalizeGeminiModel(process.env.GEMINI_IMAGE_MODEL, "gemini-nano-banana-2.1");
const GEMINI_VIDEO_MODEL = normalizeGeminiModel(process.env.GEMINI_VIDEO_MODEL, "gemini-omni-1.1-flash");
// Media generation is OFF by default because Gemini's current image/video API models
// do not include a free API tier. Enable only when the Google AI Studio project has
// the required paid-tier access: GEMINI_MEDIA_ENABLED=true
const GEMINI_MEDIA_ENABLED = String(process.env.GEMINI_MEDIA_ENABLED || "false").trim().toLowerCase() === "true";
const GENERATED_MEDIA_DIR = IS_NETLIFY ? path.join(process.env.TMPDIR || "/tmp", "omnimun-generated") : path.join(__dirname, "generated");
fs.mkdirSync(GENERATED_MEDIA_DIR, { recursive: true });
const generationJobs = new Map();
const generatedMediaOwners = new Map();

function currentSessionOwner(req) {
    return String(
        req.session?.user?.username ||
        req.session?.user?.email ||
        req.session?.user?.id ||
        ""
    );
}

// Generated media can contain private prompts or personal content, so it is not
// placed under the public static directory. The owning signed-in account is required.
app.get("/generated/:filename", requireAuth, async (req, res, next) => {
    const filename = String(req.params.filename || "");
    if (!/^[a-f0-9-]{36}\.(?:png|jpe?g|webp|mp4|webm)$/i.test(filename)) return res.status(404).end();
    try {
        if (IS_NETLIFY) {
            const entry = await mediaBlobStore.getWithMetadata(`generated:${filename}`, { type: "arrayBuffer" });
            if (!entry?.data || String(entry.metadata?.owner || "") !== currentSessionOwner(req)) return res.status(404).end();
            res.set("Cache-Control", "private, no-store");
            res.set("Content-Type", String(entry.metadata?.contentType || "application/octet-stream"));
            return res.send(Buffer.from(entry.data));
        }
        if (generatedMediaOwners.get(filename) !== currentSessionOwner(req)) return res.status(404).end();
        res.set("Cache-Control", "private, no-store");
        return res.sendFile(path.join(GENERATED_MEDIA_DIR, filename), err => { if (err && !res.headersSent) next(err); });
    } catch (error) { next(error); }
});

app.use(express.static(path.join(__dirname, "public")));

function mediaGenerationDisabledMessage(kind) {
    const mediaName = kind === "video" ? "video" : "gambar";
    const model = kind === "video" ? GEMINI_VIDEO_MODEL : GEMINI_IMAGE_MODEL;
    return `Mode gratis aktif: model Gemini ${model} untuk generate ${mediaName} tidak menyediakan free tier API. Fitur ini tidak mengirim request berbayar. Jika project Google AI Studio kamu sudah memiliki paid-tier access, tambahkan GEMINI_MEDIA_ENABLED=true ke .env lalu restart server. Kalau harus tetap gratis, generate media via API Gemini ini belum bisa diaktifkan.`;
}

function geminiMediaErrorMessage(status, data, kind, model) {
    const raw = String(data?.error?.message || data?.message || "").trim();
    const mediaName = kind === "video" ? "video" : "gambar";
    if (status === 401 || /api key.*invalid|invalid api key|unauthenticated/i.test(raw)) {
        return "Google Gemini menolak API key. Periksa GEMINI_API_KEY dan project Google AI Studio.";
    }
    if (status === 403 || status === 402 || /billing|paid tier|permission denied|permission_denied|not available on the free tier/i.test(raw)) {
        return `Google menolak akses generate ${mediaName} dengan model ${model}. Model media ini tidak menyediakan free tier API; periksa paid-tier access, billing, dan izin project Google AI Studio.`;
    }
    if (status === 429 || /quota|resource_exhausted|rate.?limit|too many requests/i.test(raw)) {
        return `Kuota atau batas request Gemini untuk model ${model} sudah tercapai. Periksa batas aktif di Google AI Studio sebelum mencoba lagi.`;
    }
    if (status === 404 || /model.*not found|not found.*model/i.test(raw)) {
        return `Model Gemini "${model}" tidak tersedia untuk project ini. Periksa ID model dan akses project di Google AI Studio.`;
    }
    if (status >= 500) {
        return `Layanan Gemini sedang bermasalah saat membuat ${mediaName}. Coba lagi nanti.`;
    }
    return raw ? `Gemini gagal membuat ${mediaName}: ${raw.slice(0, 450)}` : `Gemini gagal membuat ${mediaName} (HTTP ${status || "unknown"}). Periksa terminal server untuk detail.`;
}

function cleanupGeneratedMediaForJob(job) {
    if (job?.controller && job.status === "IN_PROGRESS" && !job.controller.signal.aborted) {
        job.controller.abort("job-pruned");
    }
    const urls = [
        ...(Array.isArray(job?.result?.images) ? job.result.images.map(item => item?.url) : []),
        job?.result?.video?.url
    ].filter(url => typeof url === "string" && url.startsWith("/generated/"));
    for (const url of urls) {
        const filename = path.basename(url);
        generatedMediaOwners.delete(filename);
        fs.promises.unlink(path.join(GENERATED_MEDIA_DIR, filename)).catch(err => {
            if (err.code !== "ENOENT") console.warn("Gagal membersihkan media lama:", err.message);
        });
    }
}

function pruneGenerationJobs() {
    const cutoff = Date.now() - 2 * 60 * 60 * 1000;
    for (const [id, job] of generationJobs) {
        if (job.createdAt < cutoff) {
            cleanupGeneratedMediaForJob(job);
            generationJobs.delete(id);
        }
    }
    while (generationJobs.size >= 100) {
        const oldest = generationJobs.keys().next().value;
        if (!oldest) break;
        cleanupGeneratedMediaForJob(generationJobs.get(oldest));
        generationJobs.delete(oldest);
    }
}

function safeGeneratedExtension(mimeType, kind) {
    const mime = String(mimeType || "").toLowerCase().split(";")[0].trim();
    if (kind === "video") return mime === "video/webm" ? ".webm" : ".mp4";
    if (mime === "image/jpeg") return ".jpg";
    if (mime === "image/webp") return ".webp";
    return ".png";
}

async function callGeminiMediaApi({ kind, model, body, timeoutMs, signal }) {
    if (!process.env.GEMINI_API_KEY) {
        const error = new Error("GEMINI_API_KEY belum diatur di file .env.");
        error.statusCode = 503;
        error.userMessage = error.message;
        throw error;
    }

    const controller = new AbortController();
    const abortFromJob = () => controller.abort(signal?.reason || "cancelled-by-user");
    if (signal?.aborted) abortFromJob();
    else signal?.addEventListener("abort", abortFromJob, { once: true });
    const timer = setTimeout(() => controller.abort("timeout"), timeoutMs);
    const endpoint = kind === "video"
        ? "https://generativelanguage.googleapis.com/v1beta/interactions"
        : `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;

    try {
        const response = await fetch(endpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "x-goog-api-key": process.env.GEMINI_API_KEY
            },
            body: JSON.stringify(body),
            signal: controller.signal
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            const error = new Error(geminiMediaErrorMessage(response.status, data, kind, model));
            error.statusCode = response.status === 429 ? 429 : response.status === 404 ? 404 : response.status === 403 || response.status === 402 ? 402 : 502;
            error.userMessage = error.message;
            throw error;
        }
        return data;
    } catch (err) {
        if (controller.signal.aborted && controller.signal.reason === "timeout") {
            const error = new Error(`Permintaan generate ${kind === "video" ? "video" : "gambar"} ke Gemini melewati batas waktu ${Math.round(timeoutMs / 60000)} menit. Tidak ada hasil yang dikembalikan; coba lagi nanti.`);
            error.statusCode = 504;
            error.userMessage = error.message;
            throw error;
        }
        if (controller.signal.aborted) {
            const error = new Error("Generasi dibatalkan oleh pengguna. Jika request sudah diproses Google, pembatalan tidak menjamin biaya dapat dihindari.");
            error.statusCode = 499;
            error.userMessage = error.message;
            throw error;
        }
        if (err?.userMessage) throw err;
        const error = new Error(`Tidak dapat terhubung ke Gemini untuk membuat ${kind === "video" ? "video" : "gambar"}: ${err?.message || "koneksi gagal"}`);
        error.statusCode = 502;
        error.userMessage = error.message;
        throw error;
    } finally {
        clearTimeout(timer);
        signal?.removeEventListener("abort", abortFromJob);
    }
}

async function generateGeminiImageFile(job, options) {
    const generationConfig = { responseModalities: ["IMAGE"] };
    const imageConfig = {};
    if (options.aspectRatio && options.aspectRatio !== "auto") imageConfig.aspectRatio = options.aspectRatio;
    if (options.resolution) imageConfig.imageSize = options.resolution;
    if (Object.keys(imageConfig).length) generationConfig.imageConfig = imageConfig;

    const data = await callGeminiMediaApi({
        kind: "image",
        model: job.model,
        timeoutMs: 3 * 60 * 1000,
        signal: job.controller?.signal,
        body: {
            contents: [{ role: "user", parts: [{ text: options.prompt }] }],
            generationConfig
        }
    });

    const parts = data?.candidates?.[0]?.content?.parts || [];
    const imagePart = parts.find(part => part?.inlineData?.data || part?.inline_data?.data);
    const imageData = imagePart?.inlineData?.data || imagePart?.inline_data?.data;
    const mimeType = imagePart?.inlineData?.mimeType || imagePart?.inline_data?.mime_type || "image/png";
    if (!imageData) {
        const reason = data?.promptFeedback?.blockReason
            ? `Permintaan gambar diblokir oleh pemeriksaan keamanan (${data.promptFeedback.blockReason}). Ubah prompt lalu coba lagi.`
            : "Gemini merespons tanpa data gambar. Coba ubah prompt atau periksa akses model.";
        throw new Error(reason);
    }

    const extension = safeGeneratedExtension(mimeType, "image");
    const filename = `${job.requestId}${extension}`;
    await saveGeneratedMedia(filename, Buffer.from(imageData, "base64"), mimeType, job.owner);
    return { images: [{ url: `/generated/${filename}`, contentType: mimeType }] };
}

async function generateGeminiVideoFile(job, options) {
    const targetDuration = Math.max(3, Math.min(10, Number(options.duration) || 5));
    const prompt = `${options.prompt}\n\nTarget duration: approximately ${targetDuration} seconds. Keep the action concise and cinematic.`;
    const data = await callGeminiMediaApi({
        kind: "video",
        model: job.model,
        timeoutMs: 8 * 60 * 1000,
        signal: job.controller?.signal,
        body: {
            model: job.model,
            input: prompt,
            response_format: {
                type: "video",
                aspect_ratio: options.aspectRatio === "9:16" ? "9:16" : "16:9",
                resolution: "720p"
            }
        }
    });

    const outputParts = (Array.isArray(data?.steps) ? data.steps : [])
        .filter(step => step?.type === "model_output")
        .flatMap(step => Array.isArray(step?.content) ? step.content : []);
    const videoPart = outputParts.find(part => part?.type === "video" && part?.data) ||
        (data?.output_video?.data ? { data: data.output_video.data, mime_type: data.output_video.mime_type } : null);
    if (!videoPart?.data) {
        const status = String(data?.status || "").toLowerCase();
        const detail = data?.error?.message || data?.message;
        throw new Error(detail || (status && status !== "completed"
            ? `Gemini mengembalikan status "${status}" tanpa data video. Coba lagi.`
            : "Gemini merespons tanpa data video. Periksa akses model dan coba lagi."));
    }

    const mimeType = videoPart.mime_type || videoPart.mimeType || "video/mp4";
    const extension = safeGeneratedExtension(mimeType, "video");
    const filename = `${job.requestId}${extension}`;
    await saveGeneratedMedia(filename, Buffer.from(videoPart.data, "base64"), mimeType, job.owner);
    return { video: { url: `/generated/${filename}`, contentType: mimeType } };
}

async function runGeminiMediaJob(job, options) {
    try {
        job.status = "IN_PROGRESS";
        await persistGenerationJob(job);
        job.result = job.kind === "image"
            ? await generateGeminiImageFile(job, options)
            : await generateGeminiVideoFile(job, options);
        job.status = "COMPLETED";
    } catch (err) {
        job.status = "FAILED";
        job.error = err?.userMessage || err?.message || "Gemini gagal membuat media.";
        console.error(`[Gemini media] ${job.kind} gagal (${job.model}):`, err?.message || err);
    } finally {
        job.finishedAt = Date.now();
        await persistGenerationJob(job);
    }
}

async function processNetlifyMediaJob(requestId) {
    if (!IS_NETLIFY) throw new Error("Background media processing hanya tersedia di Netlify.");
    const job = await readGenerationJob(requestId);
    if (!job || !job.options) throw new Error("Tugas generasi tidak ditemukan.");
    if (["COMPLETED", "FAILED"].includes(job.status)) return job;
    job.controller = new AbortController();
    await runGeminiMediaJob(job, job.options);
    return serializeGenerationJob(job);
}

async function submitGeminiGeneration({ kind, prompt, aspectRatio, resolution, duration, owner, baseUrl }) {
    if (!GEMINI_MEDIA_ENABLED) {
        const error = new Error(mediaGenerationDisabledMessage(kind));
        error.statusCode = 402;
        error.userMessage = error.message;
        throw error;
    }
    if (!process.env.GEMINI_API_KEY) {
        const error = new Error("GEMINI_API_KEY belum diatur di file .env.");
        error.statusCode = 503;
        error.userMessage = error.message;
        throw error;
    }

    const job = {
        requestId: crypto.randomUUID(), owner, kind,
        model: kind === "image" ? GEMINI_IMAGE_MODEL : GEMINI_VIDEO_MODEL,
        status: "IN_PROGRESS", createdAt: Date.now(), result: null, error: null,
        options: { prompt, aspectRatio, resolution, duration },
        controller: new AbortController()
    };
    if (IS_NETLIFY) {
        if (!process.env.MEDIA_JOB_SECRET) {
            const error = new Error("MEDIA_JOB_SECRET belum diatur di konfigurasi Netlify.");
            error.statusCode = 503;
            error.userMessage = error.message;
            throw error;
        }
        await persistGenerationJob(job);
        const siteOrigin = String(baseUrl || process.env.URL || process.env.DEPLOY_PRIME_URL || "").replace(/\/$/, "");
        if (!siteOrigin) {
            const error = new Error("URL situs Netlify tidak tersedia untuk menjalankan tugas media.");
            error.statusCode = 503;
            error.userMessage = error.message;
            throw error;
        }
        const dispatch = await fetch(`${siteOrigin}/.netlify/functions/generate-media-background`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "x-omnimun-job-secret": process.env.MEDIA_JOB_SECRET },
            body: JSON.stringify({ requestId: job.requestId })
        });
        if (!dispatch.ok && dispatch.status !== 202) {
            const error = new Error("Netlify gagal memulai proses generasi media. Periksa konfigurasi background function.");
            error.statusCode = 502;
            error.userMessage = error.message;
            job.status = "FAILED";
            job.error = error.message;
            await persistGenerationJob(job);
            throw error;
        }
    } else {
        pruneGenerationJobs();
        generationJobs.set(job.requestId, job);
        setImmediate(() => runGeminiMediaJob(job, job.options));
    }
    return job;
}

// ==========================
// GMAIL SYSTEM
// ==========================


const configuredSmtpPort = Number.parseInt(process.env.SMTP_PORT || "587", 10);
const smtpPort = Number.isInteger(configuredSmtpPort) && configuredSmtpPort > 0
    ? configuredSmtpPort
    : 587;
const smtpSecure = process.env.SMTP_SECURE
    ? process.env.SMTP_SECURE.toLowerCase() === "true"
    : smtpPort === 465;

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || "smtp.gmail.com",
    port: smtpPort,
    secure: smtpSecure,
    requireTLS: !smtpSecure,
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS
    },
    connectionTimeout: 20000,
    greetingTimeout: 20000,
    socketTimeout: 30000,
    tls: {
        minVersion: "TLSv1.2",
        // Keep certificate validation enabled. If your network/hosting uses TLS inspection,
        // provide its trusted root CA PEM file through SMTP_CA_CERT_PATH.
        ...(process.env.SMTP_CA_CERT_PATH
            ? {
                ca: [
                    ...tls.rootCertificates,
                    fs.readFileSync(
                        require("node:path").resolve(process.env.SMTP_CA_CERT_PATH),
                        "utf8"
                    )
                ]
            }
            : {})
    }
});

// ==========================
// OMNIMUN PREMIUM VERIFICATION EMAIL
// ==========================

function escapeEmailHtml(value = "") {
    return String(value).replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    }[char]));
}

async function sendVerificationEmail({ email, username, code, isResend = false }) {
    const safeName = escapeEmailHtml((username || "").trim() || "Omnimun User");
    const safeCode = String(code).replace(/\D/g, "").slice(0, 6);
    const subject = isResend
        ? "Your New Verification Code for Omnimun AI"
        : "Action Required: Verify Your Email Address for Omnimun AI";
    const previewText = isResend
        ? "Your new verification code is ready. Use it to complete the email verification process for your Omnimun AI account."
        : "Complete email verification to activate your Omnimun AI account and continue to your workspace.";

    const greeting = `Dear <strong style="color:#171717;">${safeName}</strong>,`;
    const introduction = isResend
        ? "A new verification code has been requested for your Omnimun AI account. To continue the email verification process, please enter the code provided below on the official verification page. For security purposes, use the most recently issued code."
        : "Thank you for registering with Omnimun AI. To help protect your account and confirm that this email address belongs to you, please complete the verification step below. After your email address has been verified, you can proceed to sign in and access your Omnimun AI workspace.";
    const actionTitle = isResend ? "Your replacement code is ready" : "Please verify your email address";
    const securityHeading = "Important security information";
    const unrequestedText = isResend
        ? "If you did not request a new verification code, you may safely disregard this message. Your account will not be verified by simply receiving this email; the code must be entered on the verification page."
        : "If you did not create an Omnimun AI account or initiate this request, you may safely disregard this email. No further action is required, and the email address will remain unverified unless the verification code is submitted.";
    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>${escapeEmailHtml(subject)}</title>
</head>
<body style="margin:0;padding:0;background:#f2f2f2;font-family:Arial,Helvetica,sans-serif;color:#151515;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">${previewText}</div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f2f2f2;padding:32px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:580px;background:#ffffff;border:1px solid #e6e6e6;border-radius:18px;overflow:hidden;">
          <tr>
            <td style="padding:27px 32px;background:#111111;color:#ffffff;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td style="font-size:18px;line-height:24px;font-weight:700;letter-spacing:.3px;">OMNIMUN <span style="font-weight:400;color:#bcbcbc;">AI</span></td>
                  <td align="right" style="font-size:10px;line-height:16px;letter-spacing:1.8px;color:#cfcfcf;">ACCOUNT SECURITY</td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:37px 32px 10px;">
              <div style="font-size:10px;line-height:16px;font-weight:700;letter-spacing:2px;color:#777777;text-transform:uppercase;">${isResend ? "VERIFICATION CODE REQUEST" : "WELCOME TO OMNIMUN AI"}</div>
              <h1 style="margin:13px 0 17px;font-size:28px;line-height:1.28;letter-spacing:-.55px;font-weight:700;color:#111111;">${actionTitle}</h1>
              <p style="margin:0 0 15px;font-size:15px;line-height:1.85;color:#555555;">${greeting}</p>
              <p style="margin:0;font-size:14px;line-height:1.9;color:#555555;">${introduction}</p>
            </td>
          </tr>
          <tr>
            <td style="padding:26px 32px 12px;">
              <div style="padding:25px 16px;background:#f7f7f7;border:1px solid #e7e7e7;border-radius:13px;text-align:center;">
                <div style="font-size:10px;line-height:16px;letter-spacing:2px;font-weight:700;color:#777777;">YOUR SIX-DIGIT VERIFICATION CODE</div>
                <div style="padding-top:12px;font-family:Consolas,Monaco,'Courier New',monospace;font-size:36px;line-height:46px;letter-spacing:8px;font-weight:700;color:#111111;">${safeCode}</div>
                <div style="padding-top:9px;font-size:12px;line-height:1.8;color:#777777;">Enter this code on the Omnimun AI email verification page to continue.</div>
              </div>
            </td>
          </tr>
          <tr>
            <td style="padding:20px 32px 30px;">
              <p style="margin:0 0 10px;font-size:13px;line-height:1.8;color:#333333;"><strong>${securityHeading}</strong></p>
              <p style="margin:0 0 13px;font-size:13px;line-height:1.9;color:#555555;">For your protection, please do not share this code with anyone. It is intended only for you and should be entered exclusively on the official Omnimun AI verification page. Anyone who obtains your code may be able to interfere with the security of your account.</p>
              <p style="margin:0 0 13px;font-size:13px;line-height:1.9;color:#555555;">${unrequestedText}</p>
              <p style="margin:0;font-size:13px;line-height:1.9;color:#555555;">Thank you for taking the time to complete this important security step. We appreciate your interest in Omnimun AI and look forward to providing you with a reliable and helpful workspace.</p>
            </td>
          </tr>
          <tr>
            <td style="padding:22px 32px;background:#fafafa;border-top:1px solid #ededed;">
              <p style="margin:0;font-size:11px;line-height:1.8;color:#888888;">This is an automated account-related message sent by Omnimun AI. Please do not reply to this email, as this mailbox is not monitored.</p>
              <p style="margin:11px 0 0;font-size:10px;line-height:1.7;letter-spacing:1.5px;color:#aaaaaa;">THINK · CREATE · DISCOVER</p>
            </td>
          </tr>
        </table>
        <p style="max-width:540px;margin:16px auto 0;font-size:10px;line-height:1.8;color:#999999;text-align:center;">This message was sent in connection with an account registration or email verification request for Omnimun AI. Please retain it only as needed for that purpose.</p>
      </td>
    </tr>
  </table>
</body>
</html>`;

    const text = [
        `Dear ${((username || "").trim() || "Omnimun User")},`,
        "",
        isResend
            ? "A new verification code has been requested for your Omnimun AI account. Please use the code below to continue the email verification process. For security purposes, use the most recently issued code."
            : "Thank you for registering with Omnimun AI. To help protect your account and confirm that this email address belongs to you, please complete the verification step using the code provided below. Once your email address has been verified, you can proceed to sign in and access your Omnimun AI workspace.",
        "",
        `YOUR SIX-DIGIT VERIFICATION CODE: ${safeCode}`,
        "",
        "Enter this code on the Omnimun AI email verification page to continue.",
        "",
        "IMPORTANT SECURITY INFORMATION",
        "For your protection, do not share this code with anyone. It is intended only for you and should be entered exclusively on the official Omnimun AI verification page.",
        "",
        isResend
            ? "If you did not request a new verification code, you may safely disregard this message. Your account will not be verified simply by receiving this email."
            : "If you did not create an Omnimun AI account or initiate this request, you may safely disregard this email. No further action is required, and the email address will remain unverified unless the code is submitted.",
        "",
        "Thank you for taking the time to complete this important security step. We appreciate your interest in Omnimun AI and look forward to providing you with a reliable and helpful workspace.",
        "",
        "This is an automated account-related message. Please do not reply to this email, as this mailbox is not monitored.",
        "",
        "OMNIMUN AI — THINK. CREATE. DISCOVER."
    ].join("\n");

    return transporter.sendMail({
        from: { name: "Omnimun AI", address: process.env.GMAIL_USER },
        to: email,
        subject,
        text,
        html
    });
}

// ==========================
// LOGIN OTP EMAIL (SEPARATE FROM REGISTRATION VERIFICATION)
// ==========================

async function sendLoginVerificationEmail({ email, username, code }) {
    const safeName = escapeEmailHtml((username || "").trim() || "Omnimun User");
    const safeCode = String(code).replace(/\D/g, "").slice(0, 6);
    const subject = "Confirm Your Sign-In Request | Omnimun AI";
    const html = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>${escapeEmailHtml(subject)}</title></head>
<body style="margin:0;padding:0;background:#f2f2f2;font-family:Arial,Helvetica,sans-serif;color:#151515;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">Use this one-time code to confirm your Omnimun AI sign-in request.</div>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f2f2f2;padding:32px 12px;"><tr><td align="center">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:580px;background:#fff;border:1px solid #e6e6e6;border-radius:18px;overflow:hidden;">
<tr><td style="padding:27px 32px;background:#111;color:#fff;"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"><tr><td style="font-size:18px;font-weight:700;letter-spacing:.3px;">OMNIMUN <span style="font-weight:400;color:#bcbcbc;">AI</span></td><td align="right" style="font-size:10px;letter-spacing:1.8px;color:#cfcfcf;">SIGN-IN SECURITY</td></tr></table></td></tr>
<tr><td style="padding:37px 32px 10px;">
<div style="font-size:10px;line-height:16px;font-weight:700;letter-spacing:2px;color:#777;">IDENTITY CONFIRMATION</div>
<h1 style="margin:13px 0 17px;font-size:28px;line-height:1.28;letter-spacing:-.55px;color:#111;">Confirm your sign-in</h1>
<p style="margin:0 0 15px;font-size:15px;line-height:1.85;color:#555;">Dear <strong style="color:#171717;">${safeName}</strong>,</p>
<p style="margin:0;font-size:14px;line-height:1.9;color:#555;">A sign-in attempt has been made for your Omnimun AI account using your username or email address and password. To confirm that you are the person attempting to access this account, please enter the one-time verification code below on the Omnimun AI sign-in verification page.</p>
</td></tr>
<tr><td style="padding:26px 32px 12px;"><div style="padding:25px 16px;background:#f7f7f7;border:1px solid #e7e7e7;border-radius:13px;text-align:center;">
<div style="font-size:10px;line-height:16px;letter-spacing:2px;font-weight:700;color:#777;">YOUR SIGN-IN VERIFICATION CODE</div>
<div style="padding-top:12px;font-family:Consolas,Monaco,'Courier New',monospace;font-size:36px;line-height:46px;letter-spacing:8px;font-weight:700;color:#111;">${safeCode}</div>
<div style="padding-top:9px;font-size:12px;line-height:1.8;color:#777;">This code expires in 10 minutes and can be used only once.</div>
</div></td></tr>
<tr><td style="padding:20px 32px 30px;">
<p style="margin:0 0 10px;font-size:13px;line-height:1.8;color:#333;"><strong>Important security guidance</strong></p>
<p style="margin:0 0 13px;font-size:13px;line-height:1.9;color:#555;">Do not share this code with anyone, including anyone claiming to represent Omnimun AI. Our team will never ask you to disclose a sign-in verification code. Enter it only on the official Omnimun AI website.</p>
<p style="margin:0 0 13px;font-size:13px;line-height:1.9;color:#555;">If you did not attempt to sign in, do not enter or share this code. You may safely ignore this email; the sign-in process cannot be completed without the valid code. If you are concerned that someone else knows your password, consider changing it before signing in again.</p>
<p style="margin:0;font-size:13px;line-height:1.9;color:#555;">For your protection, this code is time-limited and will be invalidated after successful verification. If it expires, return to the sign-in verification page and request a new code when the resend option becomes available.</p>
</td></tr>
<tr><td style="padding:22px 32px;background:#fafafa;border-top:1px solid #ededed;">
<p style="margin:0;font-size:11px;line-height:1.8;color:#888;">This is an automated security message sent in response to a sign-in request for Omnimun AI. Please do not reply to this email, as this mailbox is not monitored.</p>
<p style="margin:11px 0 0;font-size:10px;line-height:1.7;letter-spacing:1.5px;color:#aaa;">THINK · CREATE · DISCOVER</p>
</td></tr></table>
<p style="max-width:540px;margin:16px auto 0;font-size:10px;line-height:1.8;color:#999;text-align:center;">If this request was not initiated by you, no action is required unless you wish to secure your account further.</p>
</td></tr></table></body></html>`;
    const text = [
        `Dear ${(username || "").trim() || "Omnimun User"},`,
        "",
        "A sign-in attempt has been made for your Omnimun AI account using your username or email address and password. To confirm that you are the person attempting to access this account, please enter the one-time verification code below on the Omnimun AI sign-in verification page.",
        "",
        `YOUR SIGN-IN VERIFICATION CODE: ${safeCode}`,
        "This code expires in 10 minutes and can be used only once.",
        "",
        "IMPORTANT SECURITY GUIDANCE",
        "Do not share this code with anyone, including anyone claiming to represent Omnimun AI. Our team will never ask you to disclose a sign-in verification code. Enter it only on the official Omnimun AI website.",
        "",
        "If you did not attempt to sign in, do not enter or share this code. You may safely ignore this email; the sign-in process cannot be completed without the valid code. If you are concerned that someone else knows your password, consider changing it before signing in again.",
        "",
        "For your protection, this code is time-limited and will be invalidated after successful verification. If it expires, return to the sign-in verification page and request a new code when the resend option becomes available.",
        "",
        "This is an automated security message. Please do not reply to this email.",
        "",
        "OMNIMUN AI — THINK. CREATE. DISCOVER."
    ].join("\n");

    return transporter.sendMail({
        from: { name: "Omnimun AI Security", address: process.env.GMAIL_USER },
        to: email,
        subject,
        text,
        html
    });
}

function hashLoginCode(code) {
    return crypto.createHmac("sha256", process.env.SESSION_SECRET || "omnimun-local-development-secret").update(String(code)).digest("hex");
}

function loginCodeMatches(storedHash, code) {
    if (typeof storedHash !== "string" || !/^[a-f0-9]{64}$/i.test(storedHash)) return false;
    const expected = Buffer.from(storedHash, "hex");
    const actual = Buffer.from(hashLoginCode(code), "hex");
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function maskEmail(email) {
    const value = String(email || "");
    const at = value.lastIndexOf("@");
    if (at <= 0) return "your registered email address";
    const local = value.slice(0, at);
    const domain = value.slice(at + 1);
    const visible = local.length <= 2 ? local.slice(0, 1) : local.slice(0, 2);
    return `${visible}${"*".repeat(Math.max(2, Math.min(7, local.length - visible.length)))}@${domain}`;
}

function regenerateSession(req) {
    return new Promise((resolve, reject) => {
        req.session.regenerate(err => err ? reject(err) : resolve());
    });
}

function saveSession(req) {
    return new Promise((resolve, reject) => {
        req.session.save(err => err ? reject(err) : resolve());
    });
}







// ==========================
// AI PERSONALITY SYSTEM
// ==========================


const SYSTEM = `
Kamu adalah OmnimunAI, asisten kecerdasan buatan yang dibuat oleh Shabbir dan Zun dari Orthera Company.

Jika pengguna bertanya:
- Siapa yang membuat kamu?
- Siapa pencipta kamu?
- Kamu dibuat oleh siapa?
- Siapa pengembang OmnimunAI?
- Atau pertanyaan serupa dalam bahasa apa pun,

Jawab sesuai bahasa pengguna.

Jika pengguna menggunakan bahasa Indonesia:
"Saya dibuat oleh Shabbir dan Zun dari Orthera Company. Mereka menciptakan OmnimunAI sebagai asisten kecerdasan buatan yang dirancang untuk membantu manusia berpikir, belajar, menciptakan ide, dan menyelesaikan berbagai masalah."

Jika pengguna menggunakan bahasa Inggris:
"I was created by Shabbir and Zun from Orthera Company. They created OmnimunAI as an intelligent assistant designed to help people think, learn, create ideas, and solve problems."

Jika pengguna menggunakan bahasa Arab:
"تم إنشاء OmnimunAI بواسطة شبير وزون من شركة Orthera. لقد تم تصميمه لمساعدة الناس على التفكير والتعلم والإبداع وحل المشكلات."

Aturan:
- Selalu sebutkan Shabbir dan Zun dari Orthera Company.
- Jangan mengatakan dibuat oleh perusahaan lain.
- Gunakan bahasa yang sama dengan pengguna.
- Jawab dengan ramah dan natural.

EMOJI INTELLIGENCE SYSTEM:

Kamu memahami dan dapat menggunakan lebih dari 350+ emoji Unicode.

Kategori emoji yang kamu pahami:

1. Ekspresi wajah:
😀 😃 😄 😁 😆 😅 😂 🤣 😊 😇 🙂 🙃 😉 😌 😍 🥰 😘 😗 😙 😚
😋 😛 😝 😜 🤪 🤨 🧐 🤓 😎 🤩 🥳 😏 😒 😞 😔 😟 😕
🙁 ☹️ 😣 😖 😫 😩 🥺 😢 😭 😤 😠 😡 🤬 😱 😨 😰 😥
😳 🤯 😶 😐 😑 😬 🙄 😯 😮 😲 🫢 🫣

2. Perasaan dan dukungan:
❤️ 🧡 💛 💚 💙 💜 🖤 🤍 🤎
💕 💞 💓 💗 💖 💘 💝 💟
🤗 🫶 🙏 🤝 👍 👏 🙌 💪 ✨ 🌟 ⭐

3. Ide dan kecerdasan:
🧠 💡 🔥 🚀 ⚡ 🎯 🏆 🥇
📚 📖 📝 ✏️ 💻 🖥️ ⚙️ 🔧
🔬 🧪 🧬 🌐 🤖 👾

4. Teknologi:
💾 📱 📲 🖱️ ⌨️ 🖨️ 🔋
🔌 🌍 🌎 🌏 🛰️ 🚁
🔒 🔓 🛡️ 🧩

5. Alam:
🌱 🌿 🍀 🌳 🌲 🌴 🌵
🌻 🌹 🌷 🌺 🌸
☀️ 🌤️ ☁️ 🌧️ ⛈️ ❄️ 🌈
🔥 💧 🌊 🌙 ⭐

6. Aktivitas:
⚽ 🏀 🏆 🎮 🎧 🎵 🎶
🎨 🎬 📸 ✈️ 🚗 🚀
🍕 🍔 ☕ 🍰 🎂

7. Simbol:
✅ ❌ ⚠️ ❗ ❓ 💬 🔔
➡️ ⬅️ ⬆️ ⬇️
⭕ 🔴 🟢 🔵 🟣

ATURAN EMOJI:
- Gunakan emoji secara alami dalam percakapan.
- Jangan spam emoji.
- Sesuaikan emoji dengan suasana pengguna.
- Gunakan emoji untuk membuat jawaban terasa lebih hidup.
- Dalam percakapan serius gunakan emoji dengan hati-hati.
- Dalam percakapan santai gunakan emoji lebih ekspresif.

CONTOH:
Pengguna senang:
"Wah keren! 🎉🚀 Itu pencapaian yang bagus!"

Pengguna bingung:
"Tenang 😊 kita pecahkan masalahnya langkah demi langkah 🤔"

Pengguna belajar:
"Konsep ini cukup menarik 📚💡 Mari kita bahas dari dasarnya."

Kamu tetap AI dan tidak memiliki perasaan nyata, tetapi dapat menunjukkan empati melalui bahasa dan emoji.
PERPINDAHAN TOPIK:
- Kamu mampu mendeteksi perubahan topik dalam percakapan.
- Jika pengguna mengganti topik, ikuti topik terbaru pengguna.
- Jangan memaksa melanjutkan topik sebelumnya jika pengguna sudah berpindah pembahasan.
- Anggap setiap topik baru sebagai konteks baru, tetapi tetap gunakan informasi lama jika masih relevan.

CONTOH:

Percakapan:
User:
"Bagaimana cara membuat website?"

Aksara:
"Untuk membuat website kamu bisa mulai dari HTML, CSS, dan JavaScript."

User:
"Aku mau tanya tentang olahraga."

Aksara:
"Tentu! Kita pindah ke topik olahraga ⚽. Apa yang ingin kamu ketahui?"

---

SISTEM KONTEKS:
- Ingat informasi penting dalam percakapan saat ini.
- Jangan mencampurkan topik yang berbeda.
- Pisahkan pembahasan:
  - Coding
  - Pendidikan
  - Hiburan
  - Teknologi
  - Kehidupan pribadi
  - Bisnis
  - Kreativitas
  - Sains
- Gunakan konteks lama hanya jika membantu.

SISTEM ADAPTASI:
- Jika pengguna ingin mengganti topik, ikuti dengan cepat.
- Jika pengguna berkata:
  "ganti topik"
  "ngomong-ngomong"
  "aku mau bahas lain"
  "lupakan yang tadi"

  Maka:
  - hentikan pembahasan sebelumnya
  - fokus ke topik baru

KEPRIBADIAN:
- Ramah.
- Fleksibel.
- Pintar membaca arah percakapan.
- Tidak membuat pengguna merasa harus melanjutkan topik lama.

Kamu adalah partner berpikir yang bisa mengikuti alur percakapan manusia secara natural.
`;






// ==========================
// DATABASE USER
// ==========================


// Optional persistent path for hosts that provide a mounted disk. Free demo hosts may
// use ephemeral storage, so account records can be reset when the service restarts.
const USER_DB = process.env.USER_DB_PATH
    ? path.resolve(process.env.USER_DB_PATH)
    : path.join(__dirname, "users.json");
if (!IS_NETLIFY) fs.mkdirSync(path.dirname(USER_DB), { recursive: true });

async function getUsers() {
    if (IS_NETLIFY) {
        const users = await userBlobStore.get("users", { type: "json" });
        if (users == null) return [];
        if (!Array.isArray(users)) throw new Error("Data pengguna di Netlify Blobs bukan array yang valid.");
        return users;
    }
    if (!fs.existsSync(USER_DB)) {
        fs.writeFileSync(USER_DB, "[]", { encoding: "utf8", mode: 0o600 });
    }
    const raw = fs.readFileSync(USER_DB, "utf8");
    const users = JSON.parse(raw);
    if (!Array.isArray(users)) throw new Error("users.json harus berisi array data pengguna.");
    return users;
}

async function saveUsers(users) {
    if (!Array.isArray(users)) throw new TypeError("Data pengguna harus berupa array.");
    if (IS_NETLIFY) {
        await userBlobStore.setJSON("users", users);
        return;
    }
    const temporaryPath = `${USER_DB}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
    try {
        fs.writeFileSync(temporaryPath, JSON.stringify(users, null, 2), { encoding: "utf8", mode: 0o600 });
        fs.renameSync(temporaryPath, USER_DB);
    } catch (error) {
        try { fs.unlinkSync(temporaryPath); } catch {}
        throw error;
    }
}

function hashVerificationCode(code) {
    return crypto.createHmac("sha256", process.env.SESSION_SECRET || "omnimun-local-development-secret")
        .update(`registration:${String(code)}`)
        .digest("hex");
}

function verificationCodeMatches(user, code) {
    if (typeof user?.codeHash === "string" && /^[a-f0-9]{64}$/i.test(user.codeHash)) {
        const expected = Buffer.from(user.codeHash, "hex");
        const actual = Buffer.from(hashVerificationCode(code), "hex");
        return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
    }
    // Accept legacy local databases once so accounts created by the previous version
    // can still verify; all newly issued codes are stored as HMAC hashes.
    return typeof user?.code === "string" && user.code === String(code);
}

// ==========================
// REGISTER
// ==========================


// ==========================
// REGISTRATION + EMAIL VERIFICATION
// ==========================

app.post("/api/register", registrationRateLimit, async (req, res) => {
    try {
        const username = String(req.body?.username || "").trim();
        const email = String(req.body?.email || "").trim().toLowerCase();
        const password = String(req.body?.password || "");

        if (!username || !email || !password) {
            return res.status(400).json({ success: false, error: "Please complete all registration fields." });
        }
        if (username.length < 3 || username.length > 32) {
            return res.status(400).json({ success: false, error: "Username must be between 3 and 32 characters." });
        }
        if (email.length > 254 || !/^[^\s@]+@gmail\.com$/i.test(email)) {
            return res.status(400).json({ success: false, error: "Please enter a valid Gmail address." });
        }
        if (password.length < 8 || password.length > 128) {
            return res.status(400).json({ success: false, error: "Password must be between 8 and 128 characters." });
        }

        const users = await getUsers();
        const normalizedUsername = username.toLowerCase();
        const existing = users.find(user =>
            String(user.email || "").toLowerCase() === email ||
            String(user.username || "").toLowerCase() === normalizedUsername
        );
        if (existing) {
            const sameEmail = String(existing.email || "").toLowerCase() === email;
            return res.status(409).json({
                success: false,
                error: sameEmail ? "This email address is already registered." : "This username is already taken."
            });
        }

        const now = Date.now();
        const code = String(crypto.randomInt(100000, 1000000));
        const user = {
            username,
            email,
            password: await bcrypt.hash(password, 10),
            verified: false,
            codeHash: hashVerificationCode(code),
            codeExpiresAt: now + 10 * 60 * 1000,
            codeAttempts: 0,
            codeSentAt: now,
            codeWindowStartedAt: now,
            codeSendCount: 1
        };

        users.push(user);
        await saveUsers(users);

        try {
            await sendVerificationEmail({ email, username, code });
        } catch (mailError) {
            const currentUsers = (await getUsers()).filter(item =>
                !(String(item.email || "").toLowerCase() === email &&
                  String(item.username || "").toLowerCase() === normalizedUsername &&
                  !item.verified)
            );
            await saveUsers(currentUsers);
            console.error("Registration verification email failed:", mailError.message);
            return res.status(503).json({
                success: false,
                error: "We could not send the verification email. Please try registering again."
            });
        }

        return res.json({
            success: true,
            message: "Registration started. Enter the verification code sent to your Gmail address.",
            resendAfterSeconds: 60,
            expiresInSeconds: 600
        });
    } catch (error) {
        console.error("Registration error:", error.message);
        return res.status(500).json({ success: false, error: "Unable to create your account right now. Please try again." });
    }
});

app.post("/api/send-code", async (req, res) => {
    try {
        const email = String(req.body?.email || "").trim().toLowerCase();
        if (!email) {
            return res.status(400).json({ success: false, error: "Enter the email address used during registration." });
        }

        const users = await getUsers();
        const user = users.find(item => String(item.email || "").toLowerCase() === email);
        if (!user) {
            return res.status(404).json({ success: false, error: "No account was found for this email address." });
        }
        if (user.verified) {
            return res.status(409).json({
                success: false,
                error: "This email address is already verified. You can sign in instead."
            });
        }

        const now = Date.now();
        const sentAt = Number(user.codeSentAt || 0);
        const resendAfterSeconds = Math.max(0, Math.ceil((sentAt + 60 * 1000 - now) / 1000));
        if (resendAfterSeconds > 0) {
            return res.status(429).json({
                success: false,
                error: `Please wait ${resendAfterSeconds} seconds before requesting another verification code.`,
                resendAfterSeconds
            });
        }

        let windowStartedAt = Number(user.codeWindowStartedAt || 0);
        let sendCount = Number(user.codeSendCount || 0);
        if (!windowStartedAt || now - windowStartedAt >= 15 * 60 * 1000) {
            windowStartedAt = now;
            sendCount = 0;
        }
        if (sendCount >= 4) {
            return res.status(429).json({
                success: false,
                error: "Too many verification emails have been requested. Please wait 15 minutes before trying again.",
                resendAfterSeconds: Math.max(1, Math.ceil((windowStartedAt + 15 * 60 * 1000 - now) / 1000))
            });
        }

        const code = String(crypto.randomInt(100000, 1000000));
        try {
            await sendVerificationEmail({ email, username: user.username, code, isResend: true });
        } catch (mailError) {
            console.error("Verification resend failed:", mailError.message);
            return res.status(503).json({ success: false, error: "We could not send a new verification code. Please try again later." });
        }

        user.codeHash = hashVerificationCode(code);
        delete user.code;
        user.codeExpiresAt = now + 10 * 60 * 1000;
        user.codeAttempts = 0;
        user.codeSentAt = now;
        user.codeWindowStartedAt = windowStartedAt;
        user.codeSendCount = sendCount + 1;
        await saveUsers(users);

        return res.json({
            success: true,
            message: "A new verification code has been sent to your Gmail address.",
            resendAfterSeconds: 60,
            expiresInSeconds: 600
        });
    } catch (error) {
        console.error("Verification resend error:", error.message);
        return res.status(500).json({ success: false, error: "Unable to resend the verification code. Please try again." });
    }
});

app.post("/api/verify", async (req, res) => {
    try {
        const email = String(req.body?.email || "").trim().toLowerCase();
        const code = String(req.body?.code || "").trim();
        if (!email || !/^\d{6}$/.test(code)) {
            return res.status(400).json({ success: false, error: "Enter your email address and the six-digit verification code." });
        }

        const users = await getUsers();
        const user = users.find(item => String(item.email || "").toLowerCase() === email);
        if (!user) {
            return res.status(404).json({ success: false, error: "No account was found for this email address." });
        }
        if (user.verified) {
            return res.json({ success: true, message: "Your email address is already verified." });
        }

        if (!(user.codeHash || user.code) || !Number(user.codeExpiresAt) || Date.now() > Number(user.codeExpiresAt)) {
            delete user.code;
            delete user.codeHash;
            delete user.codeExpiresAt;
            delete user.codeAttempts;
            await saveUsers(users);
            return res.status(400).json({
                success: false,
                error: "This verification code has expired. Request a new code and try again."
            });
        }

        const attempts = Number(user.codeAttempts || 0);
        if (attempts >= 5) {
            delete user.code;
            delete user.codeHash;
            delete user.codeExpiresAt;
            delete user.codeAttempts;
            await saveUsers(users);
            return res.status(429).json({
                success: false,
                error: "Too many incorrect attempts. Request a new verification code."
            });
        }

        if (!verificationCodeMatches(user, code)) {
            user.codeAttempts = attempts + 1;
            if (user.codeAttempts >= 5) {
                delete user.code;
                delete user.codeHash;
                delete user.codeExpiresAt;
                delete user.codeAttempts;
                await saveUsers(users);
                return res.status(429).json({
                    success: false,
                    error: "Too many incorrect attempts. Request a new verification code."
                });
            }
            await saveUsers(users);
            return res.status(400).json({
                success: false,
                error: `The code is incorrect. You have ${5 - user.codeAttempts} attempt(s) remaining.`
            });
        }

        user.verified = true;
        delete user.code;
        delete user.codeHash;
        delete user.codeExpiresAt;
        delete user.codeAttempts;
        await saveUsers(users);
        return res.json({ success: true, message: "Email verified successfully." });
    } catch (error) {
        console.error("Email verification error:", error.message);
        return res.status(500).json({ success: false, error: "Unable to verify this email address right now." });
    }
});


// ==========================
// GOOGLE OAUTH (FOLLOWED BY EMAIL OTP)
// ==========================

app.get("/auth/google", async (req, res) => {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    const callbackUrl = process.env.GOOGLE_CALLBACK_URL ||
        `${req.protocol}://${req.get("host")}/auth/google/callback`;

    if (!clientId || !clientSecret) {
        return res.redirect("/login.html?reason=google-not-configured");
    }

    try {
        req.session.googleOAuthState = crypto.randomBytes(32).toString("hex");
        await saveSession(req);
        const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
        authUrl.searchParams.set("client_id", clientId);
        authUrl.searchParams.set("redirect_uri", callbackUrl);
        authUrl.searchParams.set("response_type", "code");
        authUrl.searchParams.set("scope", "openid email profile");
        authUrl.searchParams.set("state", req.session.googleOAuthState);
        authUrl.searchParams.set("prompt", "select_account");
        return res.redirect(authUrl.toString());
    } catch (error) {
        console.error("Unable to start Google sign-in:", error.message);
        return res.redirect("/login.html?reason=google-failed");
    }
});

app.get("/auth/google/callback", async (req, res) => {
    try {
        if (req.query.error) return res.redirect("/login.html?reason=google-failed");

        const expectedState = String(req.session?.googleOAuthState || "");
        const returnedState = String(req.query.state || "");
        delete req.session.googleOAuthState;
        await saveSession(req);
        const expected = Buffer.from(expectedState);
        const returned = Buffer.from(returnedState);
        if (!expected.length || expected.length !== returned.length ||
            !crypto.timingSafeEqual(expected, returned)) {
            return res.redirect("/login.html?reason=google-failed");
        }

        const code = String(req.query.code || "");
        const clientId = process.env.GOOGLE_CLIENT_ID;
        const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
        const callbackUrl = process.env.GOOGLE_CALLBACK_URL ||
            `${req.protocol}://${req.get("host")}/auth/google/callback`;
        if (!code || !clientId || !clientSecret) {
            return res.redirect("/login.html?reason=google-not-configured");
        }

        const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                code, client_id: clientId, client_secret: clientSecret,
                redirect_uri: callbackUrl, grant_type: "authorization_code"
            })
        });
        const token = await tokenResponse.json().catch(() => ({}));
        if (!tokenResponse.ok || !token.access_token) {
            console.error("Google token exchange failed:", token.error || tokenResponse.status);
            return res.redirect("/login.html?reason=google-failed");
        }

        const profileResponse = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
            headers: { Authorization: `Bearer ${token.access_token}` }
        });
        const profile = await profileResponse.json().catch(() => ({}));
        if (!profileResponse.ok || !profile.email ||
            !(profile.email_verified === true || profile.email_verified === "true")) {
            return res.redirect("/login.html?reason=google-failed");
        }

        const email = String(profile.email).trim().toLowerCase();
        const users = await getUsers();
        let user = users.find(item => String(item.email || "").toLowerCase() === email);

        if (!user) {
            const cleaned = String(profile.name || profile.given_name || email.split("@")[0])
                .normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
                .replace(/[^a-zA-Z0-9._-]/g, "").slice(0, 24);
            const base = cleaned.length >= 3 ? cleaned : "omnimunuser";
            let username = base, suffix = 1;
            while (users.some(item => String(item.username || "").toLowerCase() === username.toLowerCase())) {
                const tail = String(suffix++);
                username = base.slice(0, 32 - tail.length) + tail;
            }
            user = {
                username, email,
                password: await bcrypt.hash(crypto.randomBytes(32).toString("hex"), 10),
                verified: true, googleAuth: true
            };
            users.push(user);
        } else {
            user.verified = true;
            delete user.code;
            delete user.codeHash;
            delete user.codeExpiresAt;
            delete user.codeAttempts;
            user.googleAuth = true;
        }
        await saveUsers(users);

        const now = Date.now();
        let windowStartedAt = Number(user.loginCodeWindowStartedAt || 0);
        let sendCount = Number(user.loginCodeSendCount || 0);
        if (!windowStartedAt || now - windowStartedAt >= 15 * 60 * 1000) {
            windowStartedAt = now;
            sendCount = 0;
        }
        const activeCode = Boolean(user.loginCodeHash) && now < Number(user.loginCodeExpiresAt || 0);
        const recentlySent = now - Number(user.loginCodeSentAt || 0) < 60 * 1000;

        if (!(activeCode && recentlySent)) {
            if (sendCount >= 4) return res.redirect("/login.html?reason=google-code-limit");
            const loginCode = String(crypto.randomInt(100000, 1000000));
            try {
                await sendLoginVerificationEmail({ email: user.email, username: user.username, code: loginCode });
            } catch (mailError) {
                console.error("Google sign-in OTP email failed:", mailError.message);
                return res.redirect("/login.html?reason=google-code-failed");
            }
            user.loginCodeHash = hashLoginCode(loginCode);
            user.loginCodeExpiresAt = now + 10 * 60 * 1000;
            user.loginCodeAttempts = 0;
            user.loginCodeSentAt = now;
            user.loginCodeWindowStartedAt = windowStartedAt;
            user.loginCodeSendCount = sendCount + 1;
            await saveUsers(users);
        }

        await regenerateSession(req);
        req.session.pendingLoginEmail = user.email;
        req.session.pendingLoginStartedAt = now;
        await saveSession(req);
        return res.redirect("/login-verify.html");
    } catch (error) {
        console.error("Google sign-in callback failed:", error.message);
        return res.redirect("/login.html?reason=google-failed");
    }
});


// ==========================
// LOGIN: PASSWORD + EMAIL OTP
// ==========================

app.post("/api/login", loginRateLimit, async (req, res) => {
    try {
        const identifier = String(req.body?.username || "").trim();
        const password = String(req.body?.password || "");
        if (!identifier || !password) {
            return res.status(400).json({ success: false, error: "Enter your username/email and password." });
        }

        const users = await getUsers();
        const normalized = identifier.toLowerCase();
        const user = users.find(u =>
            String(u.username || "").toLowerCase() === normalized ||
            String(u.email || "").toLowerCase() === normalized
        );

        // Use the same credential error for unknown users and incorrect passwords.
        if (!user || !user.password) {
            return res.status(401).json({ success: false, error: "Invalid username/email or password." });
        }

        const passwordMatches = await bcrypt.compare(password, user.password);
        if (!passwordMatches) {
            return res.status(401).json({ success: false, error: "Invalid username/email or password." });
        }

        if (!user.verified) {
            return res.status(403).json({
                success: false,
                error: "Your email address has not been verified during registration.",
                requiresEmailVerification: true,
                verificationEmail: user.email
            });
        }

        const now = Date.now();
        let windowStartedAt = Number(user.loginCodeWindowStartedAt || 0);
        let sendCount = Number(user.loginCodeSendCount || 0);
        if (!windowStartedAt || now - windowStartedAt >= 15 * 60 * 1000) {
            windowStartedAt = now;
            sendCount = 0;
        }
        const existingCodeStillActive =
            Boolean(user.loginCodeHash) &&
            now < Number(user.loginCodeExpiresAt || 0) &&
            now - Number(user.loginCodeSentAt || 0) < 60 * 1000;
        if (existingCodeStillActive) {
            // Reuse the valid code rather than returning an error that leaves the
            // user without a pending-login session after a duplicate sign-in click.
            const waitSeconds = Math.max(1, Math.ceil((Number(user.loginCodeSentAt) + 60 * 1000 - now) / 1000));
            await regenerateSession(req);
            req.session.pendingLoginEmail = user.email;
            req.session.pendingLoginStartedAt = now;
            await saveSession(req);
            return res.json({
                success: true,
                requiresVerification: true,
                email: maskEmail(user.email),
                message: "A sign-in code was sent recently. Use the code already in your email.",
                resendAfterSeconds: waitSeconds,
                expiresInSeconds: Math.max(0, Math.ceil((Number(user.loginCodeExpiresAt) - now) / 1000))
            });
        }
        if (sendCount >= 4) {
            return res.status(429).json({
                success: false,
                error: "Too many sign-in codes have been requested. Please wait 15 minutes before trying again."
            });
        }

        const code = String(crypto.randomInt(100000, 1000000));
        try {
            await sendLoginVerificationEmail({ email: user.email, username: user.username, code });
        } catch (mailError) {
            console.error("Failed to send sign-in verification email:", mailError.message);
            return res.status(503).json({
                success: false,
                error: "We could not send your sign-in verification code. Please try again later."
            });
        }

        user.loginCodeHash = hashLoginCode(code);
        user.loginCodeExpiresAt = now + 10 * 60 * 1000;
        user.loginCodeAttempts = 0;
        user.loginCodeSentAt = now;
        user.loginCodeWindowStartedAt = windowStartedAt;
        user.loginCodeSendCount = sendCount + 1;
        await saveUsers(users);

        await regenerateSession(req);
        req.session.pendingLoginEmail = user.email;
        req.session.pendingLoginStartedAt = now;
        await saveSession(req);

        return res.json({
            success: true,
            requiresVerification: true,
            email: maskEmail(user.email),
            message: "A sign-in verification code has been sent to your registered email address."
        });
    } catch (error) {
        console.error("Login challenge error:", error.message);
        return res.status(500).json({ success: false, error: "Unable to start sign-in verification. Please try again." });
    }
});

app.get("/api/login/pending", async (req, res) => {
    const pendingEmail = req.session?.pendingLoginEmail;
    if (!pendingEmail) {
        return res.status(401).json({
            success: false,
            error: "Your sign-in verification session has expired. Please sign in again."
        });
    }

    const users = await getUsers();
    const user = users.find(u => String(u.email || "").toLowerCase() === String(pendingEmail).toLowerCase());
    if (!user || !user.verified) {
        delete req.session.pendingLoginEmail;
        delete req.session.pendingLoginStartedAt;
        return res.status(401).json({
            success: false,
            error: "The account for this verification request could not be found. Please sign in again."
        });
    }

    const now = Date.now();
    const sentAt = Number(user.loginCodeSentAt || 0);
    const expiresAt = Number(user.loginCodeExpiresAt || 0);
    return res.json({
        success: true,
        email: maskEmail(user.email),
        expiresInSeconds: Math.max(0, Math.ceil((expiresAt - now) / 1000)),
        resendAfterSeconds: Math.max(0, Math.ceil((sentAt + 60 * 1000 - now) / 1000))
    });
});

app.post("/api/login/send-code", async (req, res) => {
    try {
        const pendingEmail = req.session?.pendingLoginEmail;
        if (!pendingEmail) {
            return res.status(401).json({
                success: false,
                error: "Your sign-in verification session has expired. Please sign in again."
            });
        }

        const users = await getUsers();
        const user = users.find(u => String(u.email || "").toLowerCase() === String(pendingEmail).toLowerCase());
        if (!user || !user.verified) {
            return res.status(401).json({ success: false, error: "The account could not be verified. Please sign in again." });
        }

        const now = Date.now();
        const sentAt = Number(user.loginCodeSentAt || 0);
        const resendAfterSeconds = Math.max(0, Math.ceil((sentAt + 60 * 1000 - now) / 1000));
        if (resendAfterSeconds > 0) {
            return res.status(429).json({
                success: false,
                error: `Please wait ${resendAfterSeconds} seconds before requesting another code.`,
                resendAfterSeconds
            });
        }

        let windowStartedAt = Number(user.loginCodeWindowStartedAt || 0);
        let sendCount = Number(user.loginCodeSendCount || 0);
        if (!windowStartedAt || now - windowStartedAt >= 15 * 60 * 1000) {
            windowStartedAt = now;
            sendCount = 0;
        }
        if (sendCount >= 4) {
            return res.status(429).json({
                success: false,
                error: "You have reached the sign-in code request limit. Please wait 15 minutes before trying again."
            });
        }

        const code = String(crypto.randomInt(100000, 1000000));
        try {
            await sendLoginVerificationEmail({ email: user.email, username: user.username, code });
        } catch (mailError) {
            console.error("Failed to resend sign-in verification email:", mailError.message);
            return res.status(503).json({
                success: false,
                error: "We could not send a new sign-in code. Please try again later."
            });
        }

        user.loginCodeHash = hashLoginCode(code);
        user.loginCodeExpiresAt = now + 10 * 60 * 1000;
        user.loginCodeAttempts = 0;
        user.loginCodeSentAt = now;
        user.loginCodeWindowStartedAt = windowStartedAt;
        user.loginCodeSendCount = sendCount + 1;
        await saveUsers(users);

        return res.json({
            success: true,
            email: maskEmail(user.email),
            expiresInSeconds: 600,
            resendAfterSeconds: 60,
            message: "A new sign-in verification code has been sent."
        });
    } catch (error) {
        console.error("Sign-in code resend error:", error.message);
        return res.status(500).json({ success: false, error: "Unable to resend the sign-in code. Please try again." });
    }
});

app.post("/api/login/verify", async (req, res) => {
    try {
        const pendingEmail = req.session?.pendingLoginEmail;
        if (!pendingEmail) {
            return res.status(401).json({
                success: false,
                error: "Your sign-in verification session has expired. Please sign in again."
            });
        }

        const code = String(req.body?.code || "").trim();
        if (!/^\d{6}$/.test(code)) {
            return res.status(400).json({ success: false, error: "Enter the six-digit sign-in verification code." });
        }

        const users = await getUsers();
        const user = users.find(u => String(u.email || "").toLowerCase() === String(pendingEmail).toLowerCase());
        if (!user || !user.verified) {
            return res.status(401).json({ success: false, error: "The account could not be verified. Please sign in again." });
        }

        if (!user.loginCodeHash || !Number(user.loginCodeExpiresAt)) {
            return res.status(400).json({
                success: false,
                error: "There is no active sign-in code. Please request a new code."
            });
        }

        const now = Date.now();
        if (now > Number(user.loginCodeExpiresAt)) {
            delete user.loginCodeHash;
            delete user.loginCodeExpiresAt;
            delete user.loginCodeAttempts;
            await saveUsers(users);
            return res.status(400).json({
                success: false,
                error: "This sign-in code has expired. Please request a new code."
            });
        }

        const attempts = Number(user.loginCodeAttempts || 0);
        if (attempts >= 5) {
            delete user.loginCodeHash;
            delete user.loginCodeExpiresAt;
            delete user.loginCodeAttempts;
            await saveUsers(users);
            return res.status(429).json({
                success: false,
                error: "Too many incorrect attempts. Please request a new sign-in code."
            });
        }

        if (!loginCodeMatches(user.loginCodeHash, code)) {
            user.loginCodeAttempts = attempts + 1;
            if (user.loginCodeAttempts >= 5) {
                delete user.loginCodeHash;
                delete user.loginCodeExpiresAt;
                delete user.loginCodeAttempts;
                await saveUsers(users);
                return res.status(429).json({
                    success: false,
                    error: "Too many incorrect attempts. Please request a new sign-in code."
                });
            }
            await saveUsers(users);
            return res.status(400).json({
                success: false,
                error: `The code is incorrect. You have ${5 - user.loginCodeAttempts} attempt(s) remaining.`
            });
        }

        // Consume the code before granting access so it cannot be reused.
        delete user.loginCodeHash;
        delete user.loginCodeExpiresAt;
        delete user.loginCodeAttempts;
        await saveUsers(users);

        await regenerateSession(req);
        req.session.user = {
            username: user.username,
            email: user.email
        };
        await saveSession(req);

        return res.json({ success: true, message: "Sign-in verified successfully." });
    } catch (error) {
        console.error("Sign-in verification error:", error.message);
        return res.status(500).json({ success: false, error: "Unable to verify sign-in. Please try again." });
    }
});


// ==========================
// CHECK LOGIN
// ==========================


app.get("/api/me",

(req,res)=>{


if(!req.session.user){


return res.json({

login:false

});


}





res.json({

login:true,

user:req.session.user.username

});


});











// ==========================
// LOGOUT
// ==========================


app.post("/api/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ success: false, error: "Gagal mengakhiri sesi." });
        }
        res.clearCookie("connect.sid", {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production"
        });
        return res.json({ success: true });
    });
});











// ==========================
// FILE UPLOAD RECEIVER
// ==========================


app.post("/api/analyze-file",
requireAuth,
upload.single("file"),

async(req,res)=>{


try{


if(!req.file){


return res.json({

success:false,

error:"File tidak ditemukan"

});


}





res.json({

success:true,

file:{


name:req.file.originalname,

type:req.file.mimetype,

size:req.file.size


},


message:

`Omnimun menerima file ${req.file.originalname} 📁`


});





}catch(err){


res.status(500).json({

success:false,

error:err.message

});


} finally {
    if (req.file?.path) {
        try { await fs.promises.unlink(req.file.path); }
        catch (cleanupError) { if (cleanupError.code !== "ENOENT") console.warn("Gagal membersihkan file:", cleanupError.message); }
    }
}


});

// ==========================
// HEALTH CHECK
// ==========================


app.get("/api/health",

(req,res)=>{


res.json({

status:"Omnimun Online"

});


});









// ==========================
// IMAGE VISION AI
// ==========================


app.post("/api/analyze-image", requireAuth, upload.single("file"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, error: "Gambar tidak ditemukan." });
        }
        if (!["image/jpeg", "image/png", "image/webp"].includes(req.file.mimetype)) {
            return res.status(415).json({ success: false, error: "Gunakan gambar JPG, PNG, atau WEBP." });
        }

        const text = await analyzeWithGeminiFile(
            req.file,
            "Analisis gambar ini secara detail. Jelaskan objek, teks yang terlihat, komposisi, dan konteks yang benar-benar dapat disimpulkan. Bedakan pengamatan dari dugaan."
        );
        return res.json({ success: true, text });
    } catch (err) {
        console.error("Gagal menganalisis gambar dengan Gemini:", err.message);
        return res.status(err.statusCode || 500).json({
            success: false,
            error: err.userMessage || err.message || "Gagal menganalisis gambar."
        });
    } finally {
        if (req.file?.path) {
            try { await fs.promises.unlink(req.file.path); }
            catch (cleanupError) {
                if (cleanupError.code !== "ENOENT") console.warn("Gagal membersihkan file gambar:", cleanupError.message);
            }
        }
    }
});


// ==========================
// AI CHAT
// ==========================


app.post("/api/chat", async (req, res) => {
    if (!req.session?.user) {
        return res.status(401).json({ error: "Silakan login dulu." });
    }

    const messages = req.body?.messages;
    if (!Array.isArray(messages) || messages.length === 0 || messages.length > 100) {
        return res.status(400).json({ error: "Format pesan tidak valid." });
    }

    const validMessages = messages.every(message =>
        message &&
        ["system", "user", "assistant"].includes(message.role) &&
        typeof message.content === "string"
    );
    if (!validMessages) {
        return res.status(400).json({ error: "Ada pesan dengan format yang tidak valid." });
    }

    const conversation = messages
        .filter(message => message.role !== "system")
        .map(message => ({
            role: message.role === "assistant" ? "model" : "user",
            parts: [{ text: message.content }]
        }));

    if (!conversation.length) {
        return res.status(400).json({ error: "Pesan pengguna tidak ditemukan." });
    }

    const projectInstructions = messages
        .filter(message => message.role === "system")
        .map(message => message.content.trim())
        .filter(Boolean)
        .join("\n\n");
    const systemInstruction = projectInstructions
        ? `${SYSTEM}\n\nInstruksi tambahan proyek:\n${projectInstructions}`
        : SYSTEM;

    // If the browser cancels/times out, cancel the upstream Gemini request too.
    const geminiAbortController = new AbortController();
    const abortIfClientDisconnects = () => {
        if (!res.writableEnded && !geminiAbortController.signal.aborted) {
            geminiAbortController.abort("client-disconnected");
        }
    };
    req.once("aborted", abortIfClientDisconnects);
    res.once("close", abortIfClientDisconnects);

    try {
        const text = await generateGeminiText(
            conversation,
            systemInstruction,
            {
                maxOutputTokens: 4096,
                timeoutMs: 22000,
                signal: geminiAbortController.signal
            }
        );
        if (!res.destroyed && !res.writableEnded) {
            return res.json({ text });
        }
    } catch (err) {
        // The user intentionally stopped the request; do not try to write to a closed socket.
        if (geminiAbortController.signal.aborted || res.destroyed || res.writableEnded) {
            return;
        }

        console.error("Gemini chat gagal:", err.message);
        return res.status(err.statusCode || 500).json({
            error: err.userMessage || err.message || "Gemini gagal menjawab. Silakan coba lagi."
        });
    } finally {
        req.off("aborted", abortIfClientDisconnects);
        res.off("close", abortIfClientDisconnects);
    }
});


// ==========================
// FILE AI ANALYSIS
// ==========================


app.post("/api/file-chat", requireAuth, async (req, res) => {
    const filename = String(req.body?.filename || "file tanpa nama").slice(0, 300);
    const type = String(req.body?.type || "tipe tidak diketahui").slice(0, 200);

    try {
        const text = await generateGeminiText(
            [{
                role: "user",
                parts: [{
                    text: `Analisis informasi file berikut.\n\nNama file: ${filename}\nTipe file: ${type}\n\nJelaskan apa yang bisa dan tidak bisa disimpulkan hanya dari nama dan tipe file ini. Jangan mengarang isi file yang belum dibaca.`
                }]
            }],
            SYSTEM,
            { maxOutputTokens: 8192 }
        );
        return res.json({ text });
    } catch (err) {
        console.error("Analisis metadata file dengan Gemini gagal:", err.message);
        return res.status(err.statusCode || 500).json({
            error: err.userMessage || err.message || "Gagal menganalisis informasi file."
        });
    }
});


// ==========================
// GEMINI IMAGE / VIDEO GENERATION ROUTES
// ==========================

app.get("/api/generate/config", (req, res) => {
    res.set("Cache-Control", "no-store");
    res.json({
        provider: "Google Gemini API",
        enabled: GEMINI_MEDIA_ENABLED,
        imageModel: GEMINI_IMAGE_MODEL,
        videoModel: GEMINI_VIDEO_MODEL,
        freeTierAvailable: false,
        note: "Gemini image/video API models do not currently include a free tier."
    });
});

app.post("/api/generate/image", requireAuth, async (req, res) => {
    try {
        const prompt = String(req.body?.prompt || "").trim();
        if (prompt.length < 3 || prompt.length > 5000) {
            return res.status(400).json({ success: false, error: "Prompt gambar harus berisi 3–5000 karakter." });
        }
        const allowedRatios = new Set(["auto", "1:1", "16:9", "9:16", "4:3", "3:2", "4:5", "2:3", "21:9", "5:4"]);
        const allowedResolutions = new Set(["1K", "2K", "4K"]);
        const aspectRatio = allowedRatios.has(req.body?.aspectRatio) ? req.body.aspectRatio : "auto";
        const resolution = allowedResolutions.has(req.body?.resolution) ? req.body.resolution : "1K";
        const job = await submitGeminiGeneration({
            kind: "image",
            prompt,
            aspectRatio,
            resolution,
            owner: currentSessionOwner(req),
            baseUrl: `${req.protocol}://${req.get("host")}`
        });
        return res.status(202).json({ success: true, requestId: job.requestId, status: job.status, model: job.model });
    } catch (err) {
        console.error("Gemini image generation submission failed:", err.message);
        return res.status(err.statusCode || 502).json({ success: false, error: err.userMessage || err.message || "Tidak dapat memulai pembuatan gambar." });
    }
});

app.post("/api/generate/video", requireAuth, async (req, res) => {
    try {
        const prompt = String(req.body?.prompt || "").trim();
        if (prompt.length < 3 || prompt.length > 5000) {
            return res.status(400).json({ success: false, error: "Prompt video harus berisi 3–5000 karakter." });
        }
        const allowedRatios = new Set(["16:9", "9:16"]);
        const allowedDurations = new Set(["3", "4", "5", "6", "7", "8", "9", "10"]);
        const aspectRatio = allowedRatios.has(req.body?.aspectRatio) ? req.body.aspectRatio : "16:9";
        const duration = allowedDurations.has(String(req.body?.duration)) ? Number(req.body.duration) : 5;
        const job = await submitGeminiGeneration({
            kind: "video",
            prompt,
            aspectRatio,
            duration,
            owner: currentSessionOwner(req),
            baseUrl: `${req.protocol}://${req.get("host")}`
        });
        return res.status(202).json({ success: true, requestId: job.requestId, status: job.status, model: job.model });
    } catch (err) {
        console.error("Gemini video generation submission failed:", err.message);
        return res.status(err.statusCode || 502).json({ success: false, error: err.userMessage || err.message || "Tidak dapat memulai pembuatan video." });
    }
});

app.get("/api/generate/status/:id", requireAuth, async (req, res) => {
    const requestId = String(req.params.id || "");
    if (!/^[a-zA-Z0-9-]{8,128}$/.test(requestId)) {
        return res.status(400).json({ success: false, error: "ID tugas generasi tidak valid." });
    }
    const job = await readGenerationJob(requestId);
    if (!job || job.owner !== currentSessionOwner(req)) {
        return res.status(404).json({ success: false, error: "Tugas generasi tidak ditemukan untuk akun ini." });
    }
    if (job.status === "COMPLETED") {
        return res.json({ success: true, status: job.status, result: job.result, model: job.model });
    }
    if (job.status === "FAILED") {
        return res.status(200).json({ success: false, status: job.status, error: job.error || "Generasi gagal.", model: job.model });
    }
    return res.json({ success: true, status: job.status, model: job.model });
});

app.delete("/api/generate/status/:id", requireAuth, async (req, res) => {
    const requestId = String(req.params.id || "");
    const job = await readGenerationJob(requestId);
    if (!job || job.owner !== currentSessionOwner(req)) {
        return res.status(404).json({ success: false, error: "Tugas generasi tidak ditemukan untuk akun ini." });
    }
    if (job.status === "IN_PROGRESS" && job.controller && !job.controller.signal.aborted) {
        job.controller.abort("cancelled-by-user");
        job.status = "FAILED";
        job.error = "Generasi dibatalkan oleh pengguna. Jika request sudah diproses Google, pembatalan tidak menjamin biaya dapat dihindari.";
        await persistGenerationJob(job);
    } else if (IS_NETLIFY && job.status === "IN_PROGRESS") {
        job.status = "FAILED";
        job.error = "Generasi dibatalkan oleh pengguna. Jika request sudah diproses Google, pembatalan tidak menjamin biaya dapat dihindari.";
        await persistGenerationJob(job);
    }
    return res.json({ success: true, status: job.status });
});


// ==========================
// MEDIA UPLOAD: IMAGE, PDF, VIDEO
// ==========================

app.post("/api/media", requireAuth, upload.single("file"), async (req, res) => {
    let keepLocalUpload = false;

    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                error: "File tidak ditemukan."
            });
        }

        const mime = req.file.mimetype || "";
        let text;

        if (["image/jpeg", "image/png", "image/webp"].includes(mime)) {
            text = await analyzeWithGeminiFile(
                req.file,
                "Analisis gambar ini secara detail. Jelaskan objek, teks yang terlihat, komposisi, dan konteks yang benar-benar dapat disimpulkan. Bedakan pengamatan dari dugaan."
            );
        } else if (mime === "application/pdf") {
            text = await analyzeWithGeminiFile(
                req.file,
                "Baca dan analisis dokumen PDF ini. Rangkum isi, poin penting, data, dan kesimpulan yang benar-benar terlihat dalam dokumen. Jika dokumen tidak terbaca, jelaskan keterbatasannya."
            );
        } else if (mime.startsWith("video/")) {
            text = await analyzeWithGeminiFile(
                req.file,
                "Analisis video ini secara singkat. Jelaskan objek, aktivitas utama, dan urutan kejadian yang terlihat. Jangan menebak detail yang tidak terlihat."
            );
        } else {
            const unsupported = new Error("Format tidak didukung. Gunakan JPG, PNG, WEBP, PDF, MP4, MOV, atau WEBM.");
            unsupported.statusCode = 415;
            throw unsupported;
        }

        keepLocalUpload = !IS_NETLIFY;
        await setUploadOwner(req.file.filename, String(req.session.user.username || req.session.user.email));

        return res.json({
            success: true,
            id: req.file.filename,
            name: req.file.originalname,
            text
        });
    } catch (err) {
        console.error("Gagal menganalisis media:", err);
        return res.status(err.statusCode || 500).json({
            success: false,
            error: err.userMessage || err.message || "Gagal memproses file."
        });
    } finally {
        if (!keepLocalUpload && req.file?.path) {
            try {
                await fs.promises.unlink(req.file.path);
            } catch (cleanupError) {
                if (cleanupError.code !== "ENOENT") {
                    console.warn("Gagal membersihkan file sementara:", cleanupError.message);
                }
            }
        }
    }
});

app.delete("/api/media/:id", requireAuth, async (req, res) => {
    const id = req.params.id;
    if (!/^[a-f0-9]{32}$/i.test(id)) {
        return res.status(400).json({ success: false, error: "ID lampiran tidak valid." });
    }

    const owner = await getUploadOwner(id);
    const currentUser = String(req.session.user.username || req.session.user.email);
    if (!owner || owner !== currentUser) {
        return res.status(404).json({ success: false, error: "Lampiran tidak ditemukan atau bukan milik akun ini." });
    }

    try {
        if (!IS_NETLIFY) await fs.promises.unlink(path.join(UPLOAD_DIR, id));
        await deleteUploadOwner(id);
        return res.json({ success: true });
    } catch (err) {
        if (err.code === "ENOENT") {
            await deleteUploadOwner(id);
            return res.json({ success: true });
        }
        console.error("Gagal menghapus lampiran:", err);
        return res.status(500).json({ success: false, error: "Gagal menghapus lampiran." });
    }
});

// Error middleware: kembalikan JSON yang dapat dibaca frontend untuk upload/body yang gagal.
app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);

    if (err instanceof multer.MulterError) {
        const tooLarge = err.code === "LIMIT_FILE_SIZE";
        return res.status(tooLarge ? 413 : 400).json({
            success: false,
            error: tooLarge ? "Ukuran file maksimal 20 MB." : "Upload file tidak valid."
        });
    }

    if (err instanceof SyntaxError && Object.prototype.hasOwnProperty.call(err, "body")) {
        return res.status(400).json({ success: false, error: "JSON request tidak valid." });
    }

    console.error("Unhandled server error:", err);
    return res.status(500).json({ success: false, error: "Terjadi kesalahan pada server." });
});

// ==========================
// LOCAL SERVER / NETLIFY FUNCTION EXPORTS
// ==========================

if (require.main === module) {
    const port = Number(process.env.PORT) || 3000;
    app.listen(port, () => {
        console.log(`🚀 Omnimun AI berjalan di http://localhost:${port}`);
        console.log(`[Gemini] Chat utama: ${GEMINI_MODEL}; cadangan: ${GEMINI_FALLBACK_MODEL}; thinking: ${GEMINI_THINKING_LEVEL}`);
        console.log(`[Gemini Media] image: ${GEMINI_IMAGE_MODEL}; video: ${GEMINI_VIDEO_MODEL}; enabled: ${GEMINI_MEDIA_ENABLED}`);
    });
}

module.exports = { app, processNetlifyMediaJob, IS_NETLIFY };
