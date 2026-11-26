const { Redis } = require('@upstash/redis');

// Shared Upstash Redis client, from the Vercel Upstash integration.
// Used by both the rate limiter and App Attest device storage, so there
// is one client and one set of credentials for the whole server.
// Returns null when the env vars are missing (local development), and
// callers must fall back to an in-memory store in that case.
const redisUrl = process.env.KV_REST_API_URL;
const redisToken = process.env.KV_REST_API_TOKEN;
const redis = redisUrl && redisToken ? new Redis({ url: redisUrl, token: redisToken }) : null;

module.exports = { redis };
