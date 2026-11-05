const rateLimit = require('express-rate-limit');

// Rate limiting for POST /sign.
//
// Two tiers, both per client IP:
//   - burst:    5 requests per minute, stops a script hammering the
//               endpoint in seconds.
//   - sustained: 20 requests per hour, caps steady minting of passes.
//
// Legitimate PassKeepr use is one signing request per pass created, so
// 20/hour is generous for a real user and still slows abuse a lot.
//
// The limiters run BEFORE multer in routes/index.js, so a rejected
// request never pays the cost of receiving and parsing a 20MB upload.
//
// What this does NOT do:
//   - It does not authenticate anyone. An attacker can still sign
//     passes, just at most 20/hour per IP. Auth (a shared secret only
//     PassKeepr sends) is the real fix for that; this is a speed bump.
//   - It is not a hard cap on Vercel. express-rate-limit's default
//     store keeps counters in memory, per function instance. Vercel
//     runs many instances and cold starts reset them, so a distributed
//     attacker can get more than 20/hour in total. A hard cap needs a
//     shared store (Upstash Redis / Vercel KV with @upstash/ratelimit)
//     or Vercel Firewall rate limiting in front of the app.
//
// Trust proxy: app.js sets `trust proxy` to 1 so req.ip is the real
// client IP from X-Forwarded-For when running behind Vercel. Without
// that, every client would share Vercel's edge IP and one bucket.

function envInt(name, fallback) {
  const value = parseInt(process.env[name], 10);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function tooManyRequests(req, res) {
  res.status(429).json({ error: 'Too many signing requests, try again later' });
}

const signBurstLimiter = rateLimit({
  windowMs: envInt('RATE_LIMIT_BURST_WINDOW_MS', 60 * 1000),
  limit: envInt('RATE_LIMIT_BURST_MAX', 5),
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: tooManyRequests,
});

const signHourlyLimiter = rateLimit({
  windowMs: envInt('RATE_LIMIT_HOURLY_WINDOW_MS', 60 * 60 * 1000),
  limit: envInt('RATE_LIMIT_HOURLY_MAX', 20),
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: tooManyRequests,
});

module.exports = { signBurstLimiter, signHourlyLimiter };
