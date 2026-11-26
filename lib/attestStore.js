const { redis } = require('./redis');

// Storage for App Attest challenges and device keys.
//
// Keys, all under the pk-server: prefix confirmed with Drew:
//   pk-server:attest:challenge:<challenge>  -> "1", TTL 5 minutes, single use
//   pk-server:attest:device:<keyId>         -> JSON { publicKey, signCount, createdAt }
//
// When Redis is configured the data is shared across every serverless
// instance. When it is not (local development) an in-memory Map is used
// instead, which is only accurate within a single process, exactly like
// the rate limiter fallback. Nothing here is a secret: the public key
// is public by design, and the challenge is a one-time random value.

const CHALLENGE_TTL_SECONDS = 5 * 60;

const memoryChallenges = new Map();
const memoryDevices = new Map();

function challengeKey(challenge) {
  return `pk-server:attest:challenge:${challenge}`;
}

function deviceKey(keyId) {
  return `pk-server:attest:device:${keyId}`;
}

async function storeChallenge(challenge) {
  if (redis) {
    await redis.set(challengeKey(challenge), '1', { ex: CHALLENGE_TTL_SECONDS });
  } else {
    memoryChallenges.set(challenge, Date.now() + CHALLENGE_TTL_SECONDS * 1000);
  }
}

// Atomically consume a challenge. Returns true only the first time a
// challenge is presented; a replayed or expired challenge returns false.
async function consumeChallenge(challenge) {
  if (redis) {
    // GETDEL is atomic: the challenge exists for exactly one caller.
    const value = await redis.getdel(challengeKey(challenge));
    return value !== null && value !== undefined;
  }
  const expiresAt = memoryChallenges.get(challenge);
  memoryChallenges.delete(challenge);
  return expiresAt !== undefined && expiresAt > Date.now();
}

async function saveDevice(keyId, publicKey) {
  const record = { publicKey, signCount: 0, createdAt: new Date().toISOString() };
  if (redis) {
    await redis.set(deviceKey(keyId), JSON.stringify(record));
  } else {
    memoryDevices.set(keyId, record);
  }
  return record;
}

async function getDevice(keyId) {
  if (redis) {
    const raw = await redis.get(deviceKey(keyId));
    if (!raw) return null;
    return typeof raw === 'string' ? JSON.parse(raw) : raw;
  }
  return memoryDevices.get(keyId) || null;
}

// Atomically advance the stored sign count, but only if the stored
// count still equals `expected`. Returns true on success, false if
// another request already advanced it (a replayed assertion).
async function advanceSignCount(keyId, expected, next) {
  if (redis) {
    const result = await redis.eval(
      `local raw = redis.call('GET', KEYS[1])
       if not raw then return 0 end
       local record = cjson.decode(raw)
       if record.signCount ~= tonumber(ARGV[1]) then return 0 end
       record.signCount = tonumber(ARGV[2])
       redis.call('SET', KEYS[1], cjson.encode(record))
       return 1`,
      [deviceKey(keyId)],
      [String(expected), String(next)]
    );
    return result === 1;
  }
  const record = memoryDevices.get(keyId);
  if (!record || record.signCount !== expected) return false;
  record.signCount = next;
  return true;
}

module.exports = { storeChallenge, consumeChallenge, saveDevice, getDevice, advanceSignCount };
