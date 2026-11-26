const { verifyAssertion } = require('node-app-attest');
const { consumeChallenge, getDevice, advanceSignCount } = require('../lib/attestStore');

// App Attest verification for POST /sign.
//
// The app sends three headers with a signing request:
//   X-App-Attest-Key-Id:     base64 key ID from DCAppAttestService.generateKey
//   X-App-Attest-Assertion:  base64 assertion from generateAssertion
//   X-App-Attest-Challenge:  the one-time challenge the assertion was made for
//
// The assertion is over the challenge string itself: on the app, the
// client data hash is SHA-256 of the challenge, and verifyAssertion is
// given the raw challenge as its payload. The challenge is single use,
// so a captured assertion cannot be replayed for a second pass.
//
// Dual mode, controlled by REQUIRE_ATTEST (default false):
//   false: requests with no attestation headers are allowed through
//     (old app versions keep working) and requests with a bad
//     attestation are rejected with 401.
//   true:  requests with no attestation headers are rejected with 426
//     and a please-update message, so old versions fail clearly
//     instead of silently.
// Attestation must fail closed once enforcement is on. Unlike rate
// limiting, a verification outage must not become a bypass, so a
// Redis error here rejects the request instead of allowing it.
//
// Bundle and team IDs are public identifiers from the PassKeepr
// project, not secrets. They default to AHanshaw.PassKeepr /
// NZDS56Z4Q9 and can be overridden with env vars.

const bundleIdentifier = process.env.APP_ATTEST_BUNDLE_ID || 'AHanshaw.PassKeepr';
const teamIdentifier = process.env.APP_ATTEST_TEAM_ID || 'NZDS56Z4Q9';
const allowDevelopmentEnvironment = process.env.APP_ATTEST_ALLOW_DEV_ENV === 'true';
const attestRequired = process.env.REQUIRE_ATTEST === 'true';

async function requireAttest(req, res, next) {
  const keyId = req.get('X-App-Attest-Key-Id');
  const assertion = req.get('X-App-Attest-Assertion');
  const challenge = req.get('X-App-Attest-Challenge');

  if (!keyId && !assertion && !challenge) {
    if (attestRequired) {
      return res.status(426).json({ error: 'App Attest required, please update PassKeepr' });
    }
    return next();
  }

  if (!keyId || !assertion || !challenge) {
    return res.status(401).json({ error: 'Invalid App Attest headers' });
  }

  try {
    const device = await getDevice(keyId);
    if (!device) {
      return res.status(401).json({ error: 'Unknown App Attest key, please re-register the device' });
    }

    const challengeOk = await consumeChallenge(challenge);
    if (!challengeOk) {
      return res.status(401).json({ error: 'Invalid or reused App Attest challenge' });
    }

    const { signCount } = verifyAssertion({
      assertion: Buffer.from(assertion, 'base64'),
      payload: challenge,
      publicKey: device.publicKey,
      bundleIdentifier,
      teamIdentifier,
      signCount: device.signCount,
    });

    const advanced = await advanceSignCount(keyId, device.signCount, signCount);
    if (!advanced) {
      return res.status(401).json({ error: 'Stale App Attest assertion' });
    }

    return next();
  } catch (err) {
    console.error('App Attest verification failed:', err);
    return res.status(401).json({ error: 'App Attest verification failed' });
  }
}

module.exports = { requireAttest, bundleIdentifier, teamIdentifier, allowDevelopmentEnvironment, requireAttestEnabled: attestRequired };
