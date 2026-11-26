const express = require('express');
const crypto = require('crypto');
const { verifyAttestation } = require('node-app-attest');
const { storeChallenge, consumeChallenge, saveDevice } = require('../lib/attestStore');
const { bundleIdentifier, teamIdentifier, allowDevelopmentEnvironment } = require('../middleware/appAttest');

var router = express.Router();

// One-time challenge for App Attest. The app requests this before
// attesting a new key and before every signing request, and the
// challenge is single use with a 5 minute TTL.
router.get('/challenge', async (req, res) => {
  const challenge = crypto.randomUUID();
  try {
    await storeChallenge(challenge);
  } catch (err) {
    console.error('Failed to store App Attest challenge:', err);
    return res.status(500).json({ error: 'Could not issue challenge' });
  }
  res.json({ challenge });
});

// Register a new device key. The app sends the key ID, the attestation
// object from DCAppAttestService.attestKey, and the challenge it was
// made for. On success the device public key is stored with sign
// count 0, ready for per-sign assertions.
router.post('/', express.json(), async (req, res) => {
  const { keyId, attestation, challenge } = req.body || {};
  if (!keyId || !attestation || !challenge) {
    return res.status(400).json({ error: 'keyId, attestation and challenge are required' });
  }

  try {
    const challengeOk = await consumeChallenge(challenge);
    if (!challengeOk) {
      return res.status(401).json({ error: 'Invalid or reused App Attest challenge' });
    }

    const result = verifyAttestation({
      attestation: Buffer.from(attestation, 'base64'),
      challenge,
      keyId,
      bundleIdentifier,
      teamIdentifier,
      allowDevelopmentEnvironment,
    });

    await saveDevice(result.keyId, result.publicKey);
    res.sendStatus(204);
  } catch (err) {
    console.error('App Attest registration failed:', err);
    res.status(401).json({ error: 'App Attest verification failed' });
  }
});

module.exports = router;
