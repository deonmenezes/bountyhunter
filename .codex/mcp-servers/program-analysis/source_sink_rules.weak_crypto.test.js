"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matches(id, text) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `no rule registered with id ${id}`);
  // Rules use a global regex with internal state (lastIndex); test against a
  // fresh copy each call so repeated assertions don't interfere.
  const re = new RegExp(rule.pattern.source, rule.pattern.flags);
  return re.test(text);
}

test("js.crypto.weak_hash flags MD5/SHA1 createHash calls", () => {
  assert.equal(
    matches("js.crypto.weak_hash", "crypto.createHash('md5')"),
    true,
  );
  assert.equal(
    matches("js.crypto.weak_hash", 'crypto.createHash("sha1")'),
    true,
  );
  assert.equal(
    matches("js.crypto.weak_hash", "crypto.createHash('sha256')"),
    false,
  );
});

test("js.crypto.weak_cipher flags deprecated createCipher and broken algorithm ids", () => {
  assert.equal(
    matches("js.crypto.weak_cipher", "crypto.createCipher('aes-256-cbc', key)"),
    true,
  );
  assert.equal(
    matches(
      "js.crypto.weak_cipher",
      "crypto.createCipheriv('des-ede3', key, iv)",
    ),
    true,
  );
  assert.equal(
    matches(
      "js.crypto.weak_cipher",
      "crypto.createCipheriv('aes-256-gcm', key, iv)",
    ),
    false,
  );
});

test("py.crypto.weak_hash flags hashlib.md5/sha1", () => {
  assert.equal(matches("py.crypto.weak_hash", "hashlib.md5(data)"), true);
  assert.equal(matches("py.crypto.weak_hash", "hashlib.sha1(data)"), true);
  assert.equal(matches("py.crypto.weak_hash", "hashlib.sha256(data)"), false);
});

test("py.crypto.weak_cipher flags DES/ARC4/Blowfish and ECB mode", () => {
  assert.equal(
    matches("py.crypto.weak_cipher", "DES.new(key, DES.MODE_ECB)"),
    true,
  );
  assert.equal(matches("py.crypto.weak_cipher", "ARC4.new(key)"), true);
  assert.equal(
    matches("py.crypto.weak_cipher", "AES.new(key, AES.MODE_GCM)"),
    false,
  );
});

test("go.crypto.weak_hash_cipher flags md5/sha1/des/rc4 usage", () => {
  assert.equal(matches("go.crypto.weak_hash_cipher", "md5.Sum(data)"), true);
  assert.equal(matches("go.crypto.weak_hash_cipher", "sha1.New()"), true);
  assert.equal(
    matches("go.crypto.weak_hash_cipher", "des.NewCipher(key)"),
    true,
  );
  assert.equal(
    matches("go.crypto.weak_hash_cipher", "sha256.Sum256(data)"),
    false,
  );
});

test("java.crypto.weak_hash flags MessageDigest MD5/SHA1", () => {
  assert.equal(
    matches("java.crypto.weak_hash", 'MessageDigest.getInstance("MD5")'),
    true,
  );
  assert.equal(
    matches("java.crypto.weak_hash", 'MessageDigest.getInstance("SHA-256")'),
    false,
  );
});

test("java.crypto.weak_cipher flags DES/RC4/ECB Cipher instances", () => {
  assert.equal(
    matches("java.crypto.weak_cipher", 'Cipher.getInstance("DES")'),
    true,
  );
  assert.equal(
    matches(
      "java.crypto.weak_cipher",
      'Cipher.getInstance("AES/ECB/PKCS5Padding")',
    ),
    true,
  );
  assert.equal(
    matches(
      "java.crypto.weak_cipher",
      'Cipher.getInstance("AES/GCM/NoPadding")',
    ),
    false,
  );
});
