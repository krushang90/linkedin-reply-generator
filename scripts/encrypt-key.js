#!/usr/bin/env node
/**
 * Encrypts a value with AES-256-GCM.
 * Usage:
 *   ENCRYPTION_KEY=your_key node scripts/encrypt-key.js sk-ant-api03-...
 *
 * Output: paste the printed string as ENCRYPTED_API_KEY in your .env
 */
import { createCipheriv, scryptSync, randomBytes } from "crypto";

const encryptionKey = process.env.ENCRYPTION_KEY;
const plaintext = process.argv[2];

if (!encryptionKey || !plaintext) {
  console.error("Usage: ENCRYPTION_KEY=<key> node scripts/encrypt-key.js <value-to-encrypt>");
  process.exit(1);
}

const salt = randomBytes(16);
const key = scryptSync(encryptionKey, salt, 32);
const iv = randomBytes(12);
const cipher = createCipheriv("aes-256-gcm", key, iv);

const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
const authTag = cipher.getAuthTag();

const result = [
  salt.toString("hex"),
  iv.toString("hex"),
  authTag.toString("hex"),
  encrypted.toString("hex"),
].join(":");

console.log("\nENCRYPTED_API_KEY=" + result);
console.log("\nPaste this into your .env file.");
