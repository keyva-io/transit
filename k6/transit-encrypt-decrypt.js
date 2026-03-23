// k6 scenario: Transit encrypt/decrypt under load
// Run: k6 run k6/transit-encrypt-decrypt.js
//
// Requires Keyva Transit running with a "payments" keyring:
//   KEYVA_MASTER_KEY=... cargo run -p transit-server -- --config transit.toml

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend } from "k6/metrics";
import encoding from "k6/encoding";

const BASE = __ENV.TRANSIT_REST_URL || "http://localhost:8099";
const KEYRING = __ENV.TRANSIT_KEYRING || "payments";

const encryptErrors = new Rate("encrypt_errors");
const decryptErrors = new Rate("decrypt_errors");
const encryptDuration = new Trend("encrypt_duration");
const decryptDuration = new Trend("decrypt_duration");

export const options = {
  scenarios: {
    transit_flow: {
      executor: "constant-arrival-rate",
      rate: 100,
      timeUnit: "1s",
      duration: "30s",
      preAllocatedVUs: 20,
      maxVUs: 50,
    },
  },
  thresholds: {
    encrypt_errors: ["rate<0.01"],
    decrypt_errors: ["rate<0.01"],
    encrypt_duration: ["p(95)<50"],
    decrypt_duration: ["p(95)<50"],
  },
};

export default function () {
  const headers = { "Content-Type": "application/json" };
  const plaintext = encoding.b64encode(
    `card-${__VU}-${__ITER}: 4111-1111-1111-1111`
  );

  // Encrypt
  const encRes = http.post(
    `${BASE}/v1/${KEYRING}/encrypt`,
    JSON.stringify({ plaintext, context: `user-${__VU}` }),
    { headers }
  );
  encryptDuration.add(encRes.timings.duration);
  const encOk = check(encRes, {
    "encrypt status 200": (r) => r.status === 200,
    "encrypt has ciphertext": (r) =>
      JSON.parse(r.body).ciphertext !== undefined,
  });
  encryptErrors.add(!encOk);
  if (!encOk) return;

  const ciphertext = JSON.parse(encRes.body).ciphertext;

  // Decrypt
  const decRes = http.post(
    `${BASE}/v1/${KEYRING}/decrypt`,
    JSON.stringify({ ciphertext, context: `user-${__VU}` }),
    { headers }
  );
  decryptDuration.add(decRes.timings.duration);
  const decOk = check(decRes, {
    "decrypt status 200": (r) => r.status === 200,
    "decrypt roundtrip matches": (r) =>
      JSON.parse(r.body).plaintext === plaintext,
  });
  decryptErrors.add(!decOk);
}
