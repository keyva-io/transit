// k6 scenario: Transit key rotation + rewrap workflow
// Run: k6 run k6/transit-rotate-rewrap.js
//
// Tests the rotation workflow: encrypt → rotate → old ciphertext still
// decrypts → rewrap migrates to new key → verify new version.

import http from "k6/http";
import { check, sleep } from "k6";
import { Counter } from "k6/metrics";
import encoding from "k6/encoding";

const BASE = __ENV.TRANSIT_REST_URL || "http://localhost:8099";
const KEYRING = __ENV.TRANSIT_KEYRING || "payments";

const rewrapCount = new Counter("rewrap_operations");

export const options = {
  scenarios: {
    rotation_workflow: {
      executor: "per-vu-iterations",
      vus: 1,
      iterations: 3,
    },
  },
  thresholds: {
    checks: ["rate==1"],
  },
};

export default function () {
  const headers = { "Content-Type": "application/json" };
  const plaintext = encoding.b64encode(`secret-data-${__ITER}`);

  // Step 1: Encrypt with current key
  const enc1 = http.post(
    `${BASE}/v1/${KEYRING}/encrypt`,
    JSON.stringify({ plaintext }),
    { headers }
  );
  check(enc1, {
    "encrypt 1 ok": (r) => r.status === 200,
  });
  const ct1 = JSON.parse(enc1.body).ciphertext;
  const v1 = JSON.parse(enc1.body).key_version;

  // Step 2: Rotate
  const rotateRes = http.post(
    `${BASE}/v1/${KEYRING}/rotate`,
    JSON.stringify({}),
    { headers }
  );
  check(rotateRes, {
    "rotate ok": (r) => r.status === 200,
  });

  // Step 3: Encrypt with new key
  const enc2 = http.post(
    `${BASE}/v1/${KEYRING}/encrypt`,
    JSON.stringify({ plaintext }),
    { headers }
  );
  check(enc2, {
    "encrypt 2 ok": (r) => r.status === 200,
    "encrypt 2 uses new version": (r) =>
      JSON.parse(r.body).key_version > v1,
  });
  const ct2 = JSON.parse(enc2.body).ciphertext;

  // Step 4: Old ciphertext still decrypts (old key is Draining)
  const dec1 = http.post(
    `${BASE}/v1/${KEYRING}/decrypt`,
    JSON.stringify({ ciphertext: ct1 }),
    { headers }
  );
  check(dec1, {
    "old ciphertext decrypts": (r) =>
      r.status === 200 && JSON.parse(r.body).plaintext === plaintext,
  });

  // Step 5: Rewrap old ciphertext to new key
  const rewrapRes = http.post(
    `${BASE}/v1/${KEYRING}/rewrap`,
    JSON.stringify({ ciphertext: ct1 }),
    { headers }
  );
  check(rewrapRes, {
    "rewrap ok": (r) => r.status === 200,
    "rewrap uses new version": (r) =>
      JSON.parse(r.body).key_version > v1,
  });
  rewrapCount.add(1);

  // Step 6: Rewrapped ciphertext decrypts
  const rewrappedCt = JSON.parse(rewrapRes.body).ciphertext;
  const decRewrapped = http.post(
    `${BASE}/v1/${KEYRING}/decrypt`,
    JSON.stringify({ ciphertext: rewrappedCt }),
    { headers }
  );
  check(decRewrapped, {
    "rewrapped decrypts": (r) =>
      r.status === 200 && JSON.parse(r.body).plaintext === plaintext,
  });

  sleep(0.5);
}
