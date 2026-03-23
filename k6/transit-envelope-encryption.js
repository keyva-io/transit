// k6 scenario: Transit envelope encryption (generate data key)
// Run: k6 run k6/transit-envelope-encryption.js
//
// Tests the envelope encryption pattern:
// 1. GENERATE_DATA_KEY → get plaintext DEK + wrapped DEK
// 2. "Encrypt locally" (simulated — we just verify the DEK exists)
// 3. DECRYPT the wrapped DEK → recover plaintext DEK
// 4. Verify they match

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend } from "k6/metrics";

const BASE = __ENV.TRANSIT_REST_URL || "http://localhost:8099";
const KEYRING = __ENV.TRANSIT_KEYRING || "payments";

const genErrors = new Rate("generate_dek_errors");
const unwrapErrors = new Rate("unwrap_dek_errors");
const genDuration = new Trend("generate_dek_duration");
const unwrapDuration = new Trend("unwrap_dek_duration");

export const options = {
  scenarios: {
    envelope: {
      executor: "constant-arrival-rate",
      rate: 50,
      timeUnit: "1s",
      duration: "20s",
      preAllocatedVUs: 10,
      maxVUs: 30,
    },
  },
  thresholds: {
    generate_dek_errors: ["rate<0.01"],
    unwrap_dek_errors: ["rate<0.01"],
    generate_dek_duration: ["p(95)<50"],
    unwrap_dek_duration: ["p(95)<50"],
  },
};

export default function () {
  const headers = { "Content-Type": "application/json" };

  // Generate data encryption key
  const genRes = http.post(
    `${BASE}/v1/${KEYRING}/generate-data-key`,
    JSON.stringify({ bits: 256 }),
    { headers }
  );
  genDuration.add(genRes.timings.duration);
  const genOk = check(genRes, {
    "generate status 200": (r) => r.status === 200,
    "has plaintext_key": (r) =>
      JSON.parse(r.body).plaintext_key !== undefined,
    "has wrapped_key": (r) => JSON.parse(r.body).wrapped_key !== undefined,
  });
  genErrors.add(!genOk);
  if (!genOk) return;

  const body = JSON.parse(genRes.body);

  // Unwrap (decrypt the wrapped DEK)
  const unwrapRes = http.post(
    `${BASE}/v1/${KEYRING}/decrypt`,
    JSON.stringify({ ciphertext: body.wrapped_key }),
    { headers }
  );
  unwrapDuration.add(unwrapRes.timings.duration);
  const unwrapOk = check(unwrapRes, {
    "unwrap status 200": (r) => r.status === 200,
    "unwrapped matches plaintext": (r) =>
      JSON.parse(r.body).plaintext === body.plaintext_key,
  });
  unwrapErrors.add(!unwrapOk);
}
