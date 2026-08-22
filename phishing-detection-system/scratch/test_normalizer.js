/**
 * scratch/test_normalizer.js
 * Verification test suite for PhishGuardNormalizer API parsing layer.
 */

const { PhishGuardNormalizer, normalizeScanResult, getModelDisplay, normalizeRiskScore, normalizeConfidence, normalizeVerdict } = require('../chrome-extension/normalizer.js');

console.log("==================================================");
console.log("PHISHGUARD AI NORMALIZER TEST SUITE");
console.log("==================================================\n");

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`[PASS] ${message}`);
    passed++;
  } else {
    console.error(`[FAIL] ${message}`);
    failed++;
  }
}

// 1. Model Display Formats (A - D & Null)
assert(getModelDisplay("cnn_bilstm") === "DL-CNN-BiLSTM", "Format A: 'cnn_bilstm' -> 'DL-CNN-BiLSTM'");
assert(getModelDisplay("rnn_gan") === "DL-RNN-GAN", "Format A: 'rnn_gan' -> 'DL-RNN-GAN'");
assert(getModelDisplay("RNN-GAN") === "RNN-GAN", "Format B: 'RNN-GAN' -> 'RNN-GAN'");
assert(getModelDisplay({ name: "RNN-GAN", version: "v1.0" }) === "RNN-GAN v1.0", "Format C: { name: 'RNN-GAN', version: 'v1.0' } -> 'RNN-GAN v1.0'");
assert(getModelDisplay({ architecture: "BiLSTM", type: "Deep Learning", version: "v2" }) === "BiLSTM v2", "Format D: { architecture: 'BiLSTM', type: 'Deep Learning', version: 'v2' } -> 'BiLSTM v2'");
assert(getModelDisplay(null) === "Deep Learning", "Null model -> 'Deep Learning'");
assert(getModelDisplay({}) === "Deep Learning", "Empty object model -> 'Deep Learning'");

// 2. Risk Score Normalization
assert(normalizeRiskScore(15.1) === 15.1, "Risk float 15.1 -> 15.1");
assert(normalizeRiskScore("15.1") === 15.1, "Risk string '15.1' -> 15.1");
assert(normalizeRiskScore("120") === 100.0, "Risk > 100 clamped to 100.0");
assert(normalizeRiskScore("-5") === 0.0, "Risk < 0 clamped to 0.0");
assert(normalizeRiskScore("invalid") === null, "Invalid risk -> null");
assert(normalizeRiskScore(null) === null, "Null risk -> null");

// 3. Confidence Normalization
assert(normalizeConfidence(0.96) === 96.0, "Fractional confidence 0.96 -> 96.0%");
assert(normalizeConfidence(96.0) === 96.0, "Percentage confidence 96.0 -> 96.0%");
assert(normalizeConfidence("0.85") === 85.0, "String fractional '0.85' -> 85.0%");
assert(normalizeConfidence(null) === null, "Null confidence -> null");

// 4. Verdict Normalization
assert(normalizeVerdict("phishing") === "PHISHING", "Verdict 'phishing' -> 'PHISHING'");
assert(normalizeVerdict("safe") === "SAFE", "Verdict 'safe' -> 'SAFE'");
assert(normalizeVerdict("medium") === "SUSPICIOUS", "Verdict 'medium' -> 'SUSPICIOUS'");
assert(normalizeVerdict("CRITICAL") === "PHISHING", "Verdict 'CRITICAL' -> 'PHISHING'");
assert(normalizeVerdict(null) === "UNKNOWN", "Null verdict -> 'UNKNOWN'");

// 5. Full Payload Normalization (Complete Raw Result)
const rawA = {
  success: true,
  scan_id: "scan_999",
  url: "https://google.com",
  verdict: "safe",
  risk_score: "0.3",
  confidence: 0.997,
  model: { name: "DL-CNN-BiLSTM", version: "RNN-GAN-DL-v2.0" },
  inference_time_ms: "15.09"
};

const normA = normalizeScanResult(rawA);
assert(normA.success === true, "normA.success is true");
assert(normA.scanId === "scan_999", "normA.scanId is 'scan_999'");
assert(normA.verdict === "SAFE", "normA.verdict is 'SAFE'");
assert(normA.riskScore === 0.3, "normA.riskScore is 0.3");
assert(normA.confidence === 99.7, "normA.confidence is 99.7");
assert(normA.modelDisplay === "DL-CNN-BiLSTM RNN-GAN-DL-v2.0", "normA.modelDisplay is formatted cleanly");
assert(normA.inferenceTimeMs === 15.1, "normA.inferenceTimeMs is 15.1");

// 6. Malformed Payload Test (Zero Crash Test)
const rawMalformed = {
  model: { invalid_key: 123 },
  risk_score: undefined,
  verdict: 12345
};

const normMalformed = normalizeScanResult(rawMalformed);
assert(normMalformed.verdict === "UNKNOWN", "Malformed verdict -> 'UNKNOWN'");
assert(normMalformed.modelDisplay === "Deep Learning", "Malformed model -> 'Deep Learning'");
assert(normMalformed.riskScore === null, "Malformed risk -> null");

console.log("\n==================================================");
console.log(`TEST SUMMARY: ${passed} PASSED | ${failed} FAILED`);
console.log("==================================================");

if (failed > 0) {
  process.exit(1);
}
