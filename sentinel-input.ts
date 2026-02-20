// ============================================================
// SENTINEL Anti-Cheat Detection Engine
// Copyright (c) 2026 Glenn Lee Kowalski / Alpha Unlimited
// All Rights Reserved.
//
// This software is proprietary and confidential. Unauthorized
// copying, distribution, modification, or use of this file,
// via any medium, is strictly prohibited.
//
// For licensing inquiries, contact: alphaunlimitedproductions@gmail.com
// ============================================================
/**
 * SENTINEL Anti-Cheat Detection System
 * Module 2: Cronus Zen / Script Device Detector
 * 
 * Copyright (c) 2026 Glenn Lee Kowalski / Alpha Unlimited
 * All Rights Reserved.
 * 
 * Microsecond-precision input timing analysis that detects
 * scripted recoil compensation, aim assist exploitation,
 * and inhuman input consistency patterns unique to:
 *   - Cronus Zen
 *   - XIM Matrix / XIM Apex
 *   - ReaSnow S1
 *   - Titan Two
 *   - Any USB pass-through script device
 * 
 * RICOCHET gap addressed: RICOCHET has ZERO Cronus detection.
 * These devices spoof legitimate controller identity and run
 * scripts externally. SENTINEL detects the behavioral fingerprint
 * of scripted inputs, not the hardware itself.
 * 
 * Key insight: Humans cannot produce inputs with <0.5ms timing
 * variance. Scripts execute at exactly 1ms or 2ms intervals.
 * This timing fingerprint is mathematically unforgivable.
 */

import type {
  TelemetryEvent,
  InputTelemetry,
  DetectionResult,
  SentinelConfig,
} from "./sentinel-types";
import {
  getOrCreateBaseline,
  getMetricProfile,
  pushSample,
  deviatesFromBaseline,
  calculateCrossSignalBonus,
  recordDetection,
  resolveAction,
  shannonEntropy,
} from "./sentinel-baseline";

// Cronus Zen detection constants
// NOTE: inputEntropy from telemetry is pre-computed Shannon entropy (0.0-1.0 normalized)
// Raw Shannon entropy in bits: Human = 4.2-6.8, Cronus = 2.1-3.5
// Normalized to 0.0-1.0 scale: Human > 0.5, Cronus < 0.35
const NORMALIZED_ENTROPY_FLOOR = 0.3;   // Normalized entropy - definite script
const HUMAN_MIN_TIMING_VARIANCE = 0.5;  // Milliseconds
const SCRIPT_RECOIL_THRESHOLD = 0.92;   // Perfect recoil compensation
const HUMAN_MAX_MICRO_ADJ = 200;        // Micro-adjustments per second
const HUMAN_MAX_INPUT_FREQ = 1000;      // Hz - USB polling rate norms
const AUTOMATION_REPETITION = 0.85;     // Pattern repetition threshold
const SCORE_THRESHOLD = 40;

export function analyzeInput(
  event: TelemetryEvent,
  config?: SentinelConfig
): DetectionResult | null {
  if (event.eventType !== "input_data") return null;
  const data = event.data as InputTelemetry;
  const baseline = getOrCreateBaseline(event.playerId, config);
  const flags: string[] = [];
  let score = 0;

  // CHECK 1: Normalized Input Entropy
  // Telemetry provides pre-computed normalized entropy (0.0-1.0 scale)
  // Human inputs: > 0.5 normalized (4.2-6.8 bits raw Shannon entropy)
  // Cronus scripts: < 0.35 normalized (2.1-3.5 bits raw)
  if (data.inputEntropy !== undefined) {
    const entropyProfile = getMetricProfile(baseline, "input.entropy", config);
    pushSample(entropyProfile, data.inputEntropy);
    const dev = deviatesFromBaseline(data.inputEntropy, entropyProfile, config);

    if (data.inputEntropy < NORMALIZED_ENTROPY_FLOOR) {
      flags.push(
        `Normalized input entropy ${data.inputEntropy.toFixed(3)} is far below human ` +
        `minimum (${NORMALIZED_ENTROPY_FLOOR}). Script device confirmed.`
      );
      score += 30;
    } else if (dev.deviates && dev.zScore < -2.0) {
      flags.push(
        `Input entropy dropped to ${data.inputEntropy.toFixed(3)} bits from player's ` +
        `baseline (z=${dev.zScore.toFixed(1)}). Possible script activation.`
      );
      score += 15;
    }
  }

  // CHECK 2: Inter-Input Timing Variance
  // Human thumb on analog stick: 8-15ms natural variance
  // Cronus Zen script loop: <0.1ms variance at 1ms/2ms intervals
  if (data.timingVariance !== undefined) {
    const timingProfile = getMetricProfile(baseline, "input.timingVariance", config);
    pushSample(timingProfile, data.timingVariance);
    if (data.timingVariance < HUMAN_MIN_TIMING_VARIANCE) {
      flags.push(
        `Input timing variance ${data.timingVariance.toFixed(3)}ms indicates ` +
        `mechanical input. Human minimum is ${HUMAN_MIN_TIMING_VARIANCE}ms. ` +
        `Script device timing fingerprint.`
      );
      score += 25;
    }
  }

  // CHECK 3: Recoil Compensation Pattern
  // Human: Gradual adaptation with overshoot and undershoot
  // Cronus: Frame-perfect inverse counter-movement (correlation > 0.92)
  if (data.recoilPattern !== undefined && data.recoilPattern > SCRIPT_RECOIL_THRESHOLD) {
    flags.push(
      `Recoil compensation ${(data.recoilPattern * 100).toFixed(1)}% matches ` +
      `script pattern (threshold: ${SCRIPT_RECOIL_THRESHOLD * 100}%). ` +
      `Perfect frame-level compensation is biomechanically impossible.`
    );
    score += 30;
  }

  // CHECK 4: Micro-Adjustment Frequency
  // Aim assist exploitation creates rapid oscillating inputs
  if (data.microAdjustments !== undefined && data.microAdjustments > HUMAN_MAX_MICRO_ADJ) {
    flags.push(
      `${data.microAdjustments} micro-adjustments/sec exceeds human motor ` +
      `control limit (${HUMAN_MAX_MICRO_ADJ}/s). Aim assist exploitation.`
    );
    score += 20;
  }

  // CHECK 5: Input Polling Frequency
  // Normal USB: 125-1000Hz. Cronus scripts often poll at 1000Hz+
  if (data.inputFrequency !== undefined && data.inputFrequency > HUMAN_MAX_INPUT_FREQ) {
    flags.push(
      `Input frequency ${data.inputFrequency}Hz exceeds standard USB polling ` +
      `rates. Abnormal device behavior detected.`
    );
    score += 15;
  }

  // CHECK 6: Input Pattern Repetition
  // Scripts produce identical input sequences repeatedly
  if (data.patternRepetition !== undefined && data.patternRepetition > AUTOMATION_REPETITION) {
    flags.push(
      `Input pattern repetition ${(data.patternRepetition * 100).toFixed(1)}% ` +
      `indicates automation. Human inputs never repeat above ` +
      `${AUTOMATION_REPETITION * 100}% over 30-second windows.`
    );
    score += 25;
  }

  // CROSS-SIGNAL CORRELATION
  const correlation = calculateCrossSignalBonus(baseline);
  if (correlation.bonus > 0) {
    score += correlation.bonus;
    flags.push(
      `Cross-signal: ${correlation.correlatedModules.join(" + ")} also flagged within 60s`
    );
  }

  if (score < SCORE_THRESHOLD) return null;

  const confidence = Math.min(score / 100, 0.99);
  recordDetection(baseline, "InputAnalysis", confidence);

  return {
    detected: true,
    module: "InputAnalysis",
    cheatType: score >= 70 ? "cronus_zen" : "macro_script",
    severity: score >= 80 ? "critical" : score >= 60 ? "high" : "medium",
    confidence,
    evidence: {
      metrics: {
        inputEntropy: data.inputEntropy,
        timingVariance: data.timingVariance,
        recoilPattern: data.recoilPattern,
        microAdjustments: data.microAdjustments,
      },
      flags,
      baselineSamples: (getMetricProfile(baseline, "input.entropy", config)).values.length,
      baselineDeviations: {},
      crossSignalCorrelation: correlation.correlatedModules,
    },
    description: `Input analysis detected ${flags.length} anomalies: ${flags.join("; ")}`,
    recommendedAction: resolveAction(confidence, config),
  };
}
