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
 * Module 1: Aim Trajectory Physics Validator
 * 
 * Copyright (c) 2026 Glenn Lee Kowalski / Alpha Unlimited
 * All Rights Reserved.
 * 
 * Validates aim movement against human biomechanical models.
 * Detects impossible acceleration, deceleration, and angular
 * velocity patterns that violate human motor control limits.
 * 
 * RICOCHET gap addressed: Catches CV aimbots and DMA cheats
 * that RICOCHET misses because they never touch game memory.
 * Even if the aimbot runs on external hardware, the resulting
 * aim trajectory still violates physics of human arm movement.
 * 
 * Detection targets:
 *   - Memory-based aimbots (snap angles, lock-on)
 *   - Computer vision aimbots (inhuman tracking smoothness)
 *   - DMA aimbots (impossible time-to-target)
 *   - Private/subtle aimbots (baseline deviation over time)
 */

import type {
  TelemetryEvent,
  AimTelemetry,
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
} from "./sentinel-baseline";

// Human biomechanical constants (validated against FPS research)
const HUMAN_MAX_SNAP_ANGLE = 120;       // Degrees - maximum human snap aim
const HUMAN_MIN_REACTION_MS = 80;       // Milliseconds - fastest human reaction
const INHUMAN_TRACKING = 0.95;          // Tracking smoothness ceiling
const INHUMAN_SWITCH_MS = 50;           // Target switch speed floor
const AIM_LOCK_SUSPECT_MS = 2000;       // Sustained aim lock threshold
const SCORE_THRESHOLD = 40;             // Minimum score to trigger detection

export function analyzeAim(
  event: TelemetryEvent,
  config?: SentinelConfig
): DetectionResult | null {
  if (event.eventType !== "aim_data") return null;
  const data = event.data as AimTelemetry;
  const baseline = getOrCreateBaseline(event.playerId, config);
  const flags: string[] = [];
  let score = 0;

  // CHECK 1: Snap Angle Analysis
  // Aimbots snap to targets with angles that exceed human wrist rotation speed
  if (data.snapAngle !== undefined) {
    const snapProfile = getMetricProfile(baseline, "aim.snapAngle", config);
    pushSample(snapProfile, data.snapAngle);
    const dev = deviatesFromBaseline(data.snapAngle, snapProfile, config);

    if (data.snapAngle > HUMAN_MAX_SNAP_ANGLE) {
      flags.push(
        `Snap angle ${data.snapAngle.toFixed(1)} deg exceeds human biomechanical ` +
        `limit (${HUMAN_MAX_SNAP_ANGLE} deg). Aimbot signature detected.`
      );
      score += 30;
    } else if (dev.deviates && dev.zScore > 2.0 && data.snapAngle > 60) {
      flags.push(
        `Snap angle ${data.snapAngle.toFixed(1)} deg deviates from this player's ` +
        `baseline (z=${dev.zScore.toFixed(1)}). Possible toggled aimbot.`
      );
      score += 15;
    }
  }

  // CHECK 2: Tracking Smoothness
  // Human tracking has natural jitter. CV aimbots produce unnaturally smooth tracking
  if (data.trackingSmoothness !== undefined) {
    const trackProfile = getMetricProfile(baseline, "aim.trackingSmoothness", config);
    pushSample(trackProfile, data.trackingSmoothness);
    const dev = deviatesFromBaseline(
      data.trackingSmoothness, trackProfile, config
    );

    if (data.trackingSmoothness > INHUMAN_TRACKING) {
      flags.push(
        `Tracking smoothness ${(data.trackingSmoothness * 100).toFixed(1)}% exceeds ` +
        `human capability (>${INHUMAN_TRACKING * 100}%). CV aimbot signature.`
      );
      score += 25;
    } else if (dev.deviates && dev.zScore > 2.0 && data.trackingSmoothness > 0.8) {
      flags.push(
        `Tracking smoothness spiked to ${(data.trackingSmoothness * 100).toFixed(1)}% ` +
        `from baseline (z=${dev.zScore.toFixed(1)}). Intermittent assist detected.`
      );
      score += 12;
    }
  }

  // CHECK 3: Headshot Rate
  // Statistical impossibility check against population distribution
  if (data.headshotPct !== undefined && data.headshotPct > 65) {
    flags.push(
      `Headshot rate ${data.headshotPct.toFixed(1)}% exceeds 99.9th percentile (>65%). ` +
      `Even professional players average 25-40%.`
    );
    score += 20;
  }

  // CHECK 4: Time-to-Target
  // Below 80ms is faster than human neural signal transmission
  if (data.timeToTarget !== undefined && data.timeToTarget < HUMAN_MIN_REACTION_MS) {
    flags.push(
      `Time-to-target ${data.timeToTarget}ms is below human neural transmission ` +
      `minimum (${HUMAN_MIN_REACTION_MS}ms). Hardware-assisted targeting.`
    );
    score += 25;
  }

  // CHECK 5: Aim Lock Duration
  // Sustained perfect tracking indicates software assistance
  if (data.aimLockDuration !== undefined && data.aimLockDuration > AIM_LOCK_SUSPECT_MS) {
    flags.push(
      `Aim locked on target for ${data.aimLockDuration}ms. Humans cannot maintain ` +
      `perfect lock beyond ${AIM_LOCK_SUSPECT_MS}ms during movement.`
    );
    score += 15;
  }

  // CHECK 6: Target Switch Speed
  // Instantaneous target switching is physically impossible
  if (data.targetSwitchSpeed !== undefined && data.targetSwitchSpeed < INHUMAN_SWITCH_MS) {
    flags.push(
      `Target switch in ${data.targetSwitchSpeed}ms. Human minimum is ~${INHUMAN_SWITCH_MS}ms ` +
      `due to visual processing and motor response latency.`
    );
    score += 20;
  }

  // CROSS-SIGNAL CORRELATION
  // If other modules flagged this player recently, boost confidence
  const correlation = calculateCrossSignalBonus(baseline);
  if (correlation.bonus > 0) {
    score += correlation.bonus;
    flags.push(
      `Cross-signal: ${correlation.correlatedModules.join(" + ")} also flagged within 60s`
    );
  }

  if (score < SCORE_THRESHOLD) return null;

  const confidence = Math.min(score / 100, 0.99);
  recordDetection(baseline, "AimAnalysis", confidence);

  return {
    detected: true,
    module: "AimAnalysis",
    cheatType: score >= 80 ? "aimbot" : "aim_assist_abuse",
    severity: score >= 80 ? "critical" : score >= 60 ? "high" : "medium",
    confidence,
    evidence: {
      metrics: {
        snapAngle: data.snapAngle,
        trackingSmoothness: data.trackingSmoothness,
        headshotPct: data.headshotPct,
        timeToTarget: data.timeToTarget,
      },
      flags,
      baselineSamples: (getMetricProfile(baseline, "aim.snapAngle", config)).values.length,
      baselineDeviations: {},
      crossSignalCorrelation: correlation.correlatedModules,
    },
    description: `Aim analysis flagged ${flags.length} anomalies: ${flags.join("; ")}`,
    recommendedAction: resolveAction(confidence, config),
  };
}
