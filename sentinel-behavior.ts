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
 * Module 5: Behavioral Analysis (Wallhack / ESP Detection)
 * 
 * Copyright (c) 2026 Glenn Lee Kowalski / Alpha Unlimited
 * All Rights Reserved.
 * 
 * Detects information-advantage cheats by analyzing player behavior
 * for patterns that indicate knowledge of hidden game state:
 *   - Pre-firing around corners at enemies they shouldn't know about
 *   - Tracking enemy movement through solid walls
 *   - Predicting spawn locations with impossible accuracy
 *   - Reaction times below human neural transmission speed
 * 
 * RICOCHET gap addressed: RICOCHET uses honeypot decoys for wallhack
 * detection (50% effective). SENTINEL analyzes actual gameplay behavior
 * patterns across hundreds of engagements to build statistical proof
 * of information advantage. Much harder to evade.
 */

import type {
  TelemetryEvent,
  BehaviorTelemetry,
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

// Behavioral analysis constants
const HUMAN_MIN_REACTION = 100;         // Milliseconds - absolute floor
const AUTOMATION_MOVEMENT = 0.2;        // Movement entropy floor
const WALLHACK_PREFIRE_RATE = 40;       // Pre-fire percentage threshold
const WALL_TRACK_THRESHOLD = 5;         // Wall-tracking events threshold
const ESP_SPAWN_PREDICTION = 70;        // Spawn prediction accuracy threshold
const CHEAT_CAMERA_PATTERN = 0.8;       // Camera snap pattern threshold
const SCORE_THRESHOLD = 40;

export function analyzeBehavior(
  event: TelemetryEvent,
  config?: SentinelConfig
): DetectionResult | null {
  if (event.eventType !== "behavior_data") return null;
  const data = event.data as BehaviorTelemetry;
  const baseline = getOrCreateBaseline(event.playerId, config);
  const flags: string[] = [];
  let score = 0;

  // CHECK 1: Reaction Time
  // Human neural signal: eye -> brain -> arm takes minimum 100ms
  if (data.reactionTime !== undefined) {
    const reactionProfile = getMetricProfile(baseline, "behavior.reactionTime", config);
    pushSample(reactionProfile, data.reactionTime);
    const dev = deviatesFromBaseline(
      data.reactionTime, reactionProfile, config
    );

    if (data.reactionTime < HUMAN_MIN_REACTION) {
      flags.push(
        `Reaction time ${data.reactionTime}ms is below human neural ` +
        `transmission minimum (${HUMAN_MIN_REACTION}ms). Software-assisted ` +
        `target acquisition.`
      );
      score += 30;
    } else if (dev.deviates && dev.zScore < -2.0 && data.reactionTime < 150) {
      flags.push(
        `Reaction time ${data.reactionTime}ms dropped significantly from ` +
        `player baseline (z=${dev.zScore.toFixed(1)}). Possible assistance toggle.`
      );
      score += 15;
    }
  }

  // CHECK 2: Movement Entropy
  // Automated movement lacks the randomness of human decision-making
  if (data.movementEntropy !== undefined && data.movementEntropy < AUTOMATION_MOVEMENT) {
    flags.push(
      `Movement entropy ${data.movementEntropy.toFixed(3)} indicates ` +
      `path prediction or automated movement. Human movement entropy ` +
      `is typically 0.4-0.9.`
    );
    score += 20;
  }

  // CHECK 3: Pre-Firing Rate
  // Firing before visually acquiring target = information advantage
  if (data.preFiringRate !== undefined && data.preFiringRate > WALLHACK_PREFIRE_RATE) {
    flags.push(
      `Pre-firing rate ${data.preFiringRate.toFixed(1)}% indicates advance ` +
      `knowledge of enemy positions. Normal rate is 5-20%. Wallhack signature.`
    );
    score += 30;
  }

  // CHECK 4: Wall-Tracking Events
  // Camera tracking enemies through solid geometry
  if (data.wallTrackEvents !== undefined && data.wallTrackEvents > WALL_TRACK_THRESHOLD) {
    flags.push(
      `${data.wallTrackEvents} wall-tracking events: player's camera tracked ` +
      `enemies through solid walls/floors. ESP/wallhack confirmed.`
    );
    score += 35;
  }

  // CHECK 5: Spawn Prediction Accuracy
  // Knowing where enemies will spawn before they appear
  if (data.spawnPrediction !== undefined && data.spawnPrediction > ESP_SPAWN_PREDICTION) {
    flags.push(
      `Spawn prediction accuracy ${data.spawnPrediction.toFixed(1)}% indicates ` +
      `ESP (>${ESP_SPAWN_PREDICTION}%). Player consistently pre-positions ` +
      `for enemy spawns.`
    );
    score += 25;
  }

  // CHECK 6: Camera Snap Pattern
  // Snapping camera to enemies matches cheat overlay behavior
  if (data.cameraBehavior !== undefined && data.cameraBehavior > CHEAT_CAMERA_PATTERN) {
    flags.push(
      `Camera snap pattern ${(data.cameraBehavior * 100).toFixed(1)}% matches ` +
      `known wallhack/ESP overlay signatures.`
    );
    score += 20;
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
  recordDetection(baseline, "BehavioralAnalysis", confidence);

  return {
    detected: true,
    module: "BehavioralAnalysis",
    cheatType: score >= 70 ? "wallhack_esp" : "suspicious_behavior",
    severity: score >= 80 ? "critical" : score >= 60 ? "high" : "medium",
    confidence,
    evidence: {
      metrics: {
        reactionTime: data.reactionTime,
        preFiringRate: data.preFiringRate,
        wallTrackEvents: data.wallTrackEvents,
        spawnPrediction: data.spawnPrediction,
      },
      flags,
      baselineSamples: (getMetricProfile(baseline, "behavior.reactionTime", config)).values.length,
      baselineDeviations: {},
      crossSignalCorrelation: correlation.correlatedModules,
    },
    description: `Behavioral analysis flagged ${flags.length} anomalies: ${flags.join("; ")}`,
    recommendedAction: resolveAction(confidence, config),
  };
}
