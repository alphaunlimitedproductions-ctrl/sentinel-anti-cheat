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
 * Module 4: Statistical Impossibility Engine
 * 
 * Copyright (c) 2026 Glenn Lee Kowalski / Alpha Unlimited
 * All Rights Reserved.
 * 
 * Real-time Bayesian analysis combining accuracy, headshot ratio,
 * reaction time, and engagement data. Flags combinations that are
 * statistically impossible for human players at ANY skill level.
 * 
 * RICOCHET gap addressed: RICOCHET uses ML models trained on
 * population data, which means subtle cheaters configured with
 * "human-like" settings slip through. SENTINEL tracks INDIVIDUAL
 * player baselines, so sudden skill jumps within the same player
 * are caught even if the absolute values look normal.
 * 
 * Key insight: A player who averages 1.5 K/D suddenly playing at
 * 12.0 K/D is suspicious even though 12.0 K/D could theoretically
 * be achieved by a professional player. It's the CHANGE that matters.
 */

import type {
  TelemetryEvent,
  StatsTelemetry,
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

// Statistical impossibility constants
const IMPOSSIBLE_KD = 8.0;             // No human maintains this consistently
const IMPOSSIBLE_WIN_RATE = 85;         // Win rate ceiling
const EXTREME_Z_SCORE = 3.5;           // Sigma threshold for impossibility
const ANOMALOUS_SPREE = 0.6;           // Kill spree frequency threshold
const INHUMAN_DEATHLESS = 40;           // Deathless streak threshold
const SCORE_THRESHOLD = 40;

export function analyzeStats(
  event: TelemetryEvent,
  config?: SentinelConfig
): DetectionResult | null {
  if (event.eventType !== "stats_data") return null;
  const data = event.data as StatsTelemetry;
  const baseline = getOrCreateBaseline(event.playerId, config);
  const flags: string[] = [];
  let score = 0;

  // CHECK 1: K/D Ratio Analysis
  // Track against player's own historical K/D
  if (data.kdRatio !== undefined) {
    const kdProfile = getMetricProfile(baseline, "stats.kdRatio", config);
    pushSample(kdProfile, data.kdRatio);
    const dev = deviatesFromBaseline(data.kdRatio, kdProfile, config);

    if (data.kdRatio > IMPOSSIBLE_KD) {
      flags.push(
        `K/D ratio ${data.kdRatio.toFixed(2)} is statistically impossible ` +
        `to maintain (>${IMPOSSIBLE_KD}). Even top 0.01% players average 4-6.`
      );
      score += 30;
    } else if (dev.deviates && dev.zScore > 2.5 && data.kdRatio > 4) {
      flags.push(
        `K/D ratio ${data.kdRatio.toFixed(2)} spiked from this player's ` +
        `baseline (z=${dev.zScore.toFixed(1)}). Sudden skill jump detected.`
      );
      score += 15;
    }
  }

  // CHECK 2: Win Rate Analysis
  if (data.winRate !== undefined && data.winRate > IMPOSSIBLE_WIN_RATE) {
    flags.push(
      `Win rate ${data.winRate.toFixed(1)}% over ${data.matchesAnalyzed || "N/A"} ` +
      `matches exceeds statistical bounds (>${IMPOSSIBLE_WIN_RATE}%).`
    );
    score += 20;
  }

  // CHECK 3: Accuracy Z-Score
  // How far this player's accuracy deviates from population distribution
  if (data.accuracyZScore !== undefined && data.accuracyZScore > EXTREME_Z_SCORE) {
    const descriptor = data.accuracyZScore > 4 ? "impossible" : "extreme";
    flags.push(
      `Accuracy z-score ${data.accuracyZScore.toFixed(2)} is ${descriptor} ` +
      `(>${EXTREME_Z_SCORE} sigma from population mean). ` +
      `Probability of legitimate play: <0.02%.`
    );
    score += 25;
  }

  // CHECK 4: Headshot Z-Score
  if (data.headshotZScore !== undefined && data.headshotZScore > EXTREME_Z_SCORE) {
    flags.push(
      `Headshot z-score ${data.headshotZScore.toFixed(2)} exceeds normal ` +
      `distribution (>${EXTREME_Z_SCORE} sigma). Automated headshot targeting.`
    );
    score += 25;
  }

  // CHECK 5: Kill Spree Frequency
  if (data.spreeFrequency !== undefined && data.spreeFrequency > ANOMALOUS_SPREE) {
    flags.push(
      `Kill spree frequency ${(data.spreeFrequency * 100).toFixed(1)}% is ` +
      `anomalous (>${ANOMALOUS_SPREE * 100}%). Consistent domination pattern.`
    );
    score += 15;
  }

  // CHECK 6: Deathless Streak
  if (data.deathlessStreak !== undefined && data.deathlessStreak > INHUMAN_DEATHLESS) {
    flags.push(
      `${data.deathlessStreak}-kill deathless streak exceeds historical ` +
      `records. Combined with other metrics, indicates assistance.`
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
  recordDetection(baseline, "StatisticalAnalysis", confidence);

  return {
    detected: true,
    module: "StatisticalAnalysis",
    cheatType: "statistical_impossibility",
    severity: score >= 80 ? "critical" : score >= 60 ? "high" : "medium",
    confidence,
    evidence: {
      metrics: {
        kdRatio: data.kdRatio,
        winRate: data.winRate,
        accuracyZScore: data.accuracyZScore,
        headshotZScore: data.headshotZScore,
      },
      flags,
      baselineSamples: (getMetricProfile(baseline, "stats.kdRatio", config)).values.length,
      baselineDeviations: {},
      crossSignalCorrelation: correlation.correlatedModules,
    },
    description: `Statistical analysis flagged ${flags.length} impossibilities: ${flags.join("; ")}`,
    recommendedAction: resolveAction(confidence, config),
  };
}
