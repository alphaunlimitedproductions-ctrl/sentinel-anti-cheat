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
 * Module 3: Neural Packet Analyzer
 * 
 * Copyright (c) 2026 Glenn Lee Kowalski / Alpha Unlimited
 * All Rights Reserved.
 * 
 * Deep packet inspection using statistical analysis of network
 * traffic patterns. Cheat software creates distinctive traffic
 * signatures as it rapidly reads game memory and sends corrections.
 * 
 * RICOCHET gap addressed: RICOCHET has no real-time packet analysis.
 * Even encrypted cheat traffic creates detectable timing and volume
 * patterns. This module works WITHOUT decryption - it analyzes
 * the shape of traffic, not its content.
 * 
 * Key insight: When aimbot software calculates a correction and
 * sends it to the game, the corrected input travels through the
 * network as abnormally precise and rapid packets. Normal gameplay
 * generates 60-120 packets/sec. Cheat-assisted play generates
 * 300-800+ packets/sec during combat engagements.
 */

import type {
  TelemetryEvent,
  PacketTelemetry,
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

// Network analysis constants
const NORMAL_PACKET_RATE = 120;         // Packets/sec baseline
const CHEAT_PACKET_RATE = 300;          // Packets/sec anomaly threshold
const BURST_THRESHOLD = 15;             // Burst events per window
const MAX_PACKET_SIZE = 2048;           // Bytes - normal max payload
const OUT_OF_ORDER_THRESHOLD = 10;      // Percentage threshold
const DUPLICATE_THRESHOLD = 5;          // Percentage threshold
const SUSPICIOUS_PAYLOAD_THRESHOLD = 3; // Count threshold
const SCORE_THRESHOLD = 40;

export function analyzePackets(
  event: TelemetryEvent,
  config?: SentinelConfig
): DetectionResult | null {
  if (event.eventType !== "packet_data") return null;
  const data = event.data as PacketTelemetry;
  const baseline = getOrCreateBaseline(event.playerId, config);
  const flags: string[] = [];
  let score = 0;

  // CHECK 1: Packet Rate Analysis
  // Cheat software creates 2-5x normal packet rates during combat
  if (data.packetRate !== undefined) {
    const rateProfile = getMetricProfile(baseline, "packet.rate", config);
    pushSample(rateProfile, data.packetRate);
    const dev = deviatesFromBaseline(data.packetRate, rateProfile, config);

    if (data.packetRate > CHEAT_PACKET_RATE) {
      flags.push(
        `Packet rate ${data.packetRate}/s is ${(data.packetRate / NORMAL_PACKET_RATE).toFixed(1)}x ` +
        `normal (${NORMAL_PACKET_RATE}/s baseline). Cheat data exchange signature.`
      );
      score += 25;
    } else if (dev.deviates && dev.zScore > 2.5) {
      flags.push(
        `Packet rate spiked to ${data.packetRate}/s from player's baseline ` +
        `(z=${dev.zScore.toFixed(1)}). Combat-correlated traffic anomaly.`
      );
      score += 12;
    }
  }

  // CHECK 2: Burst Pattern Detection
  // Cheat polling creates characteristic burst patterns
  if (data.burstCount !== undefined && data.burstCount > BURST_THRESHOLD) {
    flags.push(
      `${data.burstCount} packet bursts detected in analysis window. ` +
      `Normal gameplay produces <${BURST_THRESHOLD}. Cheat polling pattern.`
    );
    score += 30;
  }

  // CHECK 3: Payload Size Anomalies
  // Cheat data piggybacked on legitimate packets inflates payload size
  if (data.avgPacketSize !== undefined && data.avgPacketSize > MAX_PACKET_SIZE) {
    flags.push(
      `Average packet size ${data.avgPacketSize}B exceeds normal maximum ` +
      `(${MAX_PACKET_SIZE}B). Additional data payload detected.`
    );
    score += 20;
  }

  // CHECK 4: Out-of-Order Packet Detection
  // Packet injection creates sequence number inconsistencies
  if (data.outOfOrder !== undefined && data.outOfOrder > OUT_OF_ORDER_THRESHOLD) {
    flags.push(
      `${data.outOfOrder}% of packets arrived out-of-order. Indicates ` +
      `packet injection or man-in-the-middle modification.`
    );
    score += 25;
  }

  // CHECK 5: Duplicate Packet Detection
  // Replay attacks resend captured packets
  if (data.duplicateRate !== undefined && data.duplicateRate > DUPLICATE_THRESHOLD) {
    flags.push(
      `${data.duplicateRate}% duplicate packets detected. Replay attack ` +
      `signature - captured packets being re-transmitted.`
    );
    score += 20;
  }

  // CHECK 6: Suspicious Payload Patterns
  // Known cheat communication signatures in packet structure
  if (data.suspiciousPayloads !== undefined &&
      data.suspiciousPayloads > SUSPICIOUS_PAYLOAD_THRESHOLD) {
    flags.push(
      `${data.suspiciousPayloads} suspicious payload patterns matched against ` +
      `known cheat communication signatures.`
    );
    score += 30;
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
  recordDetection(baseline, "PacketAnalysis", confidence);

  return {
    detected: true,
    module: "PacketAnalysis",
    cheatType: data.duplicateRate > DUPLICATE_THRESHOLD
      ? "packet_injection" : "network_manipulation",
    severity: score >= 80 ? "critical" : score >= 60 ? "high" : "medium",
    confidence,
    evidence: {
      metrics: {
        packetRate: data.packetRate,
        burstCount: data.burstCount,
        avgPacketSize: data.avgPacketSize,
        outOfOrder: data.outOfOrder,
      },
      flags,
      baselineSamples: (getMetricProfile(baseline, "packet.rate", config)).values.length,
      baselineDeviations: {},
      crossSignalCorrelation: correlation.correlatedModules,
    },
    description: `Packet analysis flagged ${flags.length} anomalies: ${flags.join("; ")}`,
    recommendedAction: resolveAction(confidence, config),
  };
}
