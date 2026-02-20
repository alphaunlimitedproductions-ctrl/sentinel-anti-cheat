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
 * Core Type Definitions
 * 
 * Copyright (c) 2026 Glenn Lee Kowalski / Alpha Unlimited
 * All Rights Reserved.
 * Licensed for evaluation by Activision Publishing, Inc.
 * 
 * These types define the contract between game server telemetry
 * and the SENTINEL detection pipeline. Drop this file into your
 * game server's type system.
 */

// ============================================================
// TELEMETRY TYPES - What the game server sends to SENTINEL
// ============================================================

export interface TelemetryEvent {
  playerId: string;
  sessionId: string;
  lobbyId: string;
  matchId: string;
  timestamp: number;
  eventType: TelemetryEventType;
  data: TelemetryData;
}

export type TelemetryEventType =
  | "aim_data"
  | "input_data"
  | "packet_data"
  | "stats_data"
  | "behavior_data";

export type TelemetryData =
  | AimTelemetry
  | InputTelemetry
  | PacketTelemetry
  | StatsTelemetry
  | BehaviorTelemetry;

export interface AimTelemetry {
  snapAngle: number;           // Degrees of aim snap (0-180)
  trackingSmoothness: number;  // 0.0-1.0 tracking consistency
  headshotPct: number;         // Headshot percentage this engagement
  timeToTarget: number;        // Milliseconds to acquire target
  aimLockDuration: number;     // Milliseconds aim stayed locked
  targetSwitchSpeed: number;   // Milliseconds between target switches
  aimPath: Vector2[];          // Raw aim trajectory samples
  weaponId: string;            // Current weapon identifier
}

export interface InputTelemetry {
  inputEntropy: number;        // Shannon entropy of input stream (bits)
  timingVariance: number;      // Std dev of inter-input timing (ms)
  recoilPattern: number;       // 0.0-1.0 recoil compensation score
  microAdjustments: number;    // Micro-adjustments per second
  inputFrequency: number;      // Input polling rate (Hz)
  patternRepetition: number;   // 0.0-1.0 input pattern repetition
  rawInputs: InputSample[];    // Raw input samples for analysis
  deviceType: string;          // "keyboard_mouse" | "controller"
}

export interface PacketTelemetry {
  packetRate: number;          // Packets per second
  burstCount: number;          // Number of burst events in window
  avgPacketSize: number;       // Average payload size (bytes)
  outOfOrder: number;          // Percentage of out-of-order packets
  duplicateRate: number;       // Percentage of duplicate packets
  suspiciousPayloads: number;  // Count of anomalous payload patterns
  interArrivalTimes: number[]; // Microseconds between packets
}

export interface StatsTelemetry {
  kdRatio: number;             // Kill/death ratio this session
  winRate: number;             // Win percentage over recent matches
  accuracyZScore: number;      // Accuracy deviation from population
  headshotZScore: number;      // Headshot rate deviation
  spreeFrequency: number;      // Kill spree frequency (0.0-1.0)
  deathlessStreak: number;     // Current deathless kill streak
  matchesAnalyzed: number;     // How many matches in this window
}

export interface BehaviorTelemetry {
  reactionTime: number;        // Milliseconds to first shot
  movementEntropy: number;     // Movement randomness (0.0-1.0)
  preFiringRate: number;       // Pre-fire percentage
  wallTrackEvents: number;     // Tracking through solid geometry
  spawnPrediction: number;     // Spawn prediction accuracy (%)
  cameraBehavior: number;      // Camera snap pattern score (0.0-1.0)
  engagementDistance: number;  // Average engagement distance (m)
}

// ============================================================
// DETECTION TYPES - What SENTINEL returns
// ============================================================

export interface DetectionResult {
  detected: boolean;
  module: string;
  cheatType: CheatType;
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;          // 0.0-1.0
  evidence: DetectionEvidence;
  description: string;
  recommendedAction: ActionType;
}

export type CheatType =
  | "aimbot"
  | "aim_assist_abuse"
  | "cronus_zen"
  | "macro_script"
  | "network_manipulation"
  | "packet_injection"
  | "statistical_impossibility"
  | "wallhack_esp"
  | "suspicious_behavior";

export type ActionType =
  | "flag"
  | "shadow_ban"
  | "temporary_ban"
  | "permanent_ban"
  | "hardware_ban";

export interface DetectionEvidence {
  metrics: Record<string, number>;
  flags: string[];
  baselineSamples: number;
  baselineDeviations: Record<string, number>;
  crossSignalCorrelation: string[];
}

export interface Vector2 {
  x: number;
  y: number;
}

export interface InputSample {
  timestamp: number;
  rightStickX: number;
  rightStickY: number;
  leftStickX: number;
  leftStickY: number;
  triggerL2: number;
  triggerR2: number;
  deltaTime: number;
}

// ============================================================
// PLAYER BASELINE - Per-player behavioral profile
// ============================================================

export interface PlayerBaseline {
  playerId: string;
  createdAt: number;
  eventCount: number;
  metrics: Map<string, RollingSamples>; // Per-metric rolling windows
  recentDetections: TimestampedDetection[];
}

export interface RollingSamples {
  values: number[];
  maxSamples: number;
  mean: number;
  stddev: number;
}

export interface TimestampedDetection {
  module: string;
  confidence: number;
  timestamp: number;
}

// ============================================================
// CONFIGURATION
// ============================================================

export interface SentinelConfig {
  correlationWindowMs: number;    // Time window for cross-signal (default: 60000)
  baselineSamples: number;        // Rolling baseline size (default: 50)
  deviationThreshold: number;     // Z-score threshold (default: 2.5)
  minSamplesForBaseline: number;  // Minimum samples before baseline active (default: 5)
  autobanConfidence: number;      // Auto-ban threshold (default: 0.85)
  shadowbanConfidence: number;    // Shadow-ban threshold (default: 0.65)
  flagConfidence: number;         // Flag threshold (default: 0.40)
}
