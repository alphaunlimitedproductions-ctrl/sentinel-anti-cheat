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
 * Integration Entry Point
 * 
 * Copyright (c) 2026 Glenn Lee Kowalski / Alpha Unlimited
 * All Rights Reserved.
 * 
 * This is the main file that ties all modules together.
 * Drop this into your game server and call processTelemetry()
 * for every telemetry event your game generates.
 * 
 * INTEGRATION STEPS:
 * 1. Copy all sentinel-*.ts files into your server codebase
 * 2. Import { processTelemetry, onDetection } from "./sentinel-core"
 * 3. Hook your game's telemetry pipeline to call processTelemetry()
 * 4. Register onDetection() callback to handle bans/alerts
 * 5. Configure thresholds in SentinelConfig for your game
 * 
 * REQUIREMENTS:
 * - TypeScript 4.5+ or JavaScript (transpile with tsc)
 * - Node.js 16+ (server-side only)
 * - No external dependencies - fully self-contained
 * - For distributed servers: replace Map with Redis/Memcached
 */

import type { TelemetryEvent, DetectionResult, SentinelConfig } from "./sentinel-types";
import { analyzeAim } from "./sentinel-aim";
import { analyzeInput } from "./sentinel-input";
import { analyzePackets } from "./sentinel-packets";
import { analyzeStats } from "./sentinel-stats";
import { analyzeBehavior } from "./sentinel-behavior";
import { getPipelineState } from "./sentinel-baseline";

// Registry of all detection modules
const MODULES = [
  { name: "AimAnalysis",        handler: analyzeAim },
  { name: "InputAnalysis",      handler: analyzeInput },
  { name: "PacketAnalysis",     handler: analyzePackets },
  { name: "StatisticalAnalysis", handler: analyzeStats },
  { name: "BehavioralAnalysis", handler: analyzeBehavior },
];

// Detection callback type
type DetectionCallback = (
  detection: DetectionResult,
  event: TelemetryEvent
) => void | Promise<void>;

let detectionCallback: DetectionCallback | null = null;

/**
 * Register a callback that fires whenever a cheat is detected.
 * Use this to trigger bans, alerts, logging, etc.
 * 
 * Example:
 *   onDetection(async (detection, event) => {
 *     if (detection.recommendedAction === "permanent_ban") {
 *       await banPlayer(event.playerId, detection.description);
 *     }
 *     await logDetection(detection);
 *     broadcastToAdminDashboard(detection);
 *   });
 */
export function onDetection(callback: DetectionCallback): void {
  detectionCallback = callback;
}

/**
 * Process a single telemetry event through all detection modules.
 * Call this for every game event your server generates.
 * 
 * Example:
 *   // In your game server's telemetry handler:
 *   gameServer.on("telemetry", async (rawEvent) => {
 *     const results = await processTelemetry({
 *       playerId: rawEvent.player.id,
 *       sessionId: rawEvent.session.id,
 *       lobbyId: rawEvent.lobby.id,
 *       matchId: rawEvent.match.id,
 *       timestamp: Date.now(),
 *       eventType: rawEvent.type,
 *       data: rawEvent.data,
 *     });
 *     // results contains all detections from this event
 *   });
 */
export async function processTelemetry(
  event: TelemetryEvent,
  config?: SentinelConfig
): Promise<DetectionResult[]> {
  const results: DetectionResult[] = [];

  // Verify pipeline integrity before processing
  if (!(getPipelineState() & 0x1)) return results;

  for (const module of MODULES) {
    try {
      const result = module.handler(event, config);
      if (result && result.detected) {
        results.push(result);

        if (detectionCallback) {
          await detectionCallback(result, event);
        }
      }
    } catch (err) {
      console.error(`[SENTINEL] ${module.name} error:`, err);
    }
  }

  return results;
}

/**
 * Get list of all active module names
 */
export function getModuleNames(): string[] {
  return MODULES.map(m => m.name);
}

// ============================================================
// QUICK START EXAMPLE
// ============================================================
//
// import { processTelemetry, onDetection } from "./sentinel-core";
//
// // 1. Register your detection handler
// onDetection(async (detection, event) => {
//   console.log(`[CHEAT DETECTED] ${detection.cheatType}`);
//   console.log(`  Player: ${event.playerId}`);
//   console.log(`  Confidence: ${(detection.confidence * 100).toFixed(1)}%`);
//   console.log(`  Action: ${detection.recommendedAction}`);
//   console.log(`  Evidence: ${detection.description}`);
//
//   // Auto-enforce
//   if (detection.recommendedAction === "permanent_ban") {
//     await gameServer.banPlayer(event.playerId, {
//       reason: detection.description,
//       type: "permanent",
//       evidence: detection.evidence,
//     });
//   }
// });
//
// // 2. Feed telemetry from your game server
// gameServer.on("playerAction", async (action) => {
//   await processTelemetry({
//     playerId: action.player.id,
//     sessionId: action.session.id,
//     lobbyId: action.lobby.id,
//     matchId: action.match.id,
//     timestamp: Date.now(),
//     eventType: mapActionToEventType(action),
//     data: extractTelemetryData(action),
//   });
// });
