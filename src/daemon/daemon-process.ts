/**
 * Daemon Process Manager - Background process lifecycle management
 *
 * Handles:
 * - Process forking and detachment
 * - PID file management
 * - Signal handling (SIGTERM, SIGINT)
 * - Daemon start/stop/status commands
 */

import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { CortexConfig } from '../types/config.js';

export interface DaemonCommand {
  /** Start the daemon */
  start(config: CortexConfig): Promise<DaemonStartResult>;

  /** Stop the daemon */
  stop(config: CortexConfig): Promise<DaemonStopResult>;

  /** Get daemon status */
  status(config: CortexConfig): Promise<DaemonStatusResult>;
}

export interface DaemonStartResult {
  success: boolean;
  pid?: number;
  message: string;
  error?: string;
}

export interface DaemonStopResult {
  success: boolean;
  message: string;
  error?: string;
}

export interface DaemonStatusResult {
  running: boolean;
  pid?: number;
  uptime?: number;
  sessionsWatched?: number;
  tokensSaved?: number;
  message: string;
}

/**
 * Create daemon command interface
 * @returns DaemonCommand instance
 */
export function createDaemonCommand(): DaemonCommand {
  /**
   * Check if daemon is running
   */
  function isDaemonRunning(pidFile: string): { running: boolean; pid?: number } {
    if (!existsSync(pidFile)) {
      return { running: false };
    }

    try {
      const pidStr = readFileSync(pidFile, 'utf-8').trim();
      const pid = Number.parseInt(pidStr, 10);

      if (Number.isNaN(pid)) {
        return { running: false };
      }

      // Check if process exists (cross-platform)
      try {
        process.kill(pid, 0); // Signal 0 checks existence without killing
        return { running: true, pid };
      } catch {
        // Process doesn't exist, clean up stale PID file
        unlinkSync(pidFile);
        return { running: false };
      }
    } catch {
      return { running: false };
    }
  }

  /**
   * Write PID file
   */
  function writePidFile(pidFile: string, pid: number): void {
    // Ensure directory exists
    const dir = dirname(pidFile);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    writeFileSync(pidFile, String(pid), 'utf-8');
  }

  /**
   * Remove PID file
   */
  function removePidFile(pidFile: string): void {
    if (existsSync(pidFile)) {
      unlinkSync(pidFile);
    }
  }

  async function start(config: CortexConfig): Promise<DaemonStartResult> {
    const { pidFile, logFile } = config.realtime;

    // Check if already running
    const status = isDaemonRunning(pidFile);
    if (status.running) {
      return {
        success: false,
        pid: status.pid,
        message: `Daemon already running (PID ${status.pid})`,
        error: 'Already running',
      };
    }

    try {
      // Resolve daemon entry point path
      // daemon-process.ts is bundled into dist/cli/index.js by tsup,
      // so we navigate from dist/cli/ to dist/daemon/index.js
      const __filename = fileURLToPath(import.meta.url);
      const __dirname = dirname(__filename);
      const daemonPath = join(__dirname, '..', 'daemon', 'index.js');
      const isWindows = process.platform === 'win32';

      const childEnv = {
        ...process.env,
        CORTEX_CONFIG: JSON.stringify(config),
        CORTEX_PID_FILE: pidFile,
        CORTEX_LOG_FILE: logFile,
      };

      // On Windows with Git Bash/MINGW, Node's detached:true doesn't
      // survive parent exit. Write a launcher script and run it with
      // PowerShell Start-Process which truly detaches.
      if (isWindows) {
        const configFile = join(dirname(pidFile), 'daemon-config.json');
        writeFileSync(configFile, JSON.stringify({ config, pidFile, logFile }), 'utf-8');

        // Create a tiny launcher script that sets env vars and runs the daemon
        const launcherFile = join(dirname(pidFile), 'daemon-launcher.mjs');
        const launcherCode = [
          `import { readFileSync } from 'node:fs';`,
          `const cfg = JSON.parse(readFileSync(${JSON.stringify(configFile)}, 'utf-8'));`,
          `process.env.CORTEX_CONFIG = JSON.stringify(cfg.config);`,
          `process.env.CORTEX_PID_FILE = cfg.pidFile;`,
          `process.env.CORTEX_LOG_FILE = cfg.logFile;`,
          `await import(${JSON.stringify(`file:///${daemonPath.replace(/\\/g, '/')}`)});`,
        ].join('\n');
        writeFileSync(launcherFile, launcherCode, 'utf-8');

        const ps = spawn(
          'powershell.exe',
          [
            '-NoProfile',
            '-WindowStyle',
            'Hidden',
            '-Command',
            `Start-Process -FilePath '${process.execPath}' -ArgumentList '${launcherFile}' -WindowStyle Hidden`,
          ],
          { stdio: 'ignore', windowsHide: true },
        );

        ps.unref();

        // Wait for daemon to write its own PID file
        await new Promise((resolve) => setTimeout(resolve, 2000));

        if (existsSync(pidFile)) {
          const pid = Number.parseInt(readFileSync(pidFile, 'utf-8').trim(), 10);
          if (!Number.isNaN(pid)) {
            return {
              success: true,
              pid,
              message: `Daemon started (PID ${pid})`,
            };
          }
        }

        return {
          success: false,
          message: 'Daemon failed to start (no PID file written)',
          error: 'Timeout waiting for daemon PID',
        };
      }

      // Unix: standard detached spawn
      const child = spawn(process.execPath, [daemonPath], {
        detached: true,
        stdio: 'ignore',
        env: childEnv,
      });

      // Detach from parent
      child.unref();

      // Write PID file
      if (child.pid) {
        writePidFile(pidFile, child.pid);

        return {
          success: true,
          pid: child.pid,
          message: `Daemon started (PID ${child.pid})`,
        };
      }

      return {
        success: false,
        message: 'Failed to start daemon (no PID)',
        error: 'No PID',
      };
    } catch (error) {
      return {
        success: false,
        message: 'Failed to start daemon',
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  async function stop(config: CortexConfig): Promise<DaemonStopResult> {
    const { pidFile } = config.realtime;

    const status = isDaemonRunning(pidFile);

    if (!status.running || !status.pid) {
      return {
        success: true,
        message: 'Daemon not running',
      };
    }

    try {
      // On Windows, SIGTERM is not supported by process.kill - it terminates immediately.
      // On Unix, SIGTERM allows graceful shutdown.
      const isWindows = process.platform === 'win32';

      if (isWindows) {
        // Windows: process.kill with any signal terminates the process
        process.kill(status.pid);
      } else {
        process.kill(status.pid, 'SIGTERM');
      }

      // Wait for process to exit (timeout after 5s)
      const maxWait = 5000;
      const interval = 100;
      let waited = 0;

      while (waited < maxWait) {
        try {
          process.kill(status.pid, 0);
          // Still running, wait
          await new Promise((resolve) => setTimeout(resolve, interval));
          waited += interval;
        } catch {
          // Process exited
          removePidFile(pidFile);
          return {
            success: true,
            message: `Daemon stopped (PID ${status.pid})`,
          };
        }
      }

      // Timeout, force kill
      try {
        if (!isWindows) {
          process.kill(status.pid, 'SIGKILL');
        }
        removePidFile(pidFile);
        return {
          success: true,
          message: `Daemon force killed (PID ${status.pid})`,
        };
      } catch {
        removePidFile(pidFile);
        return {
          success: true,
          message: `Daemon stopped (PID ${status.pid})`,
        };
      }
    } catch (error) {
      return {
        success: false,
        message: 'Failed to stop daemon',
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  async function status(config: CortexConfig): Promise<DaemonStatusResult> {
    const { pidFile } = config.realtime;

    const daemonStatus = isDaemonRunning(pidFile);

    if (!daemonStatus.running || !daemonStatus.pid) {
      return {
        running: false,
        message: 'Daemon not running',
      };
    }

    // Note: getMetrics() returns this process's metrics, not the daemon's.
    // For accurate daemon metrics, we'd need IPC. For now, report basic status.
    return {
      running: true,
      pid: daemonStatus.pid,
      message: `Daemon running (PID ${daemonStatus.pid})`,
    };
  }

  return {
    start,
    stop,
    status,
  };
}
