import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const AUDIO_DIR = join(dirname(fileURLToPath(import.meta.url)), '../../audio');
const DISABLED = process.env['CORTEX_AUDIO'] === 'false';

export function playSound(filename: string): void {
  if (DISABLED) return;
  const filepath = resolve(AUDIO_DIR, filename);
  if (!existsSync(filepath)) return;
  try {
    if (process.platform === 'win32') {
      const escaped = filepath.replace(/'/g, "''");
      execFileSync(
        'powershell.exe',
        [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          `(New-Object Media.SoundPlayer '${escaped}').PlaySync()`,
        ],
        { windowsHide: true, timeout: 5000, stdio: 'ignore' },
      );
    } else if (process.platform === 'darwin') {
      execFileSync('afplay', [filepath], { timeout: 5000, stdio: 'ignore' });
    } else {
      // Linux: try common audio players in order
      try {
        execFileSync('aplay', ['-q', filepath], { timeout: 5000, stdio: 'ignore' });
      } catch {
        try {
          execFileSync('paplay', [filepath], { timeout: 5000, stdio: 'ignore' });
        } catch {
          execFileSync('play', ['-q', filepath], { timeout: 5000, stdio: 'ignore' });
        }
      }
    }
  } catch {
    /* silent — player not found or sound failed */
  }
}

export function playStartup(): void {
  playSound('startup.wav');
}
export function playCommand(): void {
  playSound('command.wav');
}
export function playComplete(): void {
  playSound('complete.wav');
}
export function playEnd(): void {
  playSound('end.wav');
}
