# Sparn Audio Assets

Place `.wav` files in this folder to enable audio feedback in the Sparn CLI.

## Files

| File | Event | Description |
|---|---|---|
| `startup.wav` | CLI launch | Plays once when any `sparn` command is invoked |
| `command.wav` | Pre-action | Plays before each command's action executes |
| `complete.wav` | Post-action | Plays after each command's action completes successfully |
| `end.wav` | User stop | Plays when the user interrupts Sparn (Ctrl+C / SIGINT) |

## Format Requirements

- **Format**: WAV (`.wav`)
- **Duration**: Keep sounds short (< 1 second recommended) to avoid overlap
- **Sample rate**: Any standard rate (44100 Hz, 48000 Hz, etc.)

## Platform Support

Audio playback is cross-platform:

| Platform | Player | Notes |
|---|---|---|
| **Windows** | PowerShell `Media.SoundPlayer` | Built-in, no extra install |
| **macOS** | `afplay` | Built-in on all macOS versions |
| **Linux** | `aplay` / `paplay` / `play` | Tries each in order; install `alsa-utils` or `pulseaudio-utils` if needed |

## Configuration

- **Disable**: Set `SPARN_AUDIO=false` in your environment to silence all sounds
- **Missing files**: If a `.wav` file is absent, that event is silently skipped — no crash

## How It Works

Sounds are played synchronously via `execFileSync` with a 5-second timeout. Each
platform uses its native audio player, with Linux falling back through `aplay`,
`paplay`, and `play` in order.
