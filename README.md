# ZengAV

A no-bloat, open-source antivirus for macOS, Windows and Linux with two jobs: scan the whole computer, or check files and folders you choose. It only looks when you ask it to.

**Window and tray:** open `ZengAV` (the app) for a black-and-white window with Scan, Check (files, folder or drag and drop), a Signatures panel and per-finding Delete / Accept / Skip. A tray icon offers Open, Scan, Check and Quit; it does not scan in the background. `zengav-gui <path>...` opens straight into a check. Downloads: the app is `ZengAV` (macOS app bundle, `ZengAV.exe`, `ZengAV`), and the command line is `zengav` (macOS: next to the app and inside `ZengAV.app/Contents/Resources/`; Windows and Linux: in the `cli` folder).

**Command line:** the same engine, as a separate small program.

```
zengav scan                  # scan the whole computer
zengav check <path>...       # scan files or folders you choose
```

Build only the command line (no window, tray or GUI libraries): `cargo build --release --no-default-features`.

Findings are reported, then you pick per file: **d**elete, **a**ccept (never flag that exact content again) or **s**kip.

## Options

| Flag | Effect |
|---|---|
| `--update` | Download the newest malware hashes and YARA rules first |
| `--heuristics` | Also report weak signals (packed executables in temp folders) |
| `--full` | Ignore the unchanged-file cache |
| `--report-only` | Never prompt; exit code 1 if anything was found |
| `--delete` | Delete every finding without asking |
| `-v`, `--verbose` | Print each file as it is scanned |

## How it decides

1. SHA-256 against a memory-mapped, sorted hash database (plus `hashes.txt` for your own hashes).
2. YARA-X rules on executables, scripts, documents and archives (up to 16 MB).
3. Optional heuristics, reported as "suspicious".

Files unchanged since the last clean scan are skipped until signatures change. Workers are capped at half the cores and run at the lowest priority.

## Signatures

`--update` does two things:

- **Hashes:** MalwareBazaar needs a free personal Auth-Key from <https://auth.abuse.ch/>. Set `ZENGAV_ABUSECH_KEY` or put the key in `abusech.key` in the config folder. Without it this step is skipped.
- **Rules:** the MIT-licensed [ReversingLabs YARA rules](https://github.com/reversinglabs/reversinglabs-yara-rules) by default. List other `https://` zip URLs (one per line) in `feeds.txt`, and put your own `.yar` files in `rules/`. Check each feed's license before use.

Config folder: `~/Library/Application Support/zengav` (macOS), `~/.config/zengav` (Linux), `%APPDATA%\zengav` (Windows). Override with `ZENGAV_HOME`.

## Limits

No real-time protection and no kernel driver: it finds what is on disk when you run it. Detection depends on signature quality, so use it as a second opinion beside your OS protection. No telemetry; the only network traffic is `--update`.

## Build

```
cargo build --release
cargo test
```

## License

MIT OR Apache-2.0. The window uses Familjen Grotesk (SIL Open Font License, see `assets/OFL.txt`).
