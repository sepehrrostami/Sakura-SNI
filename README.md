# sakura-sni-android

Root-only Android wrapper around the `sakura-sni` core (same tool as the desktop build — see `sakura-sni/README.md`). The Kotlin/Compose app's whole job is: get root, extract the bundled arm64 binary, write a `config.json` from the form fields, run it via `su`, and show you the log. All the actual SNI-hiding logic (TLS ClientHello building/parsing, fragmentation, raw-socket decoy injection) is the exact same Go code already reviewed and tested in the desktop tool — it's just cross-compiled for `android/arm64` and invoked under root instead of `sudo`.

**Important — build status:** I don't have an Android SDK/Gradle/emulator available in the sandbox I built this in, so this project **compiles against the source I reviewed but I have not actually run a Gradle build or installed it on a device.** Open it in Android Studio (Giraffe+/Ladybird, AGP 8.5, Kotlin 1.9.24 — all pinned in the Gradle files) and build normally; if anything doesn't line up with your installed SDK/AGP version, it'll most likely be a minor version-string fix in `build.gradle.kts`.

## What's bundled

- `app/src/main/assets/arm64-v8a/sakura-sni` — the Go core, stripped, cross-compiled with `GOOS=android GOARCH=arm64 CGO_ENABLED=0`. Only arm64-v8a is shipped: Go's `android/arm` (32-bit) target requires cgo, and essentially every rootable device in use today is arm64. If you need 32-bit, cross-compile with the NDK's cgo toolchain from the `sakura-sni/` source yourself.

## How it works at runtime

1. App checks `su` is available (`RootShell.isRootAvailable`).
2. On **Start**, it copies the bundled binary to the app's private files dir, `chmod +x`s it, writes `config.json` from the form (connect IP:port, fake SNI, method), and starts `SniSpoofService` — a foreground service that runs `su -c "<bin> -config <config.json>"` and keeps it alive so it survives you switching to your VLESS/Trojan client app.
3. Logs stream into the on-screen log view via an in-memory ring buffer (`LogBus`).
4. **Stop** sends `ACTION_STOP` to the service, which destroys the root process.

Point your xray/v2ray client's server address at `127.0.0.1:<listen port>` (default `40443`), same as the desktop tool — UUID, real SNI, transport, TLS settings all stay unchanged.

## Building

```bash
cd sakura-sni-android
./gradlew assembleRelease   # or open in Android Studio and hit Run
```

No Maven dependencies beyond AndroidX/Compose + the Android Gradle Plugin itself — no libsu, no custom root library — so there's nothing exotic for Gradle to resolve.

## Rebuilding the bundled binary

If you change the Go core, rebuild and re-copy it:

```bash
cd ../sakura-sni
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o ../sakura-sni-android/app/src/main/assets/arm64-v8a/sakura-sni .
```

## Known rough edges to check once you have it on a device

- `android:foregroundServiceType="specialUse"` and the matching `<property>` tag are Android 14 (API 34) concepts; on older rooted devices (API 26–33) the OS should just ignore the unrecognized type and still start a normal foreground service, but I haven't verified that on a real API-26/29/31 device — worth a quick smoke test on whatever your actual target devices are.
- `su -c` quoting: the command is built as a single string (`"<bin>" -config "<config>"`); if your root manager's `su` shells out differently (e.g. Magisk vs KernelSU edge cases), double check the process actually launches — `LogBus`/the log view will just stay empty if `su` silently fails, so watch for that case specifically and consider surfacing `su`'s own exit code in the UI if it comes up.
- No persistent storage of previously-used connect IP / fake SNI yet (every relaunch starts from the field defaults) — trivial to add with a `SharedPreferences` call in `MainActivity` if you want it.
