# IgnoreMapVersion (IMV)

A standalone MetaHookSv plugin for Sven Co-op designed to bypass client-side BSP map CRC32 mismatch errors while safeguarding against network desynchronization and client crashes.

---

## Background & Problem

When a client connects to a GoldSrc / Sven Co-op dedicated server, the server sends a `svc_serverinfo` network message containing the expected 32-bit CRC checksum of the level BSP. The client engine computes the local file checksum via `CRC_MapFile` and compares the results:

If the client CRC does not match the server CRC, the engine disconnects with: *"Your map differs from the server's."*

In community multiplayer environments, slight map differences are common—such as embedded custom textures, localized entity strings, minor scripting adjustments, or recompilations. Even when these modifications do not alter collision meshes or player interaction, the engine's strict CRC comparison blocks the client from joining.

`IgnoreMapVersion` solves this problem by intercepting the handshake and providing a controlled, structurally-validated CRC override.

---

## How It Works

1. **Server CRC Interception**: During the `svc_serverinfo` network parse routine, the plugin reads the server's expected Map CRC directly from the incoming network buffer (`net_message`).
2. **Synchronous CRC Hooking**: The engine function `CRC_MapFile` (located dynamically via verified pattern scanning and build-specific RVA resolution) is hooked. When invoked during the active `svc_serverinfo` lifecycle, the plugin intercepts the calculated local CRC.
3. **Structural Lump Validation**: Before applying any override, the plugin inspects the local BSP file (`ValidateBSPFile`). It verifies the file header and the presence of essential geometry lumps (planes, clipnodes, and entities). If critical structures are missing or the file is truncated, the override is aborted.
4. **State-Gated Override**: If the map passes validation, the plugin replaces the return CRC with the server's expected CRC value. Once `svc_serverinfo` finishes, the active handshake state and cached CRC are immediately reset to prevent stale overrides from affecting subsequent operations.

---

## Configuration & ConVars

All configuration variables are archived in `config.cfg` and prefixed with `imv_`.

| ConVar | Default | Description |
| :--- | :---: | :--- |
| `imv_enabled` | `1` | Master toggle (`1` = active, `0` = disabled). |
| `imv_safety_level` | `1` | Validation rigor mode: <br>• `0` (**Force**): Bypasses all BSP integrity checks. Overrides CRC regardless of geometric differences. Increases risk of physics desync or client crashes.<br>• `1` (**Safe**): Checks BSP geometry lumps prior to override. Aborts override if corrupt or fundamentally incompatible structures are detected.<br>• `2` (**Audit Only**): Telemetry mode. Observes and logs CRC mismatches without modifying the CRC value. Normal engine disconnect will occur. |
| `imv_log` | `1` | Log output destination: <br>• `0` (**Off**): Disables diagnostic logging.<br>• `1` (**Developer Only**): Prints via `Con_DPrintf`. Messages appear only when `developer` cvar is set to `1` or higher. Keeps console clean for regular gameplay.<br>• `2` (**Console**): Prints directly to standard console (`Con_Printf`). |
| `imv_log_mode` | `1` | Log filtering policy: <br>• `0` (**Always**): Logs every map verification check, including exact matches.<br>• `1` (**Only Diff**): Logs only when a CRC mismatch or validation event occurs. |
| `imv_notify` | `1` | Displays an on-screen `CenterPrint` warning alert upon spawning into the map if a CRC mismatch was overridden. |
| `imv_crc_storage` | `1` | Enables automatic loading of CRC-indexed map variants (`maps/<name>_<crc>.bsp`). |

---

## Console Commands

- `imv_status`: Outputs diagnostic telemetry to the console, including engine build, active hook RVAs, cvar settings, session counters, and details of the most recent map verification.
- `imv_reset`: Clears session mismatch/override counters and resets the last-checked map telemetry.
- `imv_crc [map]`: Computes the engine CRC32 for a given map (or the currently loaded map if omitted), resolves its physical path on disk across game search paths, and outputs the suggested filename for CRC Map Storage.

---

## Logging Philosophy & Diagnostics

Why are separate logging targets and modes provided?

- **Standard vs. Developer Console (`imv_log`)**: During ordinary gameplay, console output should remain clean for chat, game events, and admin messages. Setting `imv_log 1` ensures diagnostic messages only appear when debugging with `developer 1`. Setting `imv_log 2` makes all actions visible immediately for players troubleshooting connectivity.
- **Match Filtering (`imv_log_mode`)**: On servers cycling standard maps, CRC matches occur on every transition. Setting `imv_log_mode 1` filters out matching maps, highlighting only instances where the client and server versions diverge.

---

## Safety & Resource Lifecycle

- **Memory Safety**: Engine data pointers (`msg_readcount`, `net_message`) are validated against engine PE section boundaries (`.data`, `.rdata`, and image bounds) before resolution. Net buffer payload extraction is protected with Structured Exception Handling (`__try ... __except`).
- **Resource Management**: The plugin does not allocate persistent background threads or heap allocations across map transitions. BSP files opened for validation are closed immediately.
- **Teardown**: Inline hooks, parse callbacks, and the optional `IFileSystem::Open` alias hook are cleanly detached in `IPluginsV4::ExitGame` before MetaHook teardown. ConVars and commands are registered into engine linked lists and released upon process termination by the operating system.

---

## Map Aliasing (Experimental)

In addition to CRC override, the plugin can transparently redirect a requested map file to a different `.bsp` on disk — useful when a server intentionally renames or forks a map but you want to keep using your local copy under its original name.

> **Status: Experimental.** This feature hooks `IFileSystem::Open` directly (VFT index verified against this project's `IFileSystem.h`), which is called for every asset load in the game, not just maps. Test thoroughly before relying on it in a live session.

### Configuration

Aliases are defined in `<gamedir>/ignoremapversion/aliases.txt`, one pair per line using KeyValues-style quoted tokens:

```
// Format: "local_file" "server_file"
// Both fields are full paths including directory and extension.

"maps/insecure01a.bsp"    "maps/insecure_01a.bsp"
"maps/my_map_v2.bsp"      "maps/my_map_v2_fix.bsp"
```

- First token is the file you have locally; second is what the server requests.
- Paths are case-insensitive. Use forward slashes.
- The alias is armed only while a CRC mismatch handshake is active for that specific `svc_serverinfo`/`CRC_MapFile` call, and is cleared automatically once the next `svc_serverinfo` arrives.

### CRC-Based Map Storage (Automatic Versioning)

In addition to static aliases in `aliases.txt`, the plugin supports automatic loading of map variants indexed by CRC.

If a server requests `maps/<mapname>.bsp` with CRC `0x1234ABCD`, the plugin automatically checks if a file named `maps/<mapname>_1234abcd.bsp` (or uppercase) exists in the game search paths. If present:
1. The engine transparently redirects the map load to `maps/<mapname>_1234abcd.bsp`.
2. The real CRC of the candidate file is verified against the server's expected CRC to ensure the filename was not faked or corrupted.
3. If matching, the map loads seamlessly without triggering any mismatch alerts or geometry validation aborts.

You can determine a map's CRC and suggested storage filename at any time using the `imv_crc <mapname>` console command.

---

## Known Issues

A handful of logging edge cases (mainly around `imv_log_mode` filtering) are still being worked out. Behavior elsewhere in the plugin is stable.

---

## Building & Installation

### Requirements
- Visual Studio 2022 (v143 toolset)
- Windows SDK 10 / 11
- Target Architecture: `x86` (`Win32`), C++20 standard

### Build
1. Open `IgnoreMapVersion.vcxproj` (or the MetaHookSv solution) in Visual Studio.
2. Select configuration **Release** and platform **Win32**.
3. Build the project. The output file `IgnoreMapVersion.dll` will be generated in the output directory.

### Installation
1. Copy `IgnoreMapVersion.dll` to your game directory (e.g., `svencoop/metahook/plugins/`).
2. Add the plugin entry to `plugins.lst`:
   ```text
   IgnoreMapVersion.dll
   ```
3. Launch the game and run `imv_status` in the console to verify initialization.
