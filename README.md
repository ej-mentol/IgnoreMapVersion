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
| `imv_log` | `1` | Diagnostic output verbosity level: <br>• `0` (**Off**): Disables all diagnostic output.<br>• `1` (**Standard**): Prints warnings, overrides, and redirects directly to console (`Con_Printf`). Routine matches and handshake telemetry route to developer console (`Con_DPrintf`, visible when `developer >= 1`). Keeps console clean for gameplay.<br>• `2` (**Verbose**): Prints all diagnostic events unconditionally to the standard console. |
| `imv_notify` | `1` | Displays an on-screen `CenterPrint` warning alert upon spawning into the map if a CRC mismatch was overridden. |
| `imv_crc_storage` | `1` | Enables automatic loading of CRC-indexed map variants (`maps/<name>_<crc>.bsp`). |

---

## Console Commands

- `imv_status [debug]`: Displays current plugin status, active log level, CRC storage state, active aliases, and the last map verification result. Append `debug` (or enable `developer 1`) to view low-level engine hook diagnostics and memory addresses.
- `imv_crc [map]`: Computes the engine CRC32 for a given map (or the currently loaded map if omitted), resolves its physical path on disk across game search paths, and outputs the suggested filename for CRC Map Storage.

---

## Logging Philosophy & Diagnostics

The plugin uses a 3-tier logging model via `imv_log`:

- **Silent by Default for Routine Events**: On servers cycling known maps, matches occur on every transition. In standard mode (`imv_log 1`), matches do not clutter the game console.
- **Developer Integration**: Setting engine variable `developer 1` seamlessly reveals routine handshake logs via `Con_DPrintf` without requiring verbose plugin configuration.
- **Safety Visibility**: Significant events (mismatch overrides, geometry rejections, map redirects) are printed to the standard console.
- **Independent Warning Channel (`imv_notify`)**: Override alerts and on-screen desync warnings are independently toggled via `imv_notify` so players never miss a critical desync alert.

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

If a server requests `maps/<mapname>.bsp` with CRC `0x1234ABCD`, the plugin automatically checks if a file named `maps/<mapname>_1234abcd.bsp` (or uppercase, or legacy `maps/<mapname>_crc1234abcd.bsp`) exists in the game search paths. If present:
1. The engine transparently redirects the map load to `maps/<mapname>_1234abcd.bsp`.
2. The real CRC of the candidate file is verified against the server's expected CRC to ensure the filename was not faked or corrupted.
3. If matching, the map loads seamlessly without triggering any mismatch alerts or geometry validation aborts.

You can determine a map's CRC and suggested storage filename at any time using the `imv_crc <mapname>` console command.

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
