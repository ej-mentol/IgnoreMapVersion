# IgnoreMapVersion (IMV)

IgnoreMapVersion is a client-side MetaHookSv plugin for Sven Co-op. It can use local BSP variants during map verification and, when enabled, allow a structurally plausible local BSP to pass the server CRC check. A matching BSP CRC does not prove that the local map is gameplay-compatible with the server map.

## Background

During `svc_serverinfo`, the server sends the expected CRC32 of the map BSP. The client engine computes a local CRC with `CRC_MapFile`; a mismatch normally prevents the client from joining. IMV hooks this check and can select a local map file or override the reported CRC after basic BSP validation.

## Behavior

1. IMV reads the server CRC from the current `net_message` only when the resolved `msg_readcount` and `net_message.cursize` bounds allow the complete CRC field to be read. If the required pointers cannot be resolved, CRC interception is skipped.
2. While `svc_serverinfo` is being parsed, the `CRC_MapFile` hook can select a configured alias or a CRC-indexed BSP candidate.
3. CRC storage candidates are accepted only when their computed CRC equals the server CRC. If candidate CRC calculation fails or differs, IMV clears the redirect and retries the originally requested map.
4. If the original local CRC differs and `imv_enabled` is enabled, IMV checks the BSP header, lump ranges, and the presence of non-empty planes, clipnodes, and entities lumps. It then reports the server CRC to the engine only when those checks pass.
5. The server CRC and handshake flag are cleared when `svc_serverinfo` finishes. The active file redirect is cleared at the start of the next `svc_serverinfo`, or when a candidate/original CRC calculation fails.

The BSP check is a basic sanity check. It does not validate every lump's contents, detect all malformed layouts, compare collision or gameplay data, or establish that two map versions are interchangeable. A CRC override can therefore still cause visual or gameplay desynchronization. Use it only with map versions you trust.

## Configuration

The plugin registers archived client variables with the `imv_` prefix.

| Variable | Default | Behavior |
| --- | ---: | --- |
| `imv_enabled` | `1` | Enables or disables the mismatch CRC override after BSP validation. It does not disable map aliases or CRC storage redirects. |
| `imv_log` | `1` | `0` disables IMV logging; `1` sends routine events to `Con_DPrintf` and significant events to `Con_Printf`; `2` sends all events to `Con_Printf`. |
| `imv_notify` | `1` | Prints a console warning when an override is applied and shows a one-time `CenterPrint` warning on the next HUD frame. |
| `imv_crc_storage` | `1` | Enables CRC-indexed BSP lookup. This is independent of `imv_enabled`. |

Map aliases are loaded at HUD initialization from `<gamedir>/ignoremapversion/aliases.txt`. The first path is the local file; the second path is the server-requested name. Paths are normalized to lowercase forward slashes.

```text
// Format: "local_file" "server_file"
"maps/local_map.bsp" "maps/server_map.bsp"
```

Aliases are considered during the `svc_serverinfo` CRC check. The filesystem hook redirects exact, case-insensitive matches for the armed server path and remains armed until the next `svc_serverinfo` or a CRC read failure. Since `IFileSystem::Open` is hooked globally, an open of that exact path during this interval is redirected too. The feature is experimental.

## CRC Storage

When the server CRC is non-zero and `imv_crc_storage` is enabled, IMV searches the game's filesystem paths for these names, in order:

```text
maps/<mapname>_<crc-lowercase>.bsp
maps/<mapname>_<crc-uppercase>.bsp
maps/<mapname>_crc<crc-lowercase>.bsp
maps/<mapname>_crc<crc-uppercase>.bsp
```

The candidate's actual CRC must match the server CRC before the redirect is kept. If it matches, the CRC check succeeds without invoking the generic mismatch override or BSP validation. If it fails, IMV retries the originally requested map; that map can still be subject to the generic mismatch override if `imv_enabled` is on and BSP validation passes.

## Commands

- `imv_status [debug]` shows plugin status, logging level, CRC storage state, aliases, and the last map verification result. Use `debug` or `developer 1` to include engine hook diagnostics and resolved addresses.
- `imv_crc [map]` lists the CRCs of the requested BSP and matching variants found through the engine filesystem, including mounted search paths and archives. It also prints the CRC-indexed storage name for the requested file. Variants are the exact map name and names with an underscore suffix, such as `map_v2.bsp` or `map_1234abcd.bsp`. Without an argument, the command uses the active redirect if present, otherwise the current level name.

## Logging

Runtime messages use the `IMV:` prefix. At `imv_log 1`, routine checks and startup details use `Con_DPrintf` and appear when `developer` is enabled. Warnings, map redirects, mismatches, and validation failures use `Con_Printf`. At `imv_log 2`, all IMV log messages use `Con_Printf`; `imv_log 0` disables messages sent through the logger. `imv_notify` adds an explicit console warning and a one-time `CenterPrint` on override; normal logger output can still report the override when notifications are disabled.

## Hooks and Resources

IMV resolves engine functions and network buffer addresses from known build information or verified byte patterns. Resolved addresses are checked against engine image sections, and `svc_serverinfo` payload access is guarded by the current message size and Structured Exception Handling.

The plugin creates no background threads. Alias configuration and temporary path strings remain in process memory; BSP file handles are closed after normal validation reads. `IPluginsV4::ExitGame` removes the CRC hook, parse callback, and optional `IFileSystem::Open` hook.

The optional `IFileSystem::Open` hook sees all filesystem opens, although it only changes the exact path currently selected by an alias or CRC storage lookup. Exercise aliases and CRC storage carefully because they affect which local BSP the engine reads.

## Build and Installation

### Requirements

- Visual Studio 2022 with the v143 toolset
- Windows SDK 10 or 11
- Win32 (x86), C++20

### Build

Open `IgnoreMapVersion.vcxproj` or the MetaHookSv solution in Visual Studio. Build `Release|Win32` for `IgnoreMapVersion.dll` and `Release_AVX2|Win32` for `IgnoreMapVersion_AVX2.dll`.

### Installation

Place the plugin DLLs in `svencoop/metahook/plugins/` and add this entry to `svencoop/metahook/configs/plugins.lst`:

```text
IgnoreMapVersion.dll
```

MetaHookSv selects the AVX2 DLL on supported CPUs. Put `aliases.txt`, if used, at `svencoop/ignoremapversion/aliases.txt`. Start the game and run `imv_status` to check initialization.
