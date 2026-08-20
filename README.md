# KevAC Extension

This is the Metamod extension half of KevAC, the server-side anti-cheat I run on my CS:GO
HNS and MIX servers. The plugin half lives in **CSGO-KevAC** and you need both, the plugin
does nothing useful without this.

The extension exists for one reason: reading `CCLCMsg_ListenEvents`, the packet where a
client tells the server which network events it wants. You cannot touch that from
SourcePawn. Injected DLLs register extra listeners there, which makes it the cleanest catch
in the whole project. Everything else (detectors, actions, bans, admin commands) lives in
the plugin.

Started from the open source AntiDLL by JDW1337
([github.com/JDW1337/AntiDLL/releases](https://github.com/JDW1337/AntiDLL/releases)). Honestly
not much of it survives, the detector set, the listener resolver and this entire extension were
rewritten or added, but credit for the starting point goes to him. I also took his personal
donation info out of the README I inherited, since that is a real person's payment details and
it does not belong in someone else's fork.

## What is in here

| Path | What it does |
|---|---|
| `extension.cpp` | the ListenEvents detour and the natives the plugin calls |
| `extension.h`, `smsdk_config.h` | extension name and version |
| `AMBuilder`, `AMBuildScript`, `configure.py` | build config |
| `gamedata/kevac.games/` | signatures and offsets, loaded by both halves |
| `data/kevac/events_detection.txt` | the blacklisted network events |

## Can one check catch every cheat on join?

No, and anything claiming it does is catching a subset. Cheats split into three groups:

**Listener DLLs** register network event listeners. The extension sees the first
`CCLCMsg_ListenEvents` packet, so these get caught on join with basically no way to false
positive. This is the group people mean when they say an anti-cheat "detects DLLs
instantly".

**Netcode, cvar and movement cheats** touch the wire, so the plugin's behavioral checks pick
them up. Some of those are things a real client physically cannot send.

**Visual only cheats** (ESP, chams, anything that just reads memory and draws on screen) send
the server nothing unusual. You cannot catch these server side. Not with this, not with any
SourceMod plugin. That is what client anti-cheats are for, and I would rather say that than
pretend otherwise.

## The blacklist

`data/kevac/events_detection.txt` is the list of network events that no retail client should
ever subscribe to. An uncommented line means any client registering that event is treated as
a cheat.

The commented lines matter just as much. Those are events the real `client.dll` subscribes
to for its own HUD, so blacklisting them would ban legitimate players. They are commented on
purpose. Only add an event you have actually verified `client.dll` does not use.

## Actions

Every detector in the plugin has its own action cvar and they all use the same scale:

| Value | What happens |
|---|---|
| `-1` | off, the check does not even run |
| `0` | log it |
| `1` | kick |
| `2` | SourceMod ban |
| `3` | SourceBans++ ban, falls back to SourceMod if SB is missing |

`0` is not silent. It still writes to admin chat. If a check is just noise to you, set it to
`-1` instead.

## How much to trust each detector

Three tiers, and the tier decides how high you should set the action.

**Impossible for a real client.** Safe to ban on. Angle clamp, because the client hard clamps
pitch to +/-89 and always sends roll 0, so anything outside that was written into the usercmd
by something else. Anti duck delay, because `IN_BULLRUSH` in a usercmd is a straight up cheat
flag. Cheat cvar unlock, because `sv_cheats` is replicated, so a client reporting a value the
server did not set has patched its own cvar protection. A blocked query gets logged but never
punished, a block on its own proves nothing.

**Probably cheating, but not provable.** Kick at most. Ghost strafe and synthetic move both
get fooled by controller players, who send analog movement legitimately. Duck macro cadence
cannot tell a scroll wheel from a macro on timing alone. It can now separate a coasting wheel
from machine timing, because a real wheel slows down and its intervals drift while a macro
lands on the same number every time, but that only stops one kind of hardware being mistaken
for intent. Strafe sync and AHK strafe both break when a client is lagging, since the server
replays backup usercmds and consecutive commands legitimately carry identical values, so
those samples get thrown away.

**Heuristics.** Log only, real players trip these. Bhop streaks, scroll cadence, silent
strafe, knifebot reaction time, aimbot snap, triggerbot tick timing. Knifebot especially,
because the stab check compares present time positions against the attacker's rewound view,
which is the exact same geometry as a legit high ping ghost stab. Leave that one at `0`.

**Fake lag** deserves its own note. It measures what the server actually received instead of
what the client says, so it cannot be spoofed: real packet loss destroys usercmds and leaves
gaps in the numbering, while fake lag only delays them so the stream stays gapless but
arrives in fat clumps. Strong evidence, still not proof, because a buffering router looks the
same. Ships off by default.

## Whitelist

`configs/kevac/whitelist.ini` (in the plugin repo) takes a SteamID on its own to exempt
someone from everything, or a SteamID followed by detector names to exempt them from just
those. Whitelisted hits still log and still alert admins, it only skips the punishment.

```
STEAM_1:0:111                       everything
STEAM_1:0:222 DuckMacro             only DuckMacro, still bannable elsewhere
STEAM_1:0:333 DuckMacro,AHKStrafe   two of them
```

## Ban waves

With `kevac_banwave 1`, bans go into a queue instead of firing when the audit window closes,
and an admin flushes it with `sm_kevac_execban confirm`. Same detection, same evidence, the
only thing that moves is when it lands.

This is what makes the middle tier usable. A detector I would normally only trust to kick can
sit at ban level, because a human looks at it before anyone actually gets banned. It does not
turn a weak check into a strong one, it just makes a mistake recoverable.

Detectors listed in `kevac_banwave_exempt` skip the queue and ban immediately. Ghost input is
there by default, since it is a protocol impossibility and there is nothing for a human to
second guess.

## Building

You need the SourceMod SDK, Metamod and an HL2SDK. None of them are in this repo, point the
build at your own copies:

```bash
python configure.py \
  --sm-path /path/to/sourcemod \
  --mms-path /path/to/metamod-source \
  --hl2sdk-root /path/to/hl2sdks
```

Then:

```bash
ambuild
```

Build on **Ubuntu 20.04**. Anything newer links against a glibc that the CS:GO server
container does not have, and it will not load.

The GitHub Actions workflow builds against SourceMod 1.10 on ubuntu-latest, which is only a
compile check. It is not the binary you should ship, use a 20.04 build for that.

## Deploying

Drop the `.so` in `addons/sourcemod/extensions/`, and copy `gamedata/` and `data/` alongside
it. `sm exts list` should show KevAC once it loads.

The plugin is compiled separately, see the CSGO-KevAC repo. It carries its own `configs/`,
`translations/` and its copy of `gamedata/`.

## License

GPL-3.0, same as the AntiDLL project it started from. See `LICENSE`.
