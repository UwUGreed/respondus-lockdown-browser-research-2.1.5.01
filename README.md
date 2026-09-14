# Respondus LockDown Browser 2.1.5.01 — Reverse Engineering Research

> Static and dynamic reverse-engineering research into Respondus LockDown Browser 2.1.5.01, including VM/environment classification, hardware inspection, process/runtime artifact monitoring, internal telemetry, policy state, obfuscated control flow, and kernel-driver behavior.

**Repository:** `respondus-lockdown-browser-research-2.1.5.01`

**Description:**  
Reverse-engineering notes and technical findings for Respondus LockDown Browser 2.1.5.01, including VM detection, device/BIOS inspection, runtime artifact monitoring, internal detection state, obfuscation, and kernel-driver behavior.

---

> [!IMPORTANT]
> ## Research Scope
>
> This repository documents observed behavior and architecture from reverse-engineering Respondus LockDown Browser.
>
> It focuses on:
>
> - detection mechanisms
> - program architecture
> - runtime state
> - telemetry
> - Windows internals
> - driver capabilities
> - control-flow protection
>
> It does **not** contain a working examination-security bypass.
>
> Findings labeled **confirmed** are directly supported by static analysis, runtime data, API usage, tracing, or reconstructed control flow.
>
> Findings labeled **unconfirmed** remain hypotheses until additional evidence is recovered.

---

# Target

| Property | Value |
| --- | --- |
| Product | Respondus LockDown Browser |
| Version | `2.1.5.01` |
| Installer | `LockDownBrowser-2-1-5-01-158741422.msi` |
| Main executable | `LockDownBrowser.exe` |
| Main DLL | `LockDownBrowser.dll` |
| Kernel driver | `LockDownService215.sys` |

---

# Artifact Metadata

## LockDownBrowser.exe

```text
Observed size:
20,699,584 bytes

Ghidra image base:
0x140000000
```

---

## LockDownBrowser.dll

```text
FileVersion:     23.10.31.1
ProductVersion:  2.1.1.5
FileDescription: LockDown Browser
Company:         Respondus, Inc.
```

Image base:

```text
0x180000000
```

Observed sections:

```text
.text
.rdata
.data
.pdata
.cldb
.fptable
.rsrc
.reloc
```

The `.cldb` section is approximately:

```text
0x200 bytes
Read/Write
Non-executable
```

Observed exports:

```text
CLDBDoSomeOtherStuff
CLDBDoSomeOtherStuffs
CLDBDoSomeStuff
CLDBDoYetMoreStuff
entry
```

Recovered PDB path:

```text
C:\VS12\LockDownChrome-HookDLL\x64\Release\LockDownBrowser.pdb
```

---

## LockDownService215.sys

```text
Version:
2.15.0.1
```

SHA256:

```text
323FAE10C53E74C2418C8D1BD45E54DE63241135BEB81196FDA0F6A16C3D5996
```

Installed path:

```text
C:\Windows\System32\drivers\LockDownService215.sys
```

Observed configuration:

```text
Service:     LockDownService215
Type:        FILE_SYSTEM_DRIVER
Start type:  SYSTEM_START
Group:       FSFilter Bottom
Dependency:  FltMgr
Altitude:    47777
Instances:   4
Frame:       0
```

Ghidra image base:

```text
0x140000000
```

Recovered debugging information:

```text
PDB:  LockDownService215.pdb
GUID: 9c670681-69fd-4e8f-ac01-e52be2132b12
Age:  1
```

---

# Executive Summary

Respondus LockDown Browser 2.1.5.01 contains a broad environment-classification system rather than one isolated virtual-machine check.

The analyzed build performs checks across several independent surfaces:

```text
Hardware identity
Windows device inventory
BIOS / registry values
CPU identity
COM device names
Process/module paths
Runtime artifact collections
Windows desktops and sessions
Recording / remote-control applications
Accessibility software
Wine / compatibility-layer indicators
Application virtualization indicators
Kernel process/thread/image events
Filesystem activity
Integrity / tamper state
```

Several internal environment categories are eventually represented through:

```text
rldbvm = 0
rldbvm = 1
rldbvm = 2
rldbvm = 3
```

A separate serialized detection state is exposed through:

```text
rldbdetect
```

The exact semantics of every numeric category are not yet known, but the writer architecture for all three non-zero `rldbvm` categories has now been substantially reconstructed.

A second major finding is that the executable uses heavy control-flow protection involving:

```text
overlapping instructions
opaque predicates
embedded RET gadgets
synthetic return stacks
arithmetic gadgets
computed dispatch
```

This significantly reduces the usefulness of naïve Ghidra function boundaries and decompilation in protected regions.

---

# High-Level Architecture

```text
                         LockDownBrowser.exe
                                 |
       +-------------------------+-------------------------+
       |                         |                         |
    Hardware                  Runtime                   Sessions
    Devices                   Processes                 Desktop
    BIOS                      Modules                   RDP
    Registry                  Artifacts                 WTS
       |                         |                         |
       +-------------------------+-------------------------+
                                 |
                      Detection / Classification
                                 |
             +-------------------+-------------------+
             |                   |                   |
         rldbvm = 1          rldbvm = 2          rldbvm = 3
             |                   |                   |
             +-------------------+-------------------+
                                 |
                           rldbdetect
                                 |
                        Telemetry / Policy
                                 |
                    LockDownService215.sys
```

Current evidence indicates that detection and classification are distributed across several subsystems rather than accumulated through one single Boolean.

---

# Internal VM State

## Serializer

Function:

```text
FUN_1401ea670
```

Observed state fields:

```text
DAT_140ccc948 + 0x4664A -> rldbvm = "1"
DAT_140ccc948 + 0x4664B -> rldbvm = "2"
DAT_140ccc948 + 0x46538 -> rldbvm = "3"
```

If none are set:

```text
rldbvm = "0"
```

Another field:

```text
DAT_140ccc948 + 0x46651
```

causes both:

```text
rldbvm     = "0"
rldbdetect = "0"
```

Its exact purpose remains unresolved.

---

# VM Classification Summary

| Internal state | Current interpretation | Confidence |
| --- | --- | --- |
| `rldbvm=1` | Hardware/platform classification | High |
| `rldbvm=2` | Recognizable runtime/software environment | High |
| `rldbvm=3` | Expected-device consistency failure | High |
| `rldbvm=0` | No active VM category serialized | Confirmed |

These descriptions represent the current structural interpretation.

They should **not** yet be translated directly into:

```text
1 = VMware
2 = VirtualBox
3 = ...
```

because the categories aggregate multiple independent conditions.

---

# Detection Result Encoding

Function:

```text
FUN_140262110
```

This function serializes existing internal flags into `rldbdetect`.

Observed mappings:

| Field | Serialized value |
| --- | ---: |
| `+0x2D4` | `1` |
| `+0x479` | `2` |
| `+0x300` | `3` |
| `+0x2D5` | `4` |
| `+0x2D6` | `5` |
| `+0x2D7` | `6` |
| `+0x3FC` | `9` |
| global `+0x448` | `10` |
| `+0x388` | `13` |
| `+0x2D9` | `16` |
| `+0x278` | `17` |
| `+0x279` | `18` |

The function appears to be a serializer rather than the original source of these detections.

---

# Comparison Helpers

## `FUN_140296900`

Case-insensitive prefix comparison.

Equivalent concept:

```c
_strnicmp(value, prefix, strlen(prefix))
```

Important return convention:

```text
0     -> prefix matched
non-0 -> mismatch
```

This matters when interpreting several obfuscated callers.

---

## `FUN_140297050`

Case-insensitive substring search.

Observed callers establish:

```text
non-zero -> substring found
zero     -> substring not found
```

Conceptually:

```c
ContainsIgnoreCase(value, substring)
```

---

# Runtime String Table

Function:

```text
FUN_1401fc0e0
```

Recovered logic:

```c
undefined8 *FUN_1401fc0e0(longlong *param_1, int param_2, int param_3)
{
    longlong base;
    undefined8 *entry;

    if (param_2 == 0x11)
        base = param_1[3];

    else if (param_2 == 0x2b)
        base = *param_1;

    else
    {
        if (param_2 != 0x3b)
            return &DAT_140b09d38;

        base = param_1[6];
    }

    entry =
        (undefined8 *)(base +
        (longlong)(param_3 / 0x15) * 0x20);

    if (0xf < (ulonglong)entry[3])
        entry = (undefined8 *)*entry;

    return entry;
}
```

For table:

```text
0x3B
```

the base is:

```text
context + 0x30
```

Entries are:

```text
0x20 bytes each
MSVC std::string-like layout
```

Index relationship:

```text
index = ID / 0x15
ID    = index * 0x15
```

Important recovered values include:

```text
0x007E  ***remote***
0x0093  ***shutdown***
0x00A8  ***touchpadswipe***
0x00BD  ***hacked***
0x00D2  ***resedit*** {%s}
0x00E7  ***vmdetected***

0x01F8  CAMEYO_VIRTUALAPP,CAMEYO_RO_VIRTUALAPP,CAMEYO_RO_PROPERTY_VIRTUALAPP
0x020D  VBoxAsw
0x0222  PG splitter
0x0237  TriDef
0x0261  ALLOW_MONITOR

0x03C6  Hacking program detected - (Discord2025) =
0x03F0  SYSTEM\CurrentControlSet\Control\Terminal Server\
0x0405  GlassSessionId
0x041A  mstsc.exe
```

Additional table entries expose:

```text
VM Detected
vm_device
ProcessorNameString
HARDWARE\DESCRIPTION\System\CentralProcessor\0
Parallels
FaceTime HD
winex11.drv
winepulse.drv
```

---

# Dynamic Instrumentation Findings

Initial Frida work successfully exposed runtime string-table values and callsites.

However, later testing showed a significant limitation.

## Direct Spawn

Spawning Respondus through Frida caused startup/authentication failure:

```text
Demo Auth 5 cannot be run because it is corrupted
```

Normal launch without Frida succeeded.

---

## Delayed Attachment

Attaching Frida after normal startup also caused instrumented Respondus processes to terminate shortly after hooks were loaded.

The behavior persisted with different attachment delays.

Therefore:

> Respondus 2.1.5.01 exhibits instrumentation-sensitive behavior. Direct Frida spawning interferes with startup/authentication, while attachment to already-running processes causes instrumented processes to terminate shortly after hooks are installed.

The research intentionally did not attempt to defeat this behavior.

Subsequent analysis therefore relies more heavily on:

```text
static reconstruction
runtime data already recovered
external observation
non-invasive tracing
```

---

# Device Enumeration

Primary function:

```text
FUN_1402b30d0
```

Observed APIs include:

```text
SetupDiGetClassDevsW
SetupDiEnumDeviceInfo
SetupDiGetDeviceRegistryPropertyA
```

Properties inspected:

```text
0x00 -> SPDRP_DEVICEDESC
0x0C -> SPDRP_FRIENDLYNAME
```

Both are compared against a runtime-loaded device prefix array.

The same function additionally performs:

```text
system identity checks
registry checks
device inventory
FNV hashing
de-duplication
diagnostic string construction
persistent detection-state updates
```

---

# Confirmed VM / Device Prefix Array

Runtime pointer:

```text
DAT_140cccba8 + 0x233D0
```

Count:

```text
DAT_140cccba8 + 0x233D8
```

Observed:

```text
26 entries
```

Recovered array:

```text
[000] Parallels Video Driver
[001] Parallels Network Adapter
[002] Parallels Mouse Synchronization Tool
[003] PRL Virtual CD-ROM

[004] VMWare SVGA II
[005] VMWare SVGA
[006] VMWare Pointing Device
[007] VMWare Accelerated AMD PCNet Adapter
[008] VMWare SCSI Controller
[009] VMWare Virtual IDE Hard Drive

[010] VM Additions S3 Trio32/64
[011] VM Additions PS/2 Port Mouse
[012] VM Additions PC/AT Enhanced PS/2 Keyboard

[013] VBOX
[014] QEMU
[015] XEN
[016] Msft Virtual
[017] Red Hat VirtIO

[018] Amazon Elastic Network Adapter
[019] Amazon Outbound Audio
[020] AWS Virtual Camera
[021] AWS Virtual DOD Driver
[022] AWS Virtual Microphone Device

[023] Wine HID
[024] Wine Adapter
[025] Wine USB
```

These are tested against both:

```text
SPDRP_DEVICEDESC
SPDRP_FRIENDLYNAME
```

using the prefix comparator.

---

# BIOS / Registry Detection Structure

Runtime structure:

```text
DAT_140cccba8 + 0x233E0
```

Recovered values:

```text
+0x00  HARDWARE\DESCRIPTION\System
+0x10  PRLS
+0x18  VideoBiosVersion
+0x20  Parallels
+0x28  HARDWARE\DESCRIPTION\System\BIOS
+0x30  SystemManufacturer
+0x38  VMWare
+0x40  VBOX
+0x48  Sun VirtualBox
+0x50  HARDWARE\DESCRIPTION\System\CentralProcessor\0
+0x58  ProcessorNameString
+0x60  QEMU
+0x80  VRTUAL
```

`VRTUAL` is spelled exactly that way in the recovered data.

---

# Confirmed Registry / Identity Checks

## System Identity

Observed comparisons:

```text
PRLS    -> prefix
VBOX    -> prefix
VRTUAL  -> prefix
VMWare  -> substring
```

---

## Video BIOS

Registry path:

```text
HKLM\HARDWARE\DESCRIPTION\System
```

Value:

```text
VideoBiosVersion
```

Compared against:

```text
Parallels
Sun VirtualBox
```

---

## VMware Manufacturer

Registry path:

```text
HKLM\HARDWARE\DESCRIPTION\System\BIOS
```

Value:

```text
SystemManufacturer
```

Compared against:

```text
VMWare
```

---

## QEMU CPU Identity

Registry path:

```text
HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0
```

Value:

```text
ProcessorNameString
```

Compared against:

```text
QEMU
```

---

# `VBoxAsw`

`VBoxAsw` was initially suspected to be another positive VirtualBox indicator.

Tracing `FUN_1402b30d0` showed different behavior.

Conceptually:

```c
if (!StartsWithIgnoreCase(deviceString, "VBoxAsw"))
{
    CheckVMDevicePrefixList(deviceString);
}
```

Within this function, `VBoxAsw` therefore acts as a:

```text
special-case exclusion
```

from the generic VM prefix loop.

It is actively retrieved for both:

```text
device description processing
friendly-name processing
```

This does not establish how `VBoxAsw` may be used elsewhere.

---

# Device Inventory and FNV-1a

The same detection routine maintains a de-duplicated device inventory.

Hash:

```text
FNV-1a 64-bit
```

Constants:

```text
offset basis:
0xCBF29CE484222325

prime:
0x100000001B3
```

Equivalent:

```c
hash = 0xCBF29CE484222325;

for each byte:
    hash = (hash ^ byte) * 0x100000001B3;
```

New device strings are stored in an inventory/diagnostic structure around:

```text
DAT_140ccc948 + 0x46878
```

This appears primarily related to:

```text
inventory
de-duplication
diagnostic reporting
```

rather than being the direct VM decision itself.

---

# Consolidated Environment State

`FUN_1402b30d0` ultimately ORs its result into:

```text
DAT_140ccc948 + 0x46518
DAT_140ccc948 + 0x4651C
```

and increments:

```text
DAT_140ccc948 + 0x46908
```

These fields appear to accumulate the outcome of:

```text
system identity checks
BIOS checks
registry checks
device-description checks
device-friendly-name checks
```

Scalar searches have not yet revealed an obvious direct reader for `+0x46518` or `+0x4651C`.

Indirect or protected consumers remain possible.

---

# COM FriendlyName Detection

Function:

```text
FUN_14023dda0
```

Observed sequence:

```text
CoInitialize
COM enumeration
FriendlyName extraction
string conversion
environment comparison
```

Runtime string:

```text
ID 0xAAA
FaceTime HD
```

Observed behavior:

```c
if (ContainsIgnoreCase(FriendlyName, "FaceTime HD"))
    state->0x4653A = 1;
```

This field later participates in `rldbvm=1`.

A literal:

```text
virtual
```

is also passed through the substring helper.

Its return value is not visibly consumed in the analyzed path, so it is not currently considered a confirmed detection trigger.

---

# `rldbvm=1`

Primary writer:

```text
FUN_1402141b0
```

Field:

```text
DAT_140ccc948 + 0x4664A
```

The function processes broader machine/platform information.

Observed behavior includes:

```text
Apple M1 Pro special-case handling
machine/platform normalization
table-based classification
hardware/environment state
COM-derived +0x4653A state
```

A Boolean classification result is ORed with:

```text
+0x4653A
```

and can result in:

```text
+0x4664A = 1
```

which serializes as:

```text
rldbvm=1
```

Current interpretation:

> `rldbvm=1` represents broader hardware/platform classification rather than one simple VM vendor match.

---

# `rldbvm=2`

Field:

```text
DAT_140ccc948 + 0x4664B
```

Three independent writers have now been identified.

---

## Writer 1 — Startup / Username Environment Check

Function:

```text
FUN_14014e000
```

Observed sequence:

```c
GetUserNameA(...);

FUN_1402062d0(global, 8, ...);

result = FUN_140296900(username, generated_string);
```

Because `FUN_140296900` returns:

```text
0 on prefix match
non-zero on mismatch
```

the observed branch:

```c
if (result != 0)
```

corresponds to an apparent **prefix mismatch**, not a match.

That branch writes:

```text
+0x4664B = 1
+0x46650 = 1
```

The generated selector-8 string remains unresolved due heavy control-flow protection.

This path therefore remains structurally confirmed but semantically unusual.

---

## Writer 2 — Process / Module Paths

Function:

```text
FUN_140209e50
```

This path generates:

```text
selector 8 pattern
selector 10 pattern
```

and searches strings derived from:

```text
K32GetModuleFileNameExA
```

Observed state writes:

```text
selector 8 found
    -> +0x4664E = 1
    -> +0x4664B = 1

selector 10 found
    -> +0x4664C = 1
    -> +0x4664B = 1
```

This demonstrates that process/module path signatures can directly contribute to:

```text
rldbvm=2
```

---

## Writer 3 — Runtime Artifact Vector

Function:

```text
FUN_14023b5b0
```

Patterns:

```text
selector 8
selector 9
```

The function scans a vector stored at:

```text
state + 0x464B0  begin
state + 0x464B8  end
state + 0x464C0  capacity
```

Record size:

```text
0x28 bytes
```

A searchable `std::string`-like object exists at:

```text
record + 0x08
```

Observed state writes:

```text
selector 8 found
    -> +0x4664F = 1
    -> +0x4664B = 1

selector 9 found
    -> +0x4664D = 1
    -> +0x4664B = 1
```

---

# `rldbvm=2` Subflags

```text
Process/module selector 8
    -> +0x4664E

Process/module selector 10
    -> +0x4664C

Runtime vector selector 8
    -> +0x4664F

Runtime vector selector 9
    -> +0x4664D
```

This symmetry strongly suggests a correlated environment signature distributed across multiple artifact types.

Current interpretation:

> `rldbvm=2` represents recognition of a software/runtime environment through correlated artifacts rather than generic virtual hardware.

The exact environment represented by selectors `8`, `9`, and `10` remains unresolved.

---

# Runtime Artifact Vector

The vector used by the third `rldbvm=2` writer is initialized empty in:

```text
FUN_14024e040
```

Constructor initialization:

```text
+0x464B0 = 0
+0x464B8 = 0
+0x464C0 = 0
```

A later routine:

```text
FUN_14023f4a0
```

passes this vector to:

```text
FUN_140226710
```

indicating that the latter populates or updates the collection.

---

## Periodic Refresh

`FUN_14023f4a0` is called from a periodic scheduler in:

```text
FUN_1402c6950
```

A counter at:

```text
+0x41FC
```

is decremented.

When it reaches zero:

```text
FUN_14023f4a0()
```

is invoked and the counter is reset to:

```text
0x546
1350 decimal
```

The scheduler tick duration is not yet known, so this should not be converted into seconds.

This establishes that the artifact vector is periodically refreshed.

---

# Shared VM2 / Hack Detection Artifact Collection

The same `0x28`-byte record collection is used for more than VM classification.

Inside:

```text
FUN_14023b5b0
```

the vector is also scanned against another pattern and can set:

```text
state + 0x2D5 = 1
```

which serializes as:

```text
rldbdetect=4
```

Observed log string:

```text
PTC 4,1 - Hack type 4 detection - ...
```

Therefore:

> The vector contains named runtime artifacts that participate in both environment classification and general hack/tamper detection.

The exact artifact type remains unresolved.

Possible interpretations include:

```text
window-derived objects
runtime object names
application artifacts
enumerated UI/process-related records
```

but none has yet been confirmed.

---

# `rldbdetect=4`

Internal field:

```text
+0x2D5
```

Serialized value:

```text
4
```

Two detection paths have been reconstructed.

---

## PTC 4,1

The runtime artifact vector is searched against a pattern.

On match:

```text
+0x2D5 = 1
```

and a diagnostic string identifies:

```text
Hack type 4 detection
```

---

## PTC 4,2

A second path uses a different signature collection.

Structure:

```text
state + 0x3F0 -> array of C-string pointers
state + 0x3F8 -> count
```

For each pattern:

```text
strlen
manual search
memcmp
```

are used against a larger buffer.

Match offsets are recorded.

The function then evaluates:

```text
missing pattern count
+
ordering failures
```

The final test is:

```c
if (missing_patterns + ordering_failures < 4)
    state->0x2D5 = 1;
```

and logs:

```text
PTC 4,2 - Hack type 4 detection ...
```

This suggests a signature sequence detector where sufficiently complete and correctly ordered evidence triggers code `4`.

---

## Latching Behavior

The same function checks:

```asm
CMP byte ptr [state+0x2D5],0
JNZ ...
```

before re-running the detector.

Therefore:

```text
+0x2D5
```

is latched once set.

This is duplicate-suppression / persistent state rather than direct proof of enforcement.

---

# `rldbvm=3`

Field:

```text
DAT_140ccc948 + 0x46538
```

Writer:

```text
FUN_14020fb20
```

A device-expectation structure is stored around:

```text
+0x46630
+0x46638
```

Record size:

```text
0x28
```

Recovered rules:

```text
Rule 3
Expected: 1
Mode: ANY
Patterns:
    graphics
    nvidia
    amd
    matrox
     arc

Rule 4
Expected: 1
Mode: ANY
Pattern:
    PCI Express Root
```

During device enumeration:

```text
SPDRP_DEVICEDESC
```

is searched using the case-insensitive substring helper.

Observed logic compares the actual result against the expected result.

A mismatch count is accumulated.

When:

```text
mismatchCount > 1
```

the function sets:

```text
+0x46538 = 1
```

which serializes as:

```text
rldbvm=3
```

Because two rules are currently present, this effectively requires both rules to disagree with expectation.

Current interpretation:

> `rldbvm=3` is a device-consistency classification based on expected presence of generic display and PCI-root style hardware indicators.

---

# VM Classification Serialization

Another function:

```text
FUN_1402528a0
```

serializes VM categories into a semicolon-delimited representation.

Observed behavior includes:

```text
+0x4664B -> append "2;"
+0x46538 -> append "3;"
```

with surrounding code strongly suggesting:

```text
+0x4664A -> "1;"
```

This is consistent with telemetry/status serialization.

---

# Important Reader Finding

Direct scalar reads of:

```text
+0x4664B
```

were found in:

```text
FUN_1401ea670
FUN_1402528a0
```

The observed behavior in those functions is:

```text
telemetry serialization
status serialization
```

No direct consumer has yet been identified where:

```text
+0x4664B == 1
```

immediately causes a termination or other enforcement action.

This is an important distinction:

> A confirmed VM classification flag is not automatically equivalent to a confirmed enforcement decision.

---

# Recording / Remote-Control Process Table

Runtime entry:

```text
ID 0x09D8
```

contains a large list of applications associated with:

```text
remote control
remote desktop
screen recording
capture
streaming
support software
```

Examples include:

```text
AnyDesk.exe
OBS.exe
obs64.exe
ShareX.exe
TeamViewer.exe
vncviewer.exe
Wirecast.exe
XSplit.Gamecaster.exe
mstsc.exe
quickassist.exe
```

The table is confirmed to exist.

It was **not** observed being retrieved through `FUN_1401fc0e0` during the startup trace.

Possible explanations include:

```text
different retrieval mechanism
policy-conditional loading
initialization-time copying
later-phase consumption
indirect table access
```

Its exact consumer remains unresolved.

---

# Accessibility Software Table

Runtime entry:

```text
ID 0x09ED
```

contains software including:

```text
Dragon
NVDA
JAWS
ZoomText
```

Examples:

```text
dragonbar.exe
natspeak.exe
nvda.exe
jfw.exe
AiSquared.ZoomText.UI.exe
```

This table is confirmed to exist.

It should **not** currently be described as a blacklist.

Possible uses include:

```text
compatibility handling
exceptions
special-case behavior
monitoring
policy
blocking
```

The consumer remains unresolved.

---

# Browser Process Indicators

Recovered process names include:

```text
chrome.exe
firefox.exe
msedge.exe
brave.exe
safari.exe
opera.exe
vivaldi.exe
wavebrowser.exe
ghost.exe
```

Nearby configuration:

```text
BlockBrowsers
```

supports browser-specific policy logic.

---

# Remote Desktop / Session Detection

Recovered values:

```text
SYSTEM\CurrentControlSet\Control\Terminal Server\
GlassSessionId
mstsc.exe
WinSta0
```

Imports include:

```text
WTSRegisterSessionNotification
WTSUnRegisterSessionNotification
WTSGetActiveConsoleSessionId
ProcessIdToSessionId
```

This confirms explicit Windows-session and RDP awareness.

---

# Sysinternals / Desktop Handling

Runtime lookups:

```text
Sysinternals
Default
Winlogon
```

Known callsites:

```text
0x1402227C0
0x1402227DA
0x1402227F4
```

Associated diagnostic string:

```text
Hacked Sysinternals Desktops in use
```

The grouping of:

```text
Sysinternals
Default
Winlogon
```

suggests desktop/window-station inspection rather than simply checking for Sysinternals executables.

The full mechanism remains under investigation.

---

# Wine Detection

Confirmed device indicators:

```text
Wine HID
Wine Adapter
Wine USB
```

Additional runtime strings:

```text
winex11.drv
winepulse.drv
```

`winex11.drv` was actively retrieved at:

```text
0x1402B52C9
0x1402B52E3
```

The resulting state transition has not yet been completely reconstructed.

---

# Cameyo Detection

Runtime value:

```text
CAMEYO_VIRTUALAPP,
CAMEYO_RO_VIRTUALAPP,
CAMEYO_RO_PROPERTY_VIRTUALAPP
```

Observed consumer:

```text
0x1402B5131
```

These values correspond to application virtualization indicators.

The exact source being queried remains unresolved.

---

# Speech / Voice Activation

Confirmed runtime values:

```text
SOFTWARE\Microsoft\Speech_OneCore\Preferences
VoiceActivationOn
VoiceActivationEnableAboveLockscreen
```

Observed consumers:

```text
0x1402189D2
0x1402189EC
0x140218A06
```

This confirms explicit runtime inspection of Windows speech/voice activation preferences.

---

# Process / Module Enumeration

Relevant imports include:

```text
CreateToolhelp32Snapshot

K32EnumProcesses
K32EnumProcessModules
K32EnumProcessModulesEx

K32GetModuleBaseNameA
K32GetModuleBaseNameW

K32GetModuleFileNameExA
K32GetModuleFileNameExW

K32GetProcessImageFileNameA

QueryFullProcessImageNameA
QueryFullProcessImageNameW
```

These confirm extensive process and module inspection capability.

---

# Service Inspection

Relevant imports include:

```text
EnumServicesStatusExA

OpenSCManagerA
OpenSCManagerW

OpenServiceW

QueryServiceConfigW
QueryServiceStatusEx

StartServiceW
```

The complete service-related detection set has not yet been recovered.

---

# Debugger / Timing Capabilities

Relevant imports include:

```text
IsDebuggerPresent
QueryPerformanceCounter
QueryPerformanceFrequency
GetTickCount
GetTickCount64
```

These confirm debugger/timing inspection capability.

Exact use within anti-debug or anti-tamper logic remains unresolved.

---

# Main DLL

`LockDownBrowser.dll` contains functionality associated with:

```text
hooks
Windows UI interaction
input handling
process memory
debugging-related APIs
```

No plaintext VM vendor table comparable to the executable's runtime structures has been recovered from the DLL.

Current evidence suggests that high-level environment classification is concentrated primarily in:

```text
LockDownBrowser.exe
```

---

# Kernel Driver

Driver:

```text
LockDownService215.sys
```

Observed role:

```text
Windows filesystem minifilter
```

---

## FLTMGR Imports

```text
FltRegisterFilter
FltStartFiltering
FltCreateCommunicationPort
FltSendMessage
```

These establish capability for:

```text
filesystem filtering
filter registration
communication-port creation
kernel/user messaging
```

---

## Kernel Monitoring

Observed callbacks:

```text
PsSetCreateProcessNotifyRoutineEx
PsSetCreateThreadNotifyRoutine
PsSetLoadImageNotifyRoutine
```

This gives the driver visibility into:

```text
process creation
thread creation
image/module loading
```

in addition to filesystem activity.

---

## Driver Cryptography

CNG imports indicate support for:

```text
hashing
symmetric crypto
encryption
decryption
key import/export
key-pair operations
random generation
```

Not yet confirmed:

```text
algorithm parameters
key sizes
protocol structure
message authentication format
encrypted payload semantics
```

---

# User-Mode / Kernel Communication

User-mode imports include:

```text
CreateFileA
CreateFileW
DeviceIoControl
```

Driver-side functionality includes:

```text
FltCreateCommunicationPort
FltSendMessage
```

This establishes communication capability between the browser/service components and the kernel driver.

The exact protocol is not yet mapped.

High-value unanswered questions include:

```text
device object / channel names
IOCTL values
input/output buffer layouts
command IDs
driver event IDs
which operations use IOCTL
which operations use minifilter ports
whether messages are authenticated/encrypted
```

This is currently one of the highest-value remaining research targets.

---

# Obfuscated Control Flow

A heavily protected region around:

```text
FUN_1402149b0
FUN_140214f16
FUN_140215029
```

was manually reconstructed.

This analysis revealed that Ghidra's ordinary function boundaries are frequently misleading in these regions.

Observed protection techniques include:

```text
overlapping instruction streams
RET gadgets embedded inside instruction immediates
opaque arithmetic predicates
synthetic return stacks
stack-manipulated control transfer
computed JMP targets
small arithmetic gadgets
fake/no-op functions
```

---

# One-Shot State `+0x466F4`

A scheduler checks:

```text
state + 0x466F4
```

before calling:

```text
FUN_1402149b0
```

The routine immediately performs:

```c
state->0x466F4 = 1;
```

Therefore:

> `+0x466F4` is currently best understood as a one-shot / re-entry latch for this protected routine.

It should **not** currently be labeled an enforcement flag.

---

# Dead / No-Op Functions

Several apparent functions encountered during this analysis are simply:

```asm
RET
```

Examples include:

```text
FUN_140213350
FUN_140216418
FUN_140217cb0
```

These appear to participate in protected/obfuscated control flow rather than perform meaningful application logic.

---

# Synthetic Return / Gadget Example

One protected dispatcher eventually performs:

```text
JMP 0x1402111F4
```

where:

```asm
1402111F4  CLC
1402111F5  RET
```

The return does not follow a conventional call stack.

Instead, the dispatcher constructs a synthetic sequence of addresses on the stack.

Observed gadgets included:

```asm
CLC
RET
```

```asm
MOV EAX,0x01EB0603
RET
```

```asm
MOV EAX,0x01EB0633
RET
```

```asm
XOR AL,0xF8
RET
```

```asm
ADD AL,0x8B
RET
```

```asm
AND AL,0xF8
RET
```

as well as additional arithmetic gadgets.

These collectively manipulate register and flag state before returning into another protected continuation.

---

# Overlapping Instructions

One particularly clear example occurs around:

```text
0x140215E6F
```

Normal disassembly produces:

```asm
MOV dword ptr [RSP+...],0xC39B7A76
```

The final byte of the immediate constant is:

```text
C3
```

which is the opcode for:

```asm
RET
```

A protected call directly targets that byte:

```text
0x140215E76
```

causing execution to interpret the byte as:

```asm
RET
```

rather than as part of the surrounding immediate.

This confirms deliberate use of:

> overlapping instruction streams where bytes inside otherwise valid instructions are separately executed as control-flow gadgets.

---

# Opaque Predicates

Multiple protected paths use predicates equivalent to:

```c
x * (x - 1)
```

followed by:

```text
test low bit
conditional branch
```

Because the product of consecutive integers is always even, the low bit is always zero.

Example pattern:

```asm
MOV  EAX,[...]
LEA  ECX,[EAX-1]
IMUL ECX,EAX
TEST CL,1
JNZ  ...
```

The branch is therefore mathematically impossible under ordinary integer semantics.

These predicates appear designed to confuse static analysis and decompilation.

---

# Control-Flow Analysis Conclusion

The protected region around:

```text
FUN_1402149b0
```

was investigated far enough to establish the protection methodology.

Continuing the gadget chain byte-by-byte produced diminishing returns because substantial effort was being spent reconstructing:

```text
dispatcher machinery
integrity arithmetic
opaque control flow
```

rather than Respondus application semantics.

The analysis therefore pivoted toward higher-value areas:

```text
observable policy state
VM classification writers
detection consumers
driver communication
Windows APIs with direct effects
```

---

# `"VM allowed - skipping"`

Recovered string:

```text
VM allowed - skipping
```

Address:

```text
0x140B28698
```

Ghidra reported:

```text
no direct references
```

A search for the literal 64-bit pointer:

```text
98 86 B2 40 01 00 00 00
```

also produced no match.

Therefore the string is currently classified as:

```text
present but without a confirmed direct consumer
```

Possible explanations include:

```text
dead / legacy string
runtime string decoding
indirect address construction
protected consumer
copied runtime table
```

No policy conclusion is currently derived from the string alone.

---

# Important Runtime Strings

Recovered values include:

```text
***remote***
***shutdown***
***touchpadswipe***
***hacked***
***resedit*** {%s}
***vmdetected***

VM Detected
VM allowed - skipping
vm_device
moosevm

ALLOW_MONITOR

BlockRecording
AllowRecording
AllowCapture
BlockAll
BlockBrowsers
BlockMirrors
DetectUnsigned
BlockSplitters
BlockTeramind
AllowGameBar
AllowCopyPaste

Sysinternals

PROGRAM HACKED OR INFECTED
AUTOLAUNCH SHIM DETECTED
FRGND CHECK TMPR
KEYBOARD HOOK REMOVED
ADMIN RIGHTS REMOVED

Hacked Sysinternals Desktops in use
Blocklisted process hacked to prevent detection %s = %s
Detected recording or capture file = %s
Core Mismatch Moose - %s %d
Hacking program detected - %s
MonitorPrestartComplete

Parallels
FaceTime HD

winex11.drv
winepulse.drv

CANARY
```

A recovered string by itself is not considered proof of an active detection or enforcement mechanism.

---

# Current VM / Environment Map

```text
Hardware / Platform
|
+-- system identity
|   +-- PRLS
|   +-- VBOX
|   +-- VRTUAL
|   +-- VMWare
|
+-- Registry
|   |
|   +-- VideoBiosVersion
|   |   +-- Parallels
|   |   +-- Sun VirtualBox
|   |
|   +-- SystemManufacturer
|   |   +-- VMWare
|   |
|   +-- ProcessorNameString
|       +-- QEMU
|
+-- SetupAPI Devices
|   |
|   +-- DEVICEDESC
|   +-- FRIENDLYNAME
|       |
|       +-- 26-entry VM prefix list
|       +-- VBoxAsw special handling
|
+-- COM FriendlyName
    |
    +-- FaceTime HD
         |
         +-- +0x4653A
              |
              +-- rldbvm=1


Runtime / Software Environment
|
+-- Username-related selector
|
+-- Process / module paths
|   +-- selector 8
|   +-- selector 10
|
+-- Periodically refreshed runtime artifact vector
    +-- selector 8
    +-- selector 9
         |
         +-- rldbvm=2


Device Expectation
|
+-- expected display-like device
|   +-- graphics
|   +-- nvidia
|   +-- amd
|   +-- matrox
|   +-- " arc "
|
+-- expected PCI root
    +-- PCI Express Root
         |
         +-- both mismatched
              |
              +-- rldbvm=3


Shared Artifact Detection
|
+-- runtime artifact vector
|   |
|   +-- VM2 signatures
|   +-- PTC 4,1
|
+-- ordered signature search
    |
    +-- PTC 4,2
         |
         +-- +0x2D5
              |
              +-- rldbdetect=4
```

---

# Confirmed vs. Open Findings

| Finding | Status |
| --- | --- |
| Runtime string table architecture | ✅ Confirmed |
| Prefix comparator | ✅ Confirmed |
| Prefix comparator returns `0` on match | ✅ Confirmed |
| Substring comparator | ✅ Confirmed |
| Full 26-entry VM device array | ✅ Confirmed |
| BIOS/registry VM structure | ✅ Confirmed |
| VMware indicators | ✅ Confirmed |
| VirtualBox indicators | ✅ Confirmed |
| Parallels indicators | ✅ Confirmed |
| QEMU indicators | ✅ Confirmed |
| Xen indicators | ✅ Confirmed |
| VirtIO indicators | ✅ Confirmed |
| AWS virtual-device indicators | ✅ Confirmed |
| Wine virtual-device indicators | ✅ Confirmed |
| Cameyo indicators actively consumed | ✅ Confirmed |
| `VBoxAsw` special-case behavior | ✅ Confirmed |
| FNV-1a device inventory | ✅ Confirmed |
| `rldbvm=1` writer architecture | ✅ Substantially mapped |
| `rldbvm=2` three-writer architecture | ✅ Confirmed |
| VM2 process/module path detection | ✅ Confirmed |
| VM2 periodic artifact vector | ✅ Confirmed |
| `rldbvm=3` device expectation rules | ✅ Confirmed |
| VM3 requires >1 mismatch | ✅ Confirmed |
| `rldbdetect=4` PTC 4,1 | ✅ Confirmed |
| `rldbdetect=4` PTC 4,2 | ✅ Confirmed |
| `+0x2D5` latched once detected | ✅ Confirmed |
| Direct VM2 readers are telemetry/status paths | ✅ Confirmed |
| Frida spawn causes startup failure | ✅ Observed |
| Frida attach destabilizes processes | ✅ Observed |
| Overlapping instruction streams | ✅ Confirmed |
| Synthetic return chains | ✅ Confirmed |
| Opaque predicates | ✅ Confirmed |
| `+0x466F4` one-shot latch | ✅ Confirmed |
| `"VM allowed - skipping"` direct consumer | ⚠️ Not found |
| Exact `rldbvm=1` semantic label | ⚠️ Open |
| Exact selector 8/9/10 strings | ⚠️ Open |
| Exact VM2 artifact record type | ⚠️ Open |
| Exact downstream consumer of `+0x46518` | ⚠️ Open |
| Exact downstream consumer of `+0x4651C` | ⚠️ Open |
| Exact enforcement action for VM classification | ⚠️ Open |
| `0x09D8` exact consumer | ⚠️ Open |
| `0x09ED` exact purpose | ⚠️ Open |
| Full Wine consumer path | ⚠️ Open |
| Full Cameyo consumer path | ⚠️ Open |
| Full Sysinternals desktop path | ⚠️ Open |
| Exact user/kernel protocol | ⚠️ Open |
| Driver IOCTL map | ⚠️ Open |
| Exact cryptographic protocol | ⚠️ Open |

---

# Current Research Priorities

## 1. Map User/Kernel Communication

Highest-value APIs:

```text
CreateFile
DeviceIoControl

FltCreateCommunicationPort
FltSendMessage
```

Primary goal:

```text
EXE/service
    |
    +-- device/channel acquisition
    |
    +-- command / IOCTL
    |
    +-- input buffer
    |
    +-- output buffer
    |
    +-- LockDownService215.sys
```

This should clarify which Respondus responsibilities have moved into kernel mode.

---

## 2. Find Detection Consumers

Instead of continuing through protected detector internals, prioritize consumers of consolidated state.

Targets include:

```text
+0x46518
+0x4651C

+0x4664A
+0x4664B
+0x46538

rldbvm
rldbdetect
```

Goal:

```text
classification
    ->
telemetry
    ->
policy
    ->
observable action
```

---

## 3. Finish Wine Path

Known live callsites:

```text
0x1402B52C9
0x1402B52E3
```

Known values:

```text
winex11.drv
winepulse.drv
Wine HID
Wine Adapter
Wine USB
```

---

## 4. Finish Cameyo Path

Known consumer:

```text
0x1402B5131
```

Known indicators:

```text
CAMEYO_VIRTUALAPP
CAMEYO_RO_VIRTUALAPP
CAMEYO_RO_PROPERTY_VIRTUALAPP
```

---

## 5. Finish Sysinternals / Desktop Path

Known runtime cluster:

```text
Sysinternals
Default
Winlogon
```

Known callsites:

```text
0x1402227C0
0x1402227DA
0x1402227F4
```

---

## 6. Map Process / Runtime Artifact Collections

Important unresolved structures:

```text
0x09D8 recording / remote-control table
0x09ED accessibility table

state + 0x464B0 runtime artifact vector
state + 0x3F0 ordered signature array
```

---

# Current Conclusion

Respondus LockDown Browser 2.1.5.01 clearly performs extensive environment classification across both user mode and kernel mode.

The VM-related architecture is now substantially clearer.

`rldbvm=1` is associated primarily with:

```text
hardware
platform
machine classification
COM device identity
```

`rldbvm=2` is associated primarily with:

```text
username/environment artifacts
process/module paths
periodically refreshed named runtime artifacts
```

`rldbvm=3` is associated with:

```text
expected hardware/device consistency
```

These classification systems coexist with a separate `rldbdetect` mechanism containing broader hack/tamper detections.

The same runtime artifact collection can participate in both:

```text
VM classification
and
hack-type detection
```

which demonstrates that Respondus does not maintain perfectly isolated detection subsystems.

The kernel driver additionally provides:

```text
filesystem visibility
process callbacks
thread callbacks
image-load callbacks
user/kernel communication
```

making this build more than a purely user-mode browser lockdown mechanism.

The newest major architectural finding is the executable's protected control flow.

Respondus contains code regions using:

```text
overlapping instructions
embedded RET gadgets
synthetic return stacks
opaque predicates
computed dispatch
```

This explains many previously confusing Ghidra decompilations and means that raw static function boundaries cannot always be trusted.

At the current stage, continuing to manually decode these protected dispatcher chains produces significantly less value than tracing:

```text
detection consumers
policy state
kernel communication
and observable system effects
```

The primary remaining architectural question is therefore:

> How are the already-confirmed environment classifications transformed into final policy and enforcement decisions, and which portions of that decision process are delegated to `LockDownService215.sys`?

---

# Research Status

```text
[CONFIRMED] Runtime string table
[CONFIRMED] Prefix comparison helper
[CONFIRMED] Substring comparison helper
[CONFIRMED] Device enumeration
[CONFIRMED] DEVICEDESC checks
[CONFIRMED] FRIENDLYNAME checks

[CONFIRMED] 26-entry VM/device prefix array

[CONFIRMED] Parallels checks
[CONFIRMED] VMware checks
[CONFIRMED] VirtualBox checks
[CONFIRMED] QEMU checks
[CONFIRMED] Xen checks
[CONFIRMED] Microsoft virtual-device checks
[CONFIRMED] VirtIO checks
[CONFIRMED] AWS virtual-device checks
[CONFIRMED] Wine virtual-device checks

[CONFIRMED] BIOS registry inspection
[CONFIRMED] VideoBiosVersion inspection
[CONFIRMED] SystemManufacturer inspection
[CONFIRMED] ProcessorNameString inspection

[CONFIRMED] FNV-1a device inventory

[CONFIRMED] rldbvm=1 writer
[CONFIRMED] rldbvm=2 has three independent writers
[CONFIRMED] rldbvm=2 process/module path checks
[CONFIRMED] rldbvm=2 runtime artifact vector
[CONFIRMED] VM2 artifact vector is periodically refreshed

[CONFIRMED] rldbvm=3 device-expectation mechanism
[CONFIRMED] VM3 graphics/device rule
[CONFIRMED] VM3 PCI Express Root rule

[CONFIRMED] rldbdetect=4 PTC 4,1
[CONFIRMED] rldbdetect=4 PTC 4,2
[CONFIRMED] code 4 is latched

[CONFIRMED] Cameyo indicator consumption
[CONFIRMED] Wine indicator consumption
[CONFIRMED] Sysinternals runtime handling
[CONFIRMED] Windows session/RDP handling
[CONFIRMED] speech preference inspection

[CONFIRMED] filesystem minifilter
[CONFIRMED] kernel process callbacks
[CONFIRMED] kernel thread callbacks
[CONFIRMED] kernel image-load callbacks
[CONFIRMED] user/kernel communication capability

[CONFIRMED] instrumentation-sensitive behavior
[CONFIRMED] overlapping instruction streams
[CONFIRMED] synthetic return chains
[CONFIRMED] embedded RET gadgets
[CONFIRMED] opaque predicates
[CONFIRMED] +0x466F4 one-shot latch

[OPEN] Exact rldbvm=1 semantic category
[OPEN] Exact selector 8 string
[OPEN] Exact selector 9 string
[OPEN] Exact selector 10 string
[OPEN] Exact VM2 artifact record type

[OPEN] +0x46518 downstream consumer
[OPEN] +0x4651C downstream consumer

[OPEN] Exact VM enforcement consumer
[OPEN] Exact policy transition following classification

[OPEN] Exact 0x09D8 consumer
[OPEN] Exact 0x09ED purpose

[OPEN] Full Wine path
[OPEN] Full Cameyo path
[OPEN] Full Sysinternals desktop path

[OPEN] Driver IOCTL interface
[OPEN] Minifilter communication protocol
[OPEN] Driver command/event identifiers
[OPEN] Exact cryptographic protocol
```

---

# Credits

Special thanks to [arcticdev00](https://github.com/arcticdev00) and the [Respondus-LDB-Offsets](https://github.com/arcticdev00/Respondus-LDB-Offsets) project.

That research on an earlier Respondus version provided an important starting point for this work.

This repository extends the analysis to:

```text
Respondus LockDown Browser 2.1.5.01
```

with additional work covering:

```text
runtime string-table reconstruction
device prefix recovery
BIOS/registry detection
VM state mapping
runtime artifact collections
rldbdetect behavior
dynamic instrumentation
kernel-driver architecture
protected control-flow reconstruction
```

---

# Disclaimer

This repository documents software behavior observed through reverse-engineering research.

It includes:

```text
static-analysis findings
dynamic-analysis findings
runtime observations
API capabilities
recovered strings
internal data structures
detection-state mappings
control-flow reconstruction
kernel-driver analysis
unresolved research questions
```

Where evidence is incomplete, findings are explicitly labeled as unconfirmed.

This repository does not provide a working examination-security bypass.
