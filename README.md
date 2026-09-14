# Respondus LockDown Browser 2.1.5.01 — Reverse Engineering Research

> Static and dynamic reverse-engineering research into Respondus LockDown Browser 2.1.5.01, including VM/environment detection, hardware inspection, process monitoring, runtime string tables, Windows session detection, policy controls, and kernel-driver behavior.

**Suggested repository name:** `respondus-lockdown-browser-research-2.1.5.01`

**GitHub description:**  
Reverse-engineering notes and technical findings for Respondus LockDown Browser 2.1.5.01, including VM detection, process monitoring, runtime string tables, device/BIOS checks, and kernel-driver behavior.

---

> [!IMPORTANT]
> **Research scope:** Static and dynamic analysis of Respondus LockDown Browser behavior and architecture.
>
> This repository documents observed findings, indicators, architecture, and detection mechanisms. It does **not** contain a working bypass implementation.
>
> Findings marked as **confirmed** were directly supported by the analyzed binary, imports, runtime behavior, recovered runtime data, or direct tracing. Items marked **unconfirmed** still require additional tracing before their exact purpose can be stated.

---

# Table of Contents

- [Target](#target)
- [Artifact Metadata](#artifact-metadata)
- [Executive Summary](#executive-summary)
- [High-Level Architecture](#high-level-architecture)
- [VM State Encoding](#vm-state-encoding)
- [Detection Result Encoding](#detection-result-encoding)
- [String Comparison Helpers](#string-comparison-helpers)
- [Runtime String Table](#runtime-string-table)
- [Dynamic Runtime Tracing](#dynamic-runtime-tracing)
- [Device Enumeration](#device-enumeration)
- [Confirmed Device Detection Prefix List](#confirmed-device-detection-prefix-list)
- [BIOS / Registry Detection Structure](#bios--registry-detection-structure)
- [`VBoxAsw` Special Handling](#vboxasw-special-handling)
- [Device Inventory / FNV-1a De-Duplication](#device-inventory--fnv-1a-de-duplication)
- [COM FriendlyName Enumeration](#com-friendlyname-enumeration)
- [BIOS / Baseboard / System Product Inspection](#bios--baseboard--system-product-inspection)
- [Virtualization / Environment Indicators](#virtualization--environment-indicators)
- [Important Runtime Strings](#important-runtime-strings)
- [Recording / Remote-Control / Capture Process List](#recording--remote-control--capture-process-list)
- [Accessibility / Assistive Technology List](#accessibility--assistive-technology-list)
- [Browser Blocking List](#browser-blocking-list)
- [Standalone Process / Application Indicators](#standalone-process--application-indicators)
- [Remote Desktop / Session Checks](#remote-desktop--session-checks)
- [Sysinternals Handling](#sysinternals-handling)
- [Recording / Capture Controls](#recording--capture-controls)
- [Windows Game Bar / Capture Handling](#windows-game-bar--capture-handling)
- [Speech / Voice Activation Checks](#speech--voice-activation-checks)
- [Process Enumeration Capability](#process-enumeration-capability)
- [Service Enumeration Capability](#service-enumeration-capability)
- [Registry Inspection](#registry-inspection)
- [Debugger / Timing Capabilities](#debugger--timing-capabilities)
- [Main DLL Findings](#main-dll-findings)
- [Kernel Driver](#kernel-driver)
- [Driver FLTMGR Capabilities](#driver-fltmgr-capabilities)
- [Driver Process / Thread / Image Monitoring](#driver-process--thread--image-monitoring)
- [Driver Cryptographic Capabilities](#driver-cryptographic-capabilities)
- [User-Mode / Kernel Communication](#user-mode--kernel-communication)
- [Tamper / Integrity Strings](#tamper--integrity-strings)
- [Policy / Configuration Names](#policy--configuration-names)
- [Respondus Infrastructure](#respondus-infrastructure)
- [Confirmed vs. Unconfirmed Findings](#confirmed-vs-unconfirmed-findings)
- [Current Reverse Engineering Map](#current-reverse-engineering-map)
- [Next Research Targets](#next-research-targets)
- [Current Conclusion](#current-conclusion)
- [Credits](#credits)
- [Disclaimer](#disclaimer)

---

# Target

| Property | Value |
| --- | --- |
| **Product** | Respondus LockDown Browser |
| **Version** | `2.1.5.01` |
| **Installer** | `LockDownBrowser-2-1-5-01-158741422.msi` |
| **Main executable** | `LockDownBrowser.exe` |
| **Main DLL** | `LockDownBrowser.dll` |
| **Kernel driver** | `LockDownService215.sys` |

---

# Artifact Metadata

## Main Executable

```text
LockDownBrowser.exe
```

Observed size:

```text
20,699,584 bytes
```

Ghidra image base:

```text
0x140000000
```

---

## Main DLL

```text
LockDownBrowser.dll
```

Version information:

```text
FileVersion:    23.10.31.1
ProductVersion: 2.1.1.5
FileDescription: LockDown Browser
Company: Respondus, Inc.
```

Observed image base:

```text
0x180000000
```

Observed sections include:

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

The `.cldb` section was observed as approximately:

```text
0x200 bytes
Read/Write
Non-executable
```

Observed exports include:

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

## Kernel Driver

```text
LockDownService215.sys
```

Version:

```text
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

Ghidra image base:

```text
0x140000000
```

Recovered PDB filename:

```text
LockDownService215.pdb
```

PDB GUID:

```text
9c670681-69fd-4e8f-ac01-e52be2132b12
```

PDB age:

```text
1
```

---

# Executive Summary

Respondus LockDown Browser does not rely on one isolated virtual-machine check.

The analyzed build contains multiple independent environment-monitoring, classification, policy, integrity, and enforcement systems.

Observed capabilities include:

- Device enumeration
- Device-description inspection
- Device friendly-name inspection
- Explicit VM-device prefix matching
- BIOS inspection
- Baseboard inspection
- System-product inspection
- CPU identity inspection
- Registry-based VM indicators
- Process enumeration
- Module enumeration
- Service enumeration
- Windows session/RDP inspection
- Recording/capture application detection
- Remote-control software detection
- Browser blocking
- Sysinternals-related desktop handling
- Accessibility-software handling
- Wine-related indicators
- VirtualBox-related handling
- VMware indicators
- Parallels indicators
- QEMU indicators
- Xen indicators
- VirtIO indicators
- AWS virtual-device indicators
- Cameyo virtualization indicators
- Kernel filesystem monitoring
- Kernel process callbacks
- Kernel thread callbacks
- Kernel image-load callbacks
- User-mode ↔ kernel communication
- Policy-controlled detection categories
- Program-integrity / tamper detection

One of the most useful discoveries was a runtime string table containing a large amount of Respondus' internal configuration, detection vocabulary, platform indicators, process lists, hardware indicators, and policy names in plaintext.

Dynamic instrumentation later exposed the exact runtime consumers of multiple environment-related strings and allowed the full VM/device prefix array and BIOS/registry comparison structure to be recovered.

---

# High-Level Architecture

```text
                        LockDownBrowser.exe
                               |
          +--------------------+--------------------+
          |                    |                    |
       Processes            Hardware             Sessions
       Services             Devices              RDP
       Modules              BIOS                 Desktop
          |                 Registry                |
          +--------------------+--------------------+
                               |
                     Environment / Detection
                           Accumulators
                               |
                +--------------+--------------+
                |                             |
             rldbvm                       rldbdetect
                |                             |
                +--------------+--------------+
                               |
                     Telemetry / Policy
                               |
                    LockDownService215.sys
```

The currently observed architecture suggests that several user-mode inspection mechanisms feed persistent global detection state, which is then consumed by later policy, telemetry, and enforcement logic.

---

# VM State Encoding

## Function

```text
FUN_1401ea670
```

Respondus exposes an internal VM state through the field:

```text
rldbvm
```

Observed values:

```text
rldbvm = "0"
rldbvm = "1"
rldbvm = "2"
rldbvm = "3"
```

Observed mapping:

```text
DAT_140ccc948 + 0x4664a != 0  -> rldbvm = "1"
DAT_140ccc948 + 0x4664b != 0  -> rldbvm = "2"
DAT_140ccc948 + 0x46538 != 0  -> rldbvm = "3"
```

Otherwise:

```text
rldbvm = "0"
```

Another flag:

```text
DAT_140ccc948 + 0x46651
```

causes:

```text
rldbvm     = "0"
rldbdetect = "0"
```

The exact semantic meaning of VM categories `1`, `2`, and `3` is still under investigation.

These values should currently be treated as **internal environment categories**, not as direct aliases for individual VM products.

---

# Detection Result Encoding

## Function

```text
FUN_140262110
```

This function appears to serialize already-computed detection flags rather than perform the original checks itself.

Observed mappings:

| Internal field | Detection value |
| --- | ---: |
| `object + 0x2d4` | `1` |
| `object + 0x479` | `2` |
| `object + 0x300` | `3` |
| `object + 0x2d5` | `4` |
| `object + 0x2d6` | `5` |
| `object + 0x2d7` | `6` |
| `object + 0x3fc` | `9` |
| `global + 0x448` | `10` |
| `object + 0x388` | `13` |
| `object + 0x2d9` | `16` |
| `object + 0x278` | `17` |
| `object + 0x279` | `18` |

The exact semantic meaning of each numeric detection code has not yet been fully mapped.

---

# String Comparison Helpers

## Case-Insensitive Prefix Match

Function:

```text
FUN_140296900
```

Observed behavior is approximately equivalent to:

```c
_strnicmp(value, prefix, strlen(prefix)) == 0
```

Conceptually:

```text
StartsWithIgnoreCase(value, prefix)
```

This helper is heavily used in VM/hardware/device classification.

---

## Case-Insensitive Substring Match

Function:

```text
FUN_140297050
```

Equivalent behavior:

```c
bool ContainsIgnoreCase(char *haystack, char *needle)
{
    size_t len = strlen(needle);

    for (char *p = haystack; p && *p; ++p)
    {
        if (_strnicmp(p, needle, len) == 0)
            return true;
    }

    return false;
}
```

Conceptually:

```text
ContainsIgnoreCase(value, pattern)
```

---

# Runtime String Table

## Function

```text
FUN_1401fc0e0
```

Recovered implementation:

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

    entry = (undefined8 *)
        (base + (longlong)(param_3 / 0x15) * 0x20);

    if (0xf < (ulonglong)entry[3])
        entry = (undefined8 *)*entry;

    return entry;
}
```

For table type:

```text
0x3B
```

the table base is:

```text
param_1[6]
```

which corresponds to:

```text
context + 0x30
```

Each table element occupies:

```text
0x20 bytes
```

and behaves like an MSVC `std::string`.

The ID/index relationship is:

```text
index = ID / 0x15
ID    = index * 0x15
```

Examples:

| Index | ID | Value |
| ---: | ---: | --- |
| `0x74` | `0x984` | `HARDWARE\DESCRIPTION\System\CentralProcessor\0` |
| `0x75` | `0x999` | `ProcessorNameString` |
| `0x78` | `0x9D8` | Large recording / remote-control process list |
| `0x79` | `0x9ED` | Accessibility / assistive-technology list |
| `0x7D` | `0xA41` | `HARDWARE\DESCRIPTION\System\BIOS` |
| `0x7E` | `0xA56` | `BaseBoardManufacturer` |
| `0x7F` | `0xA6B` | `BaseBoardProduct` |
| `0x80` | `0xA80` | `SystemProductName` |
| `0x81` | `0xA95` | `Parallels` |
| `0x82` | `0xAAA` | `FaceTime HD` |

A Frida-based runtime dump successfully recovered hundreds of plaintext strings from this table.

---

# Dynamic Runtime Tracing

Frida instrumentation was used to hook:

```text
FUN_1401fc0e0
```

at runtime.

This revealed live string-table lookups and their exact callsites.

Observed runtime lookups included:

| String ID | Runtime value | Caller |
| ---: | --- | --- |
| `0x999` | `ProcessorNameString` | `0x1402b6e6b` |
| `0x984` | `HARDWARE\DESCRIPTION\System\CentralProcessor\0` | `0x1402b6e85` |
| `0xB67` | ` BIOS: ` | `0x1402b3130` |
| `0xB7C` | ` DEVICES: ` | `0x1402b36cf` |
| `0x20D` | `VBoxAsw` | `0x1402b3a89` |
| `0x20D` | `VBoxAsw` | `0x1402b3e3c` |
| `0x1F8` | Cameyo environment list | `0x1402b5131` |
| `0xCB7` | `winex11.drv` | `0x1402b52c9` |
| `0xCB7` | `winex11.drv` | `0x1402b52e3` |
| `0x46E` | Speech preferences registry path | `0x1402189d2` |
| `0x483` | `VoiceActivationOn` | `0x1402189ec` |
| `0x498` | `VoiceActivationEnableAboveLockscreen` | `0x140218a06` |
| `0x6BA` | `WinSta0` | `0x140202d9b` |
| `0x6CF` | `Sysinternals` | `0x1402227c0` |
| `0x6E4` | `Default` | `0x1402227da` |
| `0x6F9` | `Winlogon` | `0x1402227f4` |

This establishes that these values are not merely dormant strings in the binary: they are actively retrieved during normal startup/environment inspection.

## Important Negative Finding

During the observed startup trace:

```text
ID 0x09D8
```

was **not** retrieved through `FUN_1401fc0e0`.

This means the large recording/remote-control list may be:

- loaded through a different path,
- parsed during another application phase,
- retrieved only when a relevant policy is enabled,
- copied during configuration initialization,
- or consumed indirectly.

The table entry itself is confirmed, but its exact runtime consumer remains open.

---

# Device Enumeration

## Function

```text
FUN_1402b30d0
```

This is now one of the best-understood environment-detection functions in the analyzed build.

Observed APIs include:

```text
SetupDiGetClassDevsW
SetupDiEnumDeviceInfo
SetupDiGetDeviceRegistryPropertyA
```

The function retrieves at least:

```text
SPDRP_DEVICEDESC
SPDRP_FRIENDLYNAME
```

Specifically:

```text
Property 0x00 -> SPDRP_DEVICEDESC
Property 0x0C -> SPDRP_FRIENDLYNAME
```

Both values are checked against a runtime-loaded VM/device detection prefix array.

The same function also performs:

- system identity checks,
- registry-based VM checks,
- device inventory collection,
- diagnostic string construction,
- device de-duplication,
- and consolidated detection-flag updates.

---

# Confirmed Device Detection Prefix List

The runtime structure:

```text
DAT_140cccba8 + 0x233d0
```

contains a pointer to the device detection prefix array.

The count is stored at:

```text
DAT_140cccba8 + 0x233d8
```

At runtime:

```text
Count = 26
```

These entries are compared against both:

```text
SPDRP_DEVICEDESC
SPDRP_FRIENDLYNAME
```

using:

```text
FUN_140296900
```

which is a case-insensitive prefix matcher.

The recovered list is:

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

This confirms direct device-level coverage for:

- Parallels
- VMware
- older VM Additions-style virtual hardware
- VirtualBox
- QEMU
- Xen
- Microsoft virtual devices
- VirtIO / Red Hat virtualization
- AWS virtual hardware
- Wine virtual hardware

## Simplified Device Matching Logic

```c
for each Windows device:
{
    description = SPDRP_DEVICEDESC;
    friendly    = SPDRP_FRIENDLYNAME;

    if (!StartsWithIgnoreCase(description, "VBoxAsw"))
    {
        for each VMDevicePrefix:
        {
            if (StartsWithIgnoreCase(description, VMDevicePrefix))
                detected = true;
        }
    }

    if (!StartsWithIgnoreCase(friendly, "VBoxAsw"))
    {
        for each VMDevicePrefix:
        {
            if (StartsWithIgnoreCase(friendly, VMDevicePrefix))
                detected = true;
        }
    }
}
```

---

# BIOS / Registry Detection Structure

The runtime structure referenced through:

```text
DAT_140cccba8 + 0x233e0
```

was recovered in plaintext.

Observed fields:

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

> `VRTUAL` is spelled exactly this way in the runtime data.

Do not silently correct it to `VIRTUAL`.

---

## Confirmed System Identity Checks

A machine/system identity string at:

```text
DAT_140ccc960 + 0x254
```

is tested against:

```text
PRLS
VBOX
VRTUAL
VMWare
```

Observed semantics:

```text
PRLS    -> case-insensitive prefix
VBOX    -> case-insensitive prefix
VRTUAL  -> case-insensitive prefix
VMWare  -> case-insensitive substring
```

---

## Confirmed Registry Checks

### Parallels / VirtualBox Video BIOS

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

using prefix matching.

---

### VMware System Manufacturer

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

using prefix matching.

---

### QEMU CPU Identity

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

using prefix matching.

---

# `VBoxAsw` Special Handling

A previous assumption was that:

```text
VBoxAsw
```

was simply another positive VirtualBox detection prefix.

Tracing `FUN_1402b30d0` showed that this is **not** what happens in this function.

The actual logic is:

```c
pattern = GetRuntimeString(0x20D); // "VBoxAsw"

if (!StartsWithIgnoreCase(deviceString, pattern))
{
    CheckGenericVMDevicePrefixList(deviceString);
}
```

Therefore, in `FUN_1402b30d0`:

```text
VBoxAsw
```

acts as a **special-case exclusion from the generic device-prefix detection path**.

It is actively retrieved once for device descriptions and once for friendly names.

Observed runtime callsites:

```text
0x1402b3a89
0x1402b3e3c
```

Because the comparison occurs once per enumerated device/property, the string appears repeatedly in Frida tracing.

This finding corrects the earlier interpretation that `VBoxAsw` was itself necessarily a positive VM trigger.

Its behavior in other functions, if any, has not yet been exhaustively mapped.

---

# Device Inventory / FNV-1a De-Duplication

`FUN_1402b30d0` also maintains a device inventory.

Device strings are hashed with FNV-1a 64-bit.

Constants:

```text
Offset basis:
0xCBF29CE484222325

Prime:
0x100000001B3
```

Equivalent operation:

```c
hash = 0xCBF29CE484222325;

for each byte:
    hash = (hash ^ byte) * 0x100000001B3;
```

The hash is used to check whether a device string has already been recorded.

New values are appended to a diagnostic/inventory string at approximately:

```text
DAT_140ccc948 + 0x46878
```

This path appears to perform:

```text
device inventory
+
de-duplication
+
diagnostic logging
```

rather than act as the actual VM decision logic.

---

# Consolidated Output of `FUN_1402b30d0`

The accumulated result eventually reaches:

```c
*(uint *)(DAT_140ccc948 + 0x46518) |= detected;
*(uint *)(DAT_140ccc948 + 0x4651c) |= detected;
```

The function also increments:

```text
DAT_140ccc948 + 0x46908
```

The two fields:

```text
+0x46518
+0x4651c
```

are therefore high-value downstream detection-state targets.

They currently appear to hold or accumulate the result of:

- system identity checks,
- BIOS checks,
- registry checks,
- device-description checks,
- device-friendly-name checks.

The exact downstream consumer of these two fields remains a high-priority research target.

---

# Bluetooth Enumerator Check

During device-description processing, Respondus explicitly compares against:

```text
Bluetooth Enumerator
```

and can set:

```text
*param_1 = 1
```

when the associated comparison succeeds.

The exact higher-level meaning of this output parameter has not yet been fully mapped.

---

# COM FriendlyName Enumeration

## Function

```text
FUN_14023dda0
```

This function:

1. Calls `CoInitialize`
2. Creates a COM object
3. Enumerates objects
4. Retrieves:

```text
FriendlyName
```

5. Converts the value to a plaintext C string
6. Applies environment-related string matching

A runtime string lookup:

```text
ID 0xAAA
```

resolves to:

```text
FaceTime HD
```

The function performs:

```c
if (ContainsIgnoreCase(FriendlyName, "FaceTime HD"))
    DAT_140ccc948[0x4653a] = 1;
```

That flag later feeds:

```text
FUN_1402141b0
```

and can contribute to:

```text
DAT_140ccc948 + 0x4664a = 1
```

which maps to:

```text
rldbvm = "1"
```

A literal:

```text
virtual
```

is also passed through the substring helper in the same routine.

In the analyzed decompile, that particular return value was not visibly consumed, so it should not yet be treated as a confirmed positive trigger.

---

# BIOS / Baseboard / System Product Inspection

## Function

```text
FUN_1402141b0
```

This routine contains broader machine/platform classification.

Recovered strings include:

```text
HARDWARE\DESCRIPTION\System\BIOS
BaseBoardManufacturer
BaseBoardProduct
SystemProductName
Parallels
FaceTime HD
Apple M1 Pro
```

The routine explicitly recognizes:

```text
Apple M1 Pro
```

using the case-insensitive prefix matcher.

It also consumes machine/platform data and performs table-based classification.

A boolean accumulator is ultimately ORed with:

```text
DAT_140ccc948 + 0x4653a
```

and a positive result can set:

```text
DAT_140ccc948 + 0x4664a = 1
```

which contributes to:

```text
rldbvm = "1"
```

This supports the conclusion that `rldbvm=1` represents broader platform/environment classification rather than one simple `"Parallels detected"` condition.

---

# Virtualization / Environment Indicators

## Parallels

Confirmed indicators include:

```text
PRLS
Parallels
Parallels Video Driver
Parallels Network Adapter
Parallels Mouse Synchronization Tool
PRL Virtual CD-ROM
```

Observed detection surfaces include:

- system identity
- `VideoBiosVersion`
- device description
- device friendly name
- broader hardware/platform classification

---

## VMware

Confirmed indicators include:

```text
VMWare
VMWare SVGA II
VMWare SVGA
VMWare Pointing Device
VMWare Accelerated AMD PCNet Adapter
VMWare SCSI Controller
VMWare Virtual IDE Hard Drive
```

Observed surfaces include:

- system identity substring matching
- BIOS `SystemManufacturer`
- device descriptions
- device friendly names

---

## VirtualBox

Confirmed indicators include:

```text
VBOX
Sun VirtualBox
```

and special handling for:

```text
VBoxAsw
```

Observed surfaces include:

- system identity
- `VideoBiosVersion`
- device prefixes

`VBoxAsw` itself behaves as a special-case exclusion in the currently traced device-prefix routine.

---

## QEMU

Confirmed indicators include:

```text
QEMU
```

in both:

- CPU `ProcessorNameString`
- device-prefix matching

---

## Xen

Confirmed device prefix:

```text
XEN
```

---

## Microsoft Virtual Devices

Confirmed prefix:

```text
Msft Virtual
```

---

## VirtIO

Confirmed prefix:

```text
Red Hat VirtIO
```

---

## AWS Virtual Hardware

Confirmed prefixes include:

```text
Amazon Elastic Network Adapter
Amazon Outbound Audio
AWS Virtual Camera
AWS Virtual DOD Driver
AWS Virtual Microphone Device
```

This demonstrates explicit AWS virtual-hardware awareness beyond a generic network-adapter check.

---

## Wine

Confirmed device prefixes:

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

Live lookup of:

```text
winex11.drv
```

was observed from:

```text
0x1402b52c9
0x1402b52e3
```

The exact enforcement result of those driver checks remains under investigation.

---

## Cameyo

Recovered runtime value:

```text
CAMEYO_VIRTUALAPP,CAMEYO_RO_VIRTUALAPP,CAMEYO_RO_PROPERTY_VIRTUALAPP
```

Live consumer:

```text
0x1402b5131
```

These are associated with application virtualization.

---

## Older VM Additions Indicators

Confirmed prefixes:

```text
VM Additions S3 Trio32/64
VM Additions PS/2 Port Mouse
VM Additions PC/AT Enhanced PS/2 Keyboard
```

---

## Other VM-Related Values

Recovered values include:

```text
***vmdetected***
VM Detected
vm_device
moosevm
VRTUAL
```

The exact consumers for all of these have not yet been fully mapped.

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

VBoxAsw
PG splitter
TriDef

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

ldbhackapp
moosevm
vm_device

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

VM Detected
Parallels
FaceTime HD

winex11.drv
winepulse.drv

CANARY
```

A recovered string by itself does **not** prove how it is enforced.

Where possible, this repository distinguishes:

```text
string exists
```

from:

```text
string is actively consumed
```

and:

```text
string is confirmed to cause a particular detection state
```

---

# Recording / Remote-Control / Capture Process List

Runtime entry:

```text
index: 0x78
ID:    0x09D8
```

Recovered plaintext list:

```text
ActionsServer.exe
apc_Admin.exe
apc_host.exe
AceThinker Screen Grabber Pro.exe
Apowersoft Screen Recorder Pro 2.exe
AnyDesk.exe
AVSScreenCapture.exe
AVSVideoEditor.exe
AVCUltimate.exe
ActivePresenter.exe
AweSun.exe
bomgar-scc.exe
BASupApp.exe
CrossLoopConnect.exe
CrossLoopService.exe
CoScreen.exe
Debut.exe
deskin_service.exe
deskin.exe
DeskIn_Session.exe
dwagsvc.exe
dwaglnc.exe
dwagent.exe
Filmora.exe
FSRecorder.exe
FSEditor.exe
FreeOnlineScreenRecorder.exe
g2svc.exe
g2comm.exe
Gameshow.exe
Gyazowin.exe
GyazoGIF.exe
GyazoReplay.exe
GyStation.exe
getscreen.exe
IgRemote.exe
IperiusRemote_2.exe
join.me.exe
JumpConnect.exe
Kaltura Capture.exe
LogMeIn.exe
LogiCapture.exe
Loom.exe
mnmsrvc.exe
mstsc.exe
MSOSREC.EXE
mdrserv.exe
Mikogo-host.exe
MingleStream.exe
Mingleview.exe
ncscc.exe
NetChat.exe
NetCtl.exe
NetServ.exe
Nimbus Capture.exe
nxclient.exe
nxserver.exe
nxd.exe
nxnode.exe
nxserver64.exe
nxserver32.exe
OBS.exe
obs64.exe
obs32.exe
psr.exe
Parsecd.exe
quickshot.exe
quickassist.exe
ROMServer.exe
RPAccess.exe
RPAccessHS.exe
RCPServer.exe
remoting_desktop.exe
RemotePCDesktop.exe
RemotePCUIU.exe
RemotePCBlackScreenApp.exe
RemotePCService.exe
RPCPerfViewer.exe
RServer3.exe
RPCSetup.exe
RPCPerformanceService.exe
recorder.exe
record.exe
RelayRecorder.exe
RoyalTS.exe
RemotixAgentService.exe
ReplayVideo.exe
rutserv.exe
RpcDND_Console.exe
SRServer.exe
SRService.exe
ScreenConnect.WindowsClient.exe
ScreenCapture.exe
ShareX.exe
ScreenRecorder.exe
screen_recorder.exe
Screenleap.exe
ScnRec.exe
spcplink.exe
TeamViewer.exe
tvnserver.exe
tvnviewer.exe
TiClientCore.exe
TurboMeeting.exe
UltraViewer_Desktop.exe
vncviewer.exe
vncagent.exe
vncserver.exe
virola_client_win.exe
voovmeetingapp.exe
Win2VNC.exe
WinVNC.exe
WinVNC4.exe
WinSSHD.exe
WiSSH.exe
Wirecast.exe
XSplit.Gamecaster.exe
XSplit.Core.exe
XSplit.xgcbp.exe
YuuGuu.exe
zoho.exe
AllowRecording
```

The contents strongly correlate with:

- remote administration
- remote desktop
- screen recording
- screen capture
- streaming
- video capture
- support/control tools

A nearby runtime string states:

```text
Detected recording or capture file = %s
```

> [!CAUTION]
> The list is confirmed.
>
> It has **not yet been proven that every individual entry is always an unconditional hard block**.
>
> The exact consumer of runtime ID `0x09D8` remains under investigation.

---

# Accessibility / Assistive Technology List

Runtime entry:

```text
index: 0x79
ID:    0x09ED
```

Recovered list:

```text
dragonbar.exe
natspeak.exe
dgnuiasvr_x64.exe
dgnsvc.exe
dgnuiasvr.exe
nvda.exe
nvdaHelperRemoteLoader.exe
jfw.exe
FSOcrServer.exe
VoiceAssistant.exe
AccEventCacheLoader.exe
jhookldr.exe
fsSynth32.exe
Zt.exe
ZtUac.exe
AiSquared.Magnification.Service.exe
AiSquared.ZoomText.UI.exe
QuickAccessBar.exe
AiSquared.Loader.Elevated.exe
ProtectedUI.exe
ZtOff.exe
AiSquared.Magnification.ZoomText.exe
ztVoice32.exe
```

This includes software associated with:

- Dragon
- NVDA
- JAWS
- ZoomText

> [!WARNING]
> This table should **not currently be labeled a blacklist**.

Possible purposes include:

- accessibility exceptions
- compatibility handling
- special-case handling
- allowlisting
- detection

The exact consumer remains open.

---

# Browser Blocking List

Recovered values include:

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

Nearby policy string:

```text
BlockBrowsers
```

This strongly suggests browser-process blocking.

---

# Standalone Process / Application Indicators

Recovered process/application values include:

```text
mstsc.exe
lsynchost.exe
unlocker.exe
teas helpers.exe
svchost.exe
tmagentsvc.exe
AlertusDesktopAlert.exe
```

Associated strings include:

```text
BlockTeramind
Hacking program detected - %s
Hacking program detected - (Discord2025) =
Blocklisted process hacked to prevent detection %s = %s
Unclosed app %s
Second Process List:
```

The exact behavior associated with every standalone value has not yet been mapped.

---

# Remote Desktop / Session Checks

Recovered values include:

```text
SYSTEM\CurrentControlSet\Control\Terminal Server\
GlassSessionId
mstsc.exe
WinSta0
```

Relevant imports include:

```text
WTSRegisterSessionNotification
WTSUnRegisterSessionNotification
WTSGetActiveConsoleSessionId
ProcessIdToSessionId
```

This confirms explicit Windows session-awareness and RDP-related handling.

---

# Sysinternals Handling

Recovered strings include:

```text
Sysinternals
Hacked Sysinternals Desktops in use
```

Dynamic tracing additionally showed a cluster of runtime lookups:

```text
0x1402227c0 -> Sysinternals
0x1402227da -> Default
0x1402227f4 -> Winlogon
```

Because:

```text
Default
Winlogon
Sysinternals
```

are retrieved together, this appears more consistent with Windows desktop/window-station enumeration or desktop classification than with a simple `"block every Sysinternals executable"` process check.

The nearby string:

```text
Hacked Sysinternals Desktops in use
```

further supports that interpretation.

The containing function still requires complete static tracing before the exact detection semantics are stated.

---

# Recording / Capture Controls

Recovered configuration names include:

```text
BlockRecording
AllowRecording
AllowCapture
BlockAll
BlockMirrors
BlockSplitters
```

Recovered filesystem-related values include:

```text
%USERPROFILE%\Videos\Captures
Screenshots
```

Recovered log string:

```text
Detected recording or capture file = %s
```

Together, these support both:

- process/application-based capture monitoring
- filesystem/output-artifact monitoring

---

# Windows Game Bar / Capture Handling

Recovered values include:

```text
AllowGameBar
%USERPROFILE%\Videos\Captures
Screenshots
AllowCapture
```

This indicates explicit handling of Windows capture/Game Bar behavior.

---

# Speech / Voice Activation Checks

Recovered registry path:

```text
SOFTWARE\Microsoft\Speech_OneCore\Preferences
```

Recovered values:

```text
VoiceActivationOn
VoiceActivationEnableAboveLockscreen
```

Dynamic runtime consumers:

```text
0x1402189d2 -> registry path
0x1402189ec -> VoiceActivationOn
0x140218a06 -> VoiceActivationEnableAboveLockscreen
```

This confirms that these values are actively inspected at runtime.

---

# Process Enumeration Capability

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

These imports confirm extensive user-mode process/module inspection capability.

---

# Service Enumeration Capability

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

These confirm Windows service enumeration and inspection capability.

The complete service-related detection list has not yet been recovered.

---

# Registry Inspection

Relevant imports include:

```text
RegOpenKeyA
RegOpenKeyExA
RegQueryValueExA
RegCreateKey*
RegSetValue*
RegDelete*
```

Confirmed or recovered registry targets include:

```text
HARDWARE\DESCRIPTION\System

HARDWARE\DESCRIPTION\System\BIOS

HARDWARE\DESCRIPTION\System\CentralProcessor\0

SYSTEM\CurrentControlSet\Control\Terminal Server\

SYSTEM\CurrentControlSet\services\MainLSyncHost

SOFTWARE\Microsoft\Speech_OneCore\Preferences
```

Known queried values include:

```text
VideoBiosVersion
SystemManufacturer
ProcessorNameString
VoiceActivationOn
VoiceActivationEnableAboveLockscreen
```

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

These establish debugger/timing-inspection capability.

Their precise use in VM detection or anti-tamper logic has not yet been fully traced.

---

# Main DLL Findings

`LockDownBrowser.dll` imports APIs related to:

- input handling
- hooks
- debugging
- process memory
- Windows UI interaction

No obvious plaintext VM vendor list was recovered from the DLL comparable to the runtime VM/device structures found in the executable.

Current evidence suggests that much of the high-level environment classification is concentrated in:

```text
LockDownBrowser.exe
```

while the DLL appears more focused on hook/browser behavior.

---

# Kernel Driver

## Driver Information

| Property | Value |
| --- | --- |
| **Driver** | `LockDownService215.sys` |
| **Version** | `2.15.0.1` |
| **SHA256** | `323FAE10C53E74C2418C8D1BD45E54DE63241135BEB81196FDA0F6A16C3D5996` |
| **Service name** | `LockDownService215` |
| **Driver type** | `FILE_SYSTEM_DRIVER` |
| **Start type** | `SYSTEM_START` |
| **Filter class** | `FSFilter Bottom` |
| **Observed altitude** | `47777` |
| **Observed instances** | `4` |
| **Observed frame** | `0` |
| **Dependency** | `FltMgr` |

The driver was observed running as a Windows filesystem minifilter.

---

# Driver FLTMGR Capabilities

Relevant imports include:

```text
FltRegisterFilter
FltStartFiltering
FltCreateCommunicationPort
FltSendMessage
```

These confirm capability for:

- minifilter registration
- filesystem filtering
- communication-port creation
- user/kernel message passing

---

# Driver Process / Thread / Image Monitoring

Observed kernel imports include:

```text
PsSetCreateProcessNotifyRoutineEx
PsSetCreateThreadNotifyRoutine
PsSetLoadImageNotifyRoutine
```

These confirm kernel-mode capability to monitor:

- process creation
- thread creation
- image/module loading

The driver therefore has visibility extending beyond ordinary filesystem filtering.

---

# Driver Cryptographic Capabilities

Observed CNG imports indicate functionality related to:

- hashing
- symmetric-key operations
- encryption
- decryption
- key-pair operations
- key import/export
- random generation

The following remain unconfirmed:

```text
exact AES mode
exact AES key size
exact RSA key size
exact protocol framing
exact encrypted message contents
```

---

# User-Mode / Kernel Communication

User-mode imports include:

```text
CreateFileA
CreateFileW
DeviceIoControl
```

The driver imports:

```text
FltCreateCommunicationPort
FltSendMessage
```

This strongly indicates a dedicated user/kernel communication protocol.

The exact protocol remains unmapped.

Open questions include:

- which component initiates the channel,
- message structure,
- command IDs,
- event types,
- whether the executable uses IOCTLs directly,
- what is sent over the minifilter communication port,
- whether cryptographic functionality protects or authenticates messages.

---

# Tamper / Integrity Strings

Recovered strings include:

```text
PROGRAM HACKED OR INFECTED
AUTOLAUNCH SHIM DETECTED
KEYBOARD HOOK REMOVED
ADMIN RIGHTS REMOVED
Blocklisted process hacked to prevent detection %s = %s
Early Exit - Sending to AWS
FRGND CHECK TMPR
```

These indicate integrity/tamper monitoring separate from ordinary VM and application detection.

---

# Policy / Configuration Names

Recovered values include:

```text
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
```

This strongly suggests that significant portions of Respondus behavior are policy-controlled rather than universally hard-coded to one response.

---

# Respondus Infrastructure

Recovered hostnames include:

```text
campusportal.respondus.com
server-profiles-respondus-com.s3-external-1.amazonaws.com
smc-service-cloud.respondus2.com
help-center-respondus-com.s3.amazonaws.com
notification-images-respondus-com.s3.amazonaws.com
autolaunch.respondus2.com
downloads.respondus.com
```

Recovered paths include:

```text
/services/ldb/offline-allow.htm
/overrides/cldb8675309.htm
/MONServer/ldb/sdk_expired.do
```

---

# Confirmed vs. Unconfirmed Findings

| Finding | Status |
| --- | --- |
| Device enumeration | ✅ Confirmed |
| `SPDRP_DEVICEDESC` inspection | ✅ Confirmed |
| `SPDRP_FRIENDLYNAME` inspection | ✅ Confirmed |
| Case-insensitive prefix matcher | ✅ Confirmed |
| Case-insensitive substring matcher | ✅ Confirmed |
| Full VM/device prefix array recovered | ✅ Confirmed |
| Device prefix count = 26 | ✅ Confirmed |
| Device prefixes applied to DEVICEDESC | ✅ Confirmed |
| Device prefixes applied to FRIENDLYNAME | ✅ Confirmed |
| Parallels device indicators | ✅ Confirmed |
| VMware device indicators | ✅ Confirmed |
| VirtualBox device indicator `VBOX` | ✅ Confirmed |
| QEMU device indicator | ✅ Confirmed |
| Xen device indicator | ✅ Confirmed |
| Microsoft virtual-device indicator | ✅ Confirmed |
| VirtIO device indicator | ✅ Confirmed |
| AWS virtual-device indicators | ✅ Confirmed |
| Wine virtual-device indicators | ✅ Confirmed |
| BIOS registry inspection | ✅ Confirmed |
| `VideoBiosVersion` inspection | ✅ Confirmed |
| `SystemManufacturer` inspection | ✅ Confirmed |
| CPU `ProcessorNameString` inspection | ✅ Confirmed |
| Parallels registry comparison | ✅ Confirmed |
| VMware registry comparison | ✅ Confirmed |
| Sun VirtualBox registry comparison | ✅ Confirmed |
| QEMU CPU comparison | ✅ Confirmed |
| `PRLS` system-identity comparison | ✅ Confirmed |
| `VBOX` system-identity comparison | ✅ Confirmed |
| `VMWare` system-identity comparison | ✅ Confirmed |
| `VRTUAL` system-identity comparison | ✅ Confirmed |
| `VBoxAsw` actively consumed | ✅ Confirmed |
| `VBoxAsw` special-case exclusion in `FUN_1402b30d0` | ✅ Confirmed |
| FNV-1a device de-duplication | ✅ Confirmed |
| Detection state ORed into `+0x46518` | ✅ Confirmed |
| Detection state ORed into `+0x4651c` | ✅ Confirmed |
| `FaceTime HD` FriendlyName matching | ✅ Confirmed |
| `Parallels` broader platform matching | ✅ Confirmed |
| Cameyo virtualization string actively consumed | ✅ Confirmed |
| `winex11.drv` actively consumed | ✅ Confirmed |
| Process enumeration capability | ✅ Confirmed |
| Module enumeration capability | ✅ Confirmed |
| Service inspection capability | ✅ Confirmed |
| RDP/session inspection | ✅ Confirmed |
| Sysinternals runtime string consumption | ✅ Confirmed |
| Recording/remote-control process table exists | ✅ Confirmed |
| Accessibility process table exists | ✅ Confirmed |
| Browser process table exists | ✅ Confirmed |
| Kernel filesystem minifilter | ✅ Confirmed |
| Kernel process callback capability | ✅ Confirmed |
| Kernel thread callback capability | ✅ Confirmed |
| Kernel image-load callback capability | ✅ Confirmed |
| User/kernel communication capability | ✅ Confirmed |
| Every `0x09D8` entry always hard-blocked | ⚠️ Not yet confirmed |
| Exact consumer of `0x09D8` | ⚠️ Not yet confirmed |
| Accessibility list is a blacklist | ⚠️ Not confirmed |
| Exact meaning of `+0x46518` downstream | ⚠️ Not yet confirmed |
| Exact meaning of `+0x4651c` downstream | ⚠️ Not yet confirmed |
| Exact meaning of `rldbvm=1` | ⚠️ Not yet confirmed |
| Exact meaning of `rldbvm=2` | ⚠️ Not yet confirmed |
| Exact meaning of `rldbvm=3` | ⚠️ Not yet confirmed |
| CPUID hypervisor-bit check | ⚠️ Not yet confirmed |
| Complete SMBIOS parsing behavior | ⚠️ Not yet confirmed |
| Exact driver communication protocol | ⚠️ Not yet confirmed |
| Exact cryptographic message format | ⚠️ Not yet confirmed |

---

# Highest-Value Confirmed Environment Indicators

```text
PRLS
Parallels
Parallels Video Driver
Parallels Network Adapter
Parallels Mouse Synchronization Tool
PRL Virtual CD-ROM

VMWare
VMWare SVGA II
VMWare SVGA
VMWare Pointing Device
VMWare Accelerated AMD PCNet Adapter
VMWare SCSI Controller
VMWare Virtual IDE Hard Drive

VBOX
Sun VirtualBox
VBoxAsw

QEMU
XEN
Msft Virtual
Red Hat VirtIO

Amazon Elastic Network Adapter
Amazon Outbound Audio
AWS Virtual Camera
AWS Virtual DOD Driver
AWS Virtual Microphone Device

Wine HID
Wine Adapter
Wine USB
winex11.drv
winepulse.drv

CAMEYO_VIRTUALAPP
CAMEYO_RO_VIRTUALAPP
CAMEYO_RO_PROPERTY_VIRTUALAPP

VM Additions S3 Trio32/64
VM Additions PS/2 Port Mouse
VM Additions PC/AT Enhanced PS/2 Keyboard

VRTUAL

HARDWARE\DESCRIPTION\System
VideoBiosVersion

HARDWARE\DESCRIPTION\System\BIOS
SystemManufacturer

HARDWARE\DESCRIPTION\System\CentralProcessor\0
ProcessorNameString
```

---

# Current Reverse Engineering Map

```text
Machine / System Identity
        |
        +--> PRLS             [prefix]
        +--> VBOX             [prefix]
        +--> VRTUAL           [prefix]
        +--> VMWare           [substring]


HKLM\HARDWARE\DESCRIPTION\System
        |
        +--> VideoBiosVersion
                |
                +--> Parallels
                +--> Sun VirtualBox


HKLM\HARDWARE\DESCRIPTION\System\BIOS
        |
        +--> SystemManufacturer
                |
                +--> VMWare


HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0
        |
        +--> ProcessorNameString
                |
                +--> QEMU


Windows SetupAPI
        |
        +--> SPDRP_DEVICEDESC
        |
        +--> SPDRP_FRIENDLYNAME
                |
                +--> VBoxAsw special case
                |
                +--> 26-entry VM/device prefix list
                        |
                        +--> Parallels
                        +--> VMware
                        +--> VM Additions
                        +--> VBOX
                        +--> QEMU
                        +--> XEN
                        +--> Microsoft Virtual
                        +--> VirtIO
                        +--> AWS virtual devices
                        +--> Wine


Device Inventory
        |
        +--> FNV-1a 64-bit
        |
        +--> de-duplication
        |
        +--> diagnostic device list


Combined FUN_1402b30d0 detection
        |
        +--> DAT_140ccc948 + 0x46518
        |
        +--> DAT_140ccc948 + 0x4651c


COM Enumeration
        |
        +--> FriendlyName
                |
                +--> FaceTime HD
                        |
                        +--> +0x4653a
                                |
                                +--> FUN_1402141b0
                                        |
                                        +--> +0x4664a
                                                |
                                                +--> rldbvm = 1


Wine / Cameyo
        |
        +--> CAMEYO_* values
        +--> winex11.drv
        +--> winepulse.drv


Desktop / Session Logic
        |
        +--> WinSta0
        +--> Sysinternals
        +--> Default
        +--> Winlogon
        +--> WTS APIs
        +--> Terminal Server registry


Process Monitoring
        |
        +--> Recording / remote-control table
        +--> Browser table
        +--> Individual process indicators
        +--> Accessibility table


Kernel Driver
        |
        +--> Filesystem minifilter
        +--> Process callbacks
        +--> Thread callbacks
        +--> Image-load callbacks
        +--> Communication port
```

---

# Next Research Targets

## 1. Trace `+0x46518`

`FUN_1402b30d0` ORs its consolidated environment-detection result into:

```text
DAT_140ccc948 + 0x46518
```

### Goal

Identify:

```text
who reads it
        |
        v
what decision it influences
        |
        v
whether it feeds rldbvm / rldbdetect / telemetry / enforcement
```

---

## 2. Trace `+0x4651c`

The same detection result is also ORed into:

```text
DAT_140ccc948 + 0x4651c
```

Determine why two persistent fields receive the same result and how their downstream consumers differ.

---

## 3. Finish `rldbvm` State Mapping

Continue tracing writers/readers for:

```text
+0x4664a
+0x4664b
+0x46538
```

Goal:

```text
rldbvm = 1 -> exact semantic category
rldbvm = 2 -> exact semantic category
rldbvm = 3 -> exact semantic category
```

---

## 4. Trace the `0x09D8` Process List

The runtime entry exists at:

```text
table 0x3B
index 0x78
ID 0x09D8
```

but was not observed being retrieved through `FUN_1401fc0e0` during the traced startup run.

### Goal

Determine whether it is:

- copied during initialization,
- retrieved through another function,
- policy-conditional,
- tokenized elsewhere,
- or consumed later during exam startup.

Then determine whether entries represent:

- exact process blocks,
- substring matches,
- monitor-only entries,
- terminate-on-detection entries,
- policy-controlled entries.

---

## 5. Trace the `0x09ED` Accessibility List

Determine whether the accessibility process table is:

- an allowlist,
- compatibility list,
- exception list,
- monitoring list,
- or blocklist.

---

## 6. Trace Wine Detection

Known live values:

```text
winex11.drv
winepulse.drv
Wine HID
Wine Adapter
Wine USB
```

Priority callsites:

```text
0x1402b52c9
0x1402b52e3
```

Goal:

Identify the inspected object and resulting detection flag.

---

## 7. Trace Cameyo Detection

Known runtime list:

```text
CAMEYO_VIRTUALAPP
CAMEYO_RO_VIRTUALAPP
CAMEYO_RO_PROPERTY_VIRTUALAPP
```

Known live caller:

```text
0x1402b5131
```

Goal:

Determine whether the code checks:

- environment variables,
- registry values,
- loaded modules,
- process state,
- or another virtualization artifact.

---

## 8. Finish Sysinternals/Desktop Mapping

Known runtime lookup cluster:

```text
Sysinternals
Default
Winlogon
```

Known callsites:

```text
0x1402227c0
0x1402227da
0x1402227f4
```

Goal:

Confirm the exact Windows desktop/window-station detection mechanism and relationship to:

```text
Hacked Sysinternals Desktops in use
```

---

## 9. Map Service Detection

The executable contains extensive Windows service-management capability.

Goal:

Recover any service-name lists associated with:

- VM tools,
- remote software,
- monitoring tools,
- virtualization products,
- tamper indicators.

---

## 10. Reverse User/Kernel Communication

Priority APIs:

```text
FltCreateCommunicationPort
FltSendMessage
CreateFile
DeviceIoControl
```

Goal:

Document:

- communication channel,
- commands,
- message types,
- event IDs,
- driver → user messages,
- user → driver commands,
- role of encryption/hashing.

---

# Current Conclusion

Respondus LockDown Browser `2.1.5.01` implements a broad and layered environment-classification system rather than a single VM-detection check.

The research now confirms multiple independent detection surfaces.

## Confirmed VM / Environment Surfaces

```text
System identity
BIOS registry
Video BIOS identity
System manufacturer
CPU identity
Device descriptions
Device friendly names
COM FriendlyName values
Wine driver/module indicators
Cameyo virtualization indicators
Windows desktop/session state
```

## Confirmed VM / Virtualization Families

```text
Parallels
VMware
VirtualBox
QEMU
Xen
Microsoft virtual hardware
VirtIO / Red Hat
AWS virtual hardware
Wine
Cameyo
older VM Additions-style devices
```

The strongest new finding is the recovery of the full **26-entry runtime VM/device prefix list** and the accompanying **BIOS/registry detection configuration structure**.

This moves the analysis beyond inference from imported APIs or isolated strings.

For `FUN_1402b30d0`, we now know:

```text
what Windows properties are inspected,
what registry values are queried,
what strings are compared,
what comparison semantics are used,
what device prefixes are searched,
how device strings are inventoried,
and which persistent detection fields receive the result.
```

The primary unresolved question has shifted.

It is no longer:

> Does Respondus detect virtualized environments?

That is conclusively established.

The main remaining question is:

> How do the individual environment-detection accumulators flow into the final `rldbvm`, `rldbdetect`, telemetry, policy, and enforcement decisions?

---

# Research Status Summary

```text
[CONFIRMED] Runtime string table architecture
[CONFIRMED] Table 0x3B lookup mechanism
[CONFIRMED] Case-insensitive prefix helper
[CONFIRMED] Case-insensitive substring helper

[CONFIRMED] Device enumeration
[CONFIRMED] SPDRP_DEVICEDESC inspection
[CONFIRMED] SPDRP_FRIENDLYNAME inspection

[CONFIRMED] Full 26-entry VM/device prefix array
[CONFIRMED] Device prefix count = 26
[CONFIRMED] Parallels device checks
[CONFIRMED] VMware device checks
[CONFIRMED] VirtualBox device checks
[CONFIRMED] QEMU device checks
[CONFIRMED] Xen device checks
[CONFIRMED] Microsoft virtual-device checks
[CONFIRMED] VirtIO checks
[CONFIRMED] AWS virtual-device checks
[CONFIRMED] Wine virtual-device checks

[CONFIRMED] HARDWARE\DESCRIPTION\System inspection
[CONFIRMED] VideoBiosVersion inspection
[CONFIRMED] Parallels Video BIOS comparison
[CONFIRMED] Sun VirtualBox Video BIOS comparison

[CONFIRMED] HARDWARE\DESCRIPTION\System\BIOS inspection
[CONFIRMED] SystemManufacturer inspection
[CONFIRMED] VMware manufacturer comparison

[CONFIRMED] HARDWARE\DESCRIPTION\System\CentralProcessor\0 inspection
[CONFIRMED] ProcessorNameString inspection
[CONFIRMED] QEMU CPU comparison

[CONFIRMED] PRLS system-identity comparison
[CONFIRMED] VBOX system-identity comparison
[CONFIRMED] VMWare system-identity comparison
[CONFIRMED] VRTUAL system-identity comparison

[CONFIRMED] VBoxAsw active runtime lookup
[CONFIRMED] VBoxAsw special-case exclusion behavior

[CONFIRMED] FNV-1a 64-bit device hashing
[CONFIRMED] Device inventory de-duplication
[CONFIRMED] Detection result -> +0x46518
[CONFIRMED] Detection result -> +0x4651c

[CONFIRMED] FaceTime HD FriendlyName matching
[CONFIRMED] Parallels broader platform matching
[CONFIRMED] Apple M1 Pro special-case handling

[CONFIRMED] Cameyo virtualization string actively consumed
[CONFIRMED] winex11.drv actively consumed
[CONFIRMED] Wine driver strings present

[CONFIRMED] Process enumeration capability
[CONFIRMED] Module enumeration capability
[CONFIRMED] Service inspection capability
[CONFIRMED] Registry inspection
[CONFIRMED] Windows session/RDP inspection

[CONFIRMED] Recording/remote-control process table exists
[CONFIRMED] Accessibility process table exists
[CONFIRMED] Browser process table exists

[CONFIRMED] Sysinternals runtime handling
[CONFIRMED] Speech/voice preference inspection

[CONFIRMED] Kernel filesystem minifilter
[CONFIRMED] Kernel process callbacks
[CONFIRMED] Kernel thread callbacks
[CONFIRMED] Kernel image-load callbacks
[CONFIRMED] User/kernel communication capability

[OPEN] Downstream meaning of +0x46518
[OPEN] Downstream meaning of +0x4651c

[OPEN] Exact meaning of rldbvm=1
[OPEN] Exact meaning of rldbvm=2
[OPEN] Exact meaning of rldbvm=3

[OPEN] Exact 0x09D8 enforcement behavior
[OPEN] Exact 0x09D8 consumer

[OPEN] Exact purpose of 0x09ED accessibility table

[OPEN] Complete Wine detection path
[OPEN] Complete Cameyo detection path
[OPEN] Complete Sysinternals desktop-detection path

[OPEN] Full service detection table
[OPEN] CPUID hypervisor-bit behavior
[OPEN] Additional SMBIOS parsing behavior

[OPEN] Exact kernel communication protocol
[OPEN] Exact cryptographic message format
```

---

# Credits

Special thanks to [arcticdev00](https://github.com/arcticdev00) and the [Respondus-LDB-Offsets](https://github.com/arcticdev00/Respondus-LDB-Offsets) project.

That work on the previous version of Respondus LockDown Browser provided an important foundation and starting point for this research.

This analysis extends that earlier work to version:

```text
2.1.5.01
```

with additional:

- static analysis
- dynamic instrumentation
- runtime string-table recovery
- VM/device prefix recovery
- BIOS/registry detection reconstruction
- process/application list recovery
- environment-detection tracing
- Windows session research
- kernel-driver analysis

---

# Disclaimer

This repository is intended as technical documentation of observed software behavior derived from reverse-engineering research.

It records:

- static-analysis findings
- dynamic-analysis findings
- runtime observations
- imported API capabilities
- recovered strings
- internal structures
- detection-state observations
- confirmed findings
- unresolved research questions

Where the exact purpose of a recovered value has not been established, the repository explicitly labels that conclusion as unconfirmed rather than presenting speculation as fact.

This repository does not provide a working examination-security bypass.
