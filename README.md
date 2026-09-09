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
> Findings marked as **confirmed** were directly supported by the analyzed binary, imports, runtime behavior, or recovered runtime data. Items marked **unconfirmed** still require additional tracing before their exact purpose can be stated.

---

## Table of Contents

* [Target](#target)
* [Executive Summary](#executive-summary)
* [High-Level Architecture](#high-level-architecture)
* [VM State Encoding](#vm-state-encoding)
* [Detection Result Encoding](#detection-result-encoding)
* [String Comparison Helpers](#string-comparison-helpers)
* [Device Enumeration](#device-enumeration)
* [Device Pattern Array](#device-pattern-array)
* [COM FriendlyName Enumeration](#com-friendlyname-enumeration)
* [BIOS / Baseboard / System Product Inspection](#bios--baseboard--system-product-inspection)
* [Runtime String Table](#runtime-string-table)
* [Important Runtime Strings](#important-runtime-strings)
* [Virtualization / Environment Indicators](#virtualization--environment-indicators)
* [Hardware / Registry Indicators](#hardware--registry-indicators)
* [Recording / Remote-Control / Capture Process List](#recording--remote-control--capture-process-list)
* [Accessibility / Assistive Technology List](#accessibility--assistive-technology-list)
* [Browser Blocking List](#browser-blocking-list)
* [Standalone Process / Application Indicators](#standalone-process--application-indicators)
* [Remote Desktop / Session Checks](#remote-desktop--session-checks)
* [Sysinternals Detection](#sysinternals-detection)
* [Recording / Capture Controls](#recording--capture-controls)
* [Windows Game Bar / Capture Handling](#windows-game-bar--capture-handling)
* [Speech / Voice Activation Checks](#speech--voice-activation-checks)
* [Process Enumeration Capability](#process-enumeration-capability)
* [Service Enumeration Capability](#service-enumeration-capability)
* [Registry Inspection](#registry-inspection)
* [Debugger / Timing Capabilities](#debugger--timing-capabilities)
* [Kernel Driver](#kernel-driver)
* [Driver FLTMGR Capabilities](#driver-fltmgr-capabilities)
* [Driver Process / Thread / Image Monitoring](#driver-process--thread--image-monitoring)
* [Driver Cryptographic Capabilities](#driver-cryptographic-capabilities)
* [User-Mode / Kernel Communication](#user-mode--kernel-communication)
* [Tamper / Integrity Strings](#tamper--integrity-strings)
* [Policy / Configuration Names](#policy--configuration-names)
* [Respondus Infrastructure](#respondus-infrastructure)
* [Runtime Process Behavior](#runtime-process-behavior)
* [Confirmed vs. Unconfirmed Findings](#confirmed-vs-unconfirmed-findings)
* [Highest-Value Recovered Indicators](#highest-value-recovered-indicators)
* [Current Reverse Engineering Map](#current-reverse-engineering-map)
* [Next Research Targets](#next-research-targets)
* [Current Conclusion](#current-conclusion)

---

# Target

| Property            | Value                                    |
| ------------------- | ---------------------------------------- |
| **Product**         | Respondus LockDown Browser               |
| **Version**         | `2.1.5.01`                               |
| **Installer**       | `LockDownBrowser-2-1-5-01-158741422.msi` |
| **Main executable** | `LockDownBrowser.exe`                    |
| **DLL**             | `LockDownBrowser.dll`                    |
| **Kernel driver**   | `LockDownService215.sys`                 |

---

# Executive Summary

Respondus LockDown Browser does not appear to rely on one isolated virtual-machine check.

The analyzed build contains multiple independent environment-monitoring, classification, policy, and enforcement systems.

Observed capabilities include:

* Device enumeration
* Device-description inspection
* Device friendly-name inspection
* BIOS inspection
* Baseboard inspection
* System-product inspection
* CPU identification
* Process enumeration
* Module enumeration
* Service enumeration
* Registry inspection
* Windows session/RDP inspection
* Recording/capture application detection
* Remote-control software detection
* Browser blocking
* Sysinternals-related detection
* Accessibility-software handling
* Wine-related indicators
* VirtualBox-related indicators
* Parallels detection
* Cameyo virtualization indicators
* Kernel filesystem monitoring
* Kernel process callbacks
* Kernel thread callbacks
* Kernel image-load callbacks
* User-mode ↔ kernel communication
* Policy-controlled detection categories

One of the most useful discoveries was a runtime string table containing a large amount of Respondus' internal configuration, detection vocabulary, platform indicators, application lists, and policy names in plaintext.

---

# High-Level Architecture

```text
                    LockDownBrowser.exe
                           |
        +------------------+------------------+
        |                  |                  |
     Processes          Hardware           Sessions
     Services           Devices            RDP
     Modules            BIOS               Desktop
        |               Registry              |
        +------------------+------------------+
                           |
                    Detection Flags
                           |
                 rldbdetect / rldbvm
                           |
                 Telemetry / Policy Logic
                           |
                LockDownService215.sys
```

The currently observed architecture suggests that several user-mode inspection mechanisms feed internal detection state, which can then influence policy/telemetry logic and interact with the kernel component.

---

# VM State Encoding

### Function

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

---

# Detection Result Encoding

### Function

```text
FUN_140262110
```

This function appears to serialize already-computed detection flags rather than perform the original checks itself.

Observed mappings:

| Internal field   | Detection value |
| ---------------- | --------------: |
| `object + 0x2d4` |             `1` |
| `object + 0x479` |             `2` |
| `object + 0x300` |             `3` |
| `object + 0x2d5` |             `4` |
| `object + 0x2d6` |             `5` |
| `object + 0x2d7` |             `6` |
| `object + 0x3fc` |             `9` |
| `global + 0x448` |            `10` |
| `object + 0x388` |            `13` |
| `object + 0x2d9` |            `16` |
| `object + 0x278` |            `17` |
| `object + 0x279` |            `18` |

The exact semantic meaning of each numeric detection code has not yet been fully mapped.

---

# String Comparison Helpers

## Case-Insensitive Prefix Match

### Function

```text
FUN_140296900
```

This ultimately calls:

```text
FUN_140a90090
```

Observed behavior is approximately equivalent to:

```c
_strnicmp(value, prefix, strlen(prefix))
```

Conceptually:

```text
Does value begin with pattern, ignoring ASCII case?
```

This helper is used during several environment/hardware comparison paths.

---

## Case-Insensitive Substring Match

### Function

```text
FUN_140297050
```

This function scans through the source string one byte at a time and performs a case-insensitive bounded comparison.

Equivalent logic:

```c
bool ContainsIgnoreCase(char *haystack, char *needle)
{
    size_t len = strlen(needle);

    for (char *p = haystack; *p; ++p)
    {
        if (_strnicmp(p, needle, len) == 0)
            return true;
    }

    return false;
}
```

This helper is important because several recovered platform and hardware strings are passed through this comparison path.

---

# Device Enumeration

### Function

```text
FUN_1402b30d0
```

Observed SetupAPI usage includes:

```text
SetupDiGetClassDevsW
SetupDiEnumDeviceInfo
SetupDiEnumDeviceInterfaces
SetupDiGetDeviceInstanceIdA
SetupDiGetDeviceInterfaceDetailA
SetupDiGetDeviceRegistryPropertyA
SetupDiGetDeviceRegistryPropertyW
```

Respondus retrieves at least:

```text
SPDRP_DEVICEDESC
SPDRP_FRIENDLYNAME
```

These values are subsequently checked against internal patterns.

A literal comparison with:

```text
Bluetooth Enumerator
```

was also identified.

The function computes a 64-bit FNV-1a hash of device descriptions:

```text
Offset basis: 0xCBF29CE484222325
Prime:        0x100000001B3
```

This hash-table path appears to be used for de-duplication or inventory tracking rather than direct blocking.

---

# Device Pattern Array

The device-enumeration path uses a structure containing:

```text
object + 0x233d0 = list pointer
object + 0x233d8 = count
```

Entries in this list are checked against retrieved device descriptions and friendly names using the case-insensitive prefix matcher.

This runtime array has not yet been fully recovered.

Recovering it is one of the highest-value remaining research targets because it may expose additional device-specific environment indicators.

---

# COM FriendlyName Enumeration

### Function

```text
FUN_14023dda0
```

The function initializes COM, enumerates objects, and retrieves:

```text
FriendlyName
```

The property is converted to a plaintext string.

The `FriendlyName` is checked using:

```text
FUN_140297050
```

which performs a case-insensitive substring search.

One dynamic string ID:

```text
0xAAA
```

was recovered at runtime as:

```text
FaceTime HD
```

If a `FriendlyName` contains:

```text
FaceTime HD
```

Respondus sets:

```text
DAT_140ccc948 + 0x4653a = 1
```

That flag later contributes to a path capable of producing:

```text
rldbvm = "1"
```

A literal:

```text
virtual
```

is also passed to the same substring matcher in this function.

In the analyzed build, the return value of that specific `virtual` comparison was not visibly consumed.

---

# BIOS / Baseboard / System Product Inspection

### Function

```text
FUN_1402141b0
```

This function contains clear hardware/platform inspection behavior.

Recovered runtime strings include:

```text
HARDWARE\DESCRIPTION\System\BIOS
BaseBoardManufacturer
BaseBoardProduct
SystemProductName
Parallels
FaceTime HD
```

The string:

```text
Parallels
```

is used with the case-insensitive substring matcher.

This confirms explicit Parallels-related platform detection.

The same function also explicitly checks:

```text
Apple M1 Pro
```

using the prefix matcher.

This suggests that the surrounding routine performs broader platform classification rather than simply implementing a single-vendor VM check.

---

# Runtime String Table

### Function

```text
FUN_1401fc0e0
```

This function acts as a runtime string-table accessor.

For:

```text
param_2 == 0x3B
```

the table base is located at:

```text
param_1[6]
```

or:

```text
context + 0x30
```

Each element occupies:

```text
0x20 bytes
```

and behaves like an MSVC `std::string`.

String IDs map to indexes using:

```text
ID = index * 0x15
```

Examples:

|  Index |      ID |
| -----: | ------: |
| `0x7D` | `0xA41` |
| `0x81` | `0xA95` |
| `0x82` | `0xAAA` |

A Frida-based runtime dump successfully recovered hundreds of plaintext strings from this table.

This became one of the most useful sources for mapping Respondus' internal detection vocabulary.

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
ldbhackapp
moosevm
DetectUnsigned
BlockSplitters
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
vm_device
Parallels
FaceTime HD
BlockTeramind
winex11.drv
winepulse.drv
AllowGameBar
CANARY
```

These values cover several apparent categories:

* Environment / VM detection
* Remote-control detection
* Recording / capture controls
* Tamper detection
* Policy configuration
* Hardware/platform classification
* Application/process monitoring
* Sysinternals handling
* Windows capture handling

A recovered string by itself does **not** prove how it is enforced. Exact consumers still need tracing where noted.

---

# Virtualization / Environment Indicators

## VirtualBox

Recovered runtime string:

```text
VBoxAsw
```

This is strongly suggestive of VirtualBox-related detection or classification.

The exact consumer still needs tracing.

---

## Parallels

Recovered runtime string:

```text
Parallels
```

Unlike several other indicators, this value was directly observed participating in hardware/system substring matching.

Explicit Parallels-related platform detection is therefore confirmed.

---

## Wine

Recovered strings:

```text
winex11.drv
winepulse.drv
```

These strongly indicate Wine-environment detection or classification.

The exact enforcement path associated with these strings still requires tracing.

---

## Cameyo

Recovered values:

```text
CAMEYO_VIRTUALAPP
CAMEYO_RO_VIRTUALAPP
CAMEYO_RO_PROPERTY_VIRTUALAPP
```

These values are associated with application virtualization.

---

## Other VM-Related Values

```text
***vmdetected***
VM Detected
vm_device
moosevm
VBoxAsw
Parallels
```

The presence of multiple VM/environment-related indicators supports the conclusion that Respondus uses multiple environment-classification paths instead of one single check.

---

# Hardware / Registry Indicators

Recovered values include:

```text
HARDWARE\DESCRIPTION\System\CentralProcessor\0
ProcessorNameString
HARDWARE\DESCRIPTION\System\BIOS
BaseBoardManufacturer
BaseBoardProduct
SystemProductName
```

These indicate inspection of CPU identity, BIOS information, motherboard/baseboard identity, and system-product information.

---

# Recording / Remote-Control / Capture Process List

Runtime entry:

```text
index: 0x78
ID:    0x09D8
```

Recovered process list:

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

This list is strongly associated with software categories including:

* Remote-control software
* Remote desktop
* Screen recording
* Screen capture
* Streaming
* Support tools
* Video capture

A nearby log string states:

```text
Detected recording or capture file = %s
```

> [!CAUTION]
> The exact consumer of runtime ID `0x09D8` should still be traced before labeling every entry in the list an unconditional hard block.
>
> The list itself is confirmed. The exact enforcement behavior for every individual entry is not.

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

The list contains software associated with assistive/accessibility technologies including:

* Dragon
* NVDA
* JAWS
* ZoomText

> [!WARNING]
> This list should **not** currently be labeled a blacklist.

Its purpose may instead be:

* Accessibility exceptions
* Compatibility handling
* Special handling
* An allowlist
* A detection list

The exact consumer still needs to be traced.

---

# Browser Blocking List

Recovered values:

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

A nearby policy name is:

```text
BlockBrowsers
```

This strongly suggests browser-process blocking.

---

# Standalone Process / Application Indicators

Recovered individual process/application names include:

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
```

Relevant imports include:

```text
WTSRegisterSessionNotification
WTSUnRegisterSessionNotification
WTSGetActiveConsoleSessionId
ProcessIdToSessionId
```

This confirms Windows-session inspection and strongly indicates RDP-related handling.

---

# Sysinternals Detection

Recovered values include:

```text
Sysinternals
Hacked Sysinternals Desktops in use
```

These strings indicate explicit detection or special handling of Sysinternals-related utilities or desktops.

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

Together, these values support the existence of both:

* Process-based recording/capture detection
* Output-artifact or filesystem monitoring

---

# Windows Game Bar / Capture Handling

Recovered values include:

```text
AllowGameBar
%USERPROFILE%\Videos\Captures
Screenshots
AllowCapture
```

This indicates explicit handling of Windows capture functionality and Game Bar-related behavior.

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

Respondus appears to inspect Windows voice-activation state.

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

These imports confirm extensive user-mode process and module inspection capability.

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

These imports confirm Windows service enumeration and inspection capability.

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

Recovered registry targets include:

```text
HARDWARE\DESCRIPTION\System\BIOS
HARDWARE\DESCRIPTION\System\CentralProcessor\0
SYSTEM\CurrentControlSet\Control\Terminal Server\
SYSTEM\CurrentControlSet\services\MainLSyncHost
SOFTWARE\Microsoft\Speech_OneCore\Preferences
```

These values show that registry inspection extends across hardware identity, CPU information, session configuration, services, and Windows speech preferences.

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

These imports establish debugger and timing-inspection capability.

Their exact role in VM detection or tamper detection still needs to be traced.

---

# Kernel Driver

### Driver Information

| Property              | Value                                                              |
| --------------------- | ------------------------------------------------------------------ |
| **Driver**            | `LockDownService215.sys`                                           |
| **Version**           | `2.15.0.1`                                                         |
| **SHA256**            | `323FAE10C53E74C2418C8D1BD45E54DE63241135BEB81196FDA0F6A16C3D5996` |
| **Service name**      | `LockDownService215`                                               |
| **Driver type**       | `FILE_SYSTEM_DRIVER`                                               |
| **Start type**        | `SYSTEM_START`                                                     |
| **Filter class**      | `FSFilter Bottom`                                                  |
| **Observed altitude** | `47777`                                                            |
| **Dependency**        | `FltMgr`                                                           |

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

* Filesystem minifilter registration
* Filesystem filtering
* User/kernel communication
* Message passing

---

# Driver Process / Thread / Image Monitoring

Kernel imports include:

```text
PsSetCreateProcessNotifyRoutineEx
PsSetCreateThreadNotifyRoutine
PsSetLoadImageNotifyRoutine
```

These confirm kernel-mode capability to monitor:

* Process creation
* Thread creation
* Image/module loading

This means the kernel component is not limited to filesystem filtering.

---

# Driver Cryptographic Capabilities

Observed CNG imports indicate functionality related to:

* Hashing
* Symmetric keys
* Encryption
* Decryption
* Key-pair operations
* Key import/export
* Random generation

The following details are **not yet confirmed**:

* Exact AES mode
* Exact AES key size
* Exact RSA key size
* Exact message format

---

# User-Mode / Kernel Communication

Relevant user-mode imports include:

```text
CreateFileA
CreateFileW
DeviceIoControl
```

The kernel driver also exposes minifilter communication facilities.

Together, this strongly suggests a dedicated user-mode ↔ kernel-mode communication protocol.

The exact protocol has not yet been mapped.

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

These strings indicate a separate integrity/tamper-monitoring subsystem in addition to ordinary application and environment detection.

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

The presence of these names strongly suggests that a significant portion of Respondus' behavior is policy-driven rather than universally hard-coded into one fixed response.

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

These values were recovered from the analyzed application/runtime data.

---

# Runtime Process Behavior

The Frida watcher observed multiple `LockDownBrowser.exe` instances during startup.

Observed PIDs included:

```text
15428
4240
9176
3576
8232
8272
3172
```

Several of these processes were attachable concurrently.

This confirms that Respondus launches or maintains multiple `LockDownBrowser.exe` processes during startup/runtime.

---

# Confirmed vs. Unconfirmed Findings

| Finding                                          | Status                     |
| ------------------------------------------------ | -------------------------- |
| Device enumeration                               | ✅ Confirmed                |
| `DEVICEDESC` inspection                          | ✅ Confirmed                |
| `FRIENDLYNAME` inspection                        | ✅ Confirmed                |
| Prefix matching against environment strings      | ✅ Confirmed                |
| Case-insensitive substring matching              | ✅ Confirmed                |
| BIOS registry inspection                         | ✅ Confirmed                |
| `BaseBoardManufacturer` inspection               | ✅ Confirmed                |
| `BaseBoardProduct` inspection                    | ✅ Confirmed                |
| `SystemProductName` inspection                   | ✅ Confirmed                |
| Parallels string matching                        | ✅ Confirmed                |
| `FaceTime HD` FriendlyName matching              | ✅ Confirmed                |
| `VBoxAsw` present in runtime configuration       | ✅ Confirmed                |
| Wine driver names present                        | ✅ Confirmed                |
| `vm_device` present                              | ✅ Confirmed                |
| CPU registry path present                        | ✅ Confirmed                |
| Process enumeration                              | ✅ Confirmed                |
| Module enumeration                               | ✅ Confirmed                |
| Service inspection capability                    | ✅ Confirmed                |
| RDP/session inspection                           | ✅ Confirmed                |
| Sysinternals-related detection                   | ✅ Confirmed                |
| Recording/remote-control process list            | ✅ Confirmed                |
| Browser list                                     | ✅ Confirmed                |
| Kernel minifilter                                | ✅ Confirmed                |
| Kernel process/thread/image callbacks            | ✅ Confirmed                |
| Every `0x09D8` application always hard-blocked   | ⚠️ Not yet confirmed       |
| Accessibility list is a blacklist                | ⚠️ Not confirmed           |
| CPUID hypervisor-bit check                       | ⚠️ Not yet confirmed       |
| Exact SMBIOS parsing logic                       | ⚠️ Not yet fully confirmed |
| Exact meaning of `rldbvm` values `1` / `2` / `3` | ⚠️ Not yet confirmed       |
| Exact driver communication protocol              | ⚠️ Not yet confirmed       |

---

# Highest-Value Recovered Indicators

The highest-value environment and platform indicators recovered so far include:

```text
VBoxAsw
Parallels
VM Detected
vm_device
HARDWARE\DESCRIPTION\System\CentralProcessor\0
ProcessorNameString
HARDWARE\DESCRIPTION\System\BIOS
BaseBoardManufacturer
BaseBoardProduct
SystemProductName
FaceTime HD
Sysinternals
mstsc.exe
winex11.drv
winepulse.drv
```

---

# Current Reverse Engineering Map

```text
Windows Device Enumeration
        |
        +--> Device Description
        |       |
        |       +--> Prefix matcher
        |
        +--> Friendly Name
                |
                +--> Prefix / substring matcher


COM Enumeration
        |
        +--> FriendlyName
                |
                +--> "FaceTime HD"


BIOS / System Inspection
        |
        +--> HARDWARE\DESCRIPTION\System\BIOS
        |
        +--> BaseBoardManufacturer
        |
        +--> BaseBoardProduct
        |
        +--> SystemProductName
                |
                +--> "Parallels"


Process Monitoring
        |
        +--> Recording software list
        |
        +--> Remote-control list
        |
        +--> Browser list
        |
        +--> Individual process indicators


Session Monitoring
        |
        +--> Terminal Server registry
        |
        +--> GlassSessionId
        |
        +--> mstsc.exe
        |
        +--> WTS APIs


Kernel Driver
        |
        +--> Filesystem minifilter
        |
        +--> Process callbacks
        |
        +--> Thread callbacks
        |
        +--> Image-load callbacks
        |
        +--> Communication port
```

---

# Next Research Targets

## 1. Trace the `0x09D8` Process List

Find consumers of:

```text
FUN_1401fc0e0(..., 0x3B, 0x09D8)
```

### Goal

Determine whether entries represent:

* Exact process blocks
* Substring matches
* Recording-only detections
* Remote-access detections
* Terminate-on-detection entries
* Policy-controlled entries

The presence of an application in this table should not be treated as proof of unconditional blocking until this consumer is mapped.

---

## 2. Trace the `0x09ED` Accessibility List

Determine whether the assistive-technology list is:

* Allowed
* Blocked
* Whitelisted
* Special-cased
* Compatibility-handled

This is especially important because the recovered entries include legitimate accessibility software.

---

## 3. Trace VM-Specific Strings

Priority values:

```text
VBoxAsw
vm_device
winex11.drv
winepulse.drv
Parallels
moosevm
```

### Goal

Map each value to:

```text
String-table entry
        |
        v
Consumer function
        |
        v
Comparison mechanism
        |
        v
Internal detection flag
        |
        v
rldbvm / rldbdetect / policy result
```

---

## 4. Finish `rldbvm` State Mapping

Continue tracing writers to:

```text
+0x4664a
+0x4664b
+0x46538
```

### Goal

Determine the exact meaning of:

```text
rldbvm = 1
rldbvm = 2
rldbvm = 3
```

At present, the state values themselves are confirmed, but their precise categories are not.

---

## 5. Recover the Device Pattern Array

The device-enumeration routine uses:

```text
object + 0x233d0 = list pointer
object + 0x233d8 = count
```

The list is compared against device descriptions and friendly names.

Recovering this runtime array should expose additional device-specific indicators.

---

## 6. Map Process / Service / Module Consumers

Correlate recovered runtime strings with:

* Process enumeration
* Service enumeration
* Module enumeration
* Registry inspection
* Device inspection

### Goal

Determine which string tables belong to which subsystem and how individual matches translate into detection or policy state.

---

## 7. Reverse Driver Communication

Map interactions involving:

```text
FltCreateCommunicationPort
FltSendMessage
CreateFile
DeviceIoControl
```

### Goal

Document the exact user-mode/kernel-mode communication protocol.

Relevant questions include:

* Which component initiates communication?
* What message types exist?
* Which events originate in the minifilter?
* Which detections are reported back to user mode?
* Which actions can user mode request from the driver?
* Whether message contents use the observed cryptographic functionality

The exact protocol is currently unknown.

---

# Current Conclusion

Respondus LockDown Browser `2.1.5.01` implements a broad environmental enforcement system rather than one isolated VM check.

Confirmed findings include:

* Hardware identity inspection
* BIOS inspection
* Baseboard inspection
* CPU inspection
* Device enumeration
* Friendly-name inspection
* Process enumeration
* Service enumeration
* Module enumeration
* Registry inspection
* Session/RDP inspection
* Remote-control application detection
* Recording/capture software detection
* Browser blocking
* Sysinternals-related detection
* Parallels detection
* VirtualBox-related indicators
* Wine-related indicators
* Cameyo virtualization indicators
* Kernel filesystem monitoring
* Kernel process callbacks
* Kernel thread callbacks
* Kernel image-load callbacks
* Runtime policy/configuration tables
* VM-state reporting through `rldbvm`

The most significant discovery so far is the runtime plaintext string table.

It exposes a substantial portion of Respondus' internal:

* Detection vocabulary
* Platform indicators
* Application/process lists
* Hardware indicators
* Configuration values
* Policy names
* Tamper messages
* VM-related strings

The biggest unresolved question is no longer whether Respondus performs broad environment detection.

**It clearly does.**

The remaining work is to map each recovered value to its exact consumer, internal flag, policy decision, and enforcement behavior.

---

## Research Status Summary

```text
[CONFIRMED] Device enumeration
[CONFIRMED] Device description inspection
[CONFIRMED] Friendly-name inspection
[CONFIRMED] BIOS/baseboard/system-product inspection
[CONFIRMED] Process enumeration
[CONFIRMED] Module enumeration
[CONFIRMED] Service inspection capability
[CONFIRMED] Registry inspection
[CONFIRMED] Windows session/RDP inspection
[CONFIRMED] Recording/remote-control process table
[CONFIRMED] Browser process table
[CONFIRMED] Parallels matching
[CONFIRMED] FaceTime HD matching
[CONFIRMED] VirtualBox-related runtime indicator
[CONFIRMED] Wine-related runtime indicators
[CONFIRMED] Kernel filesystem minifilter
[CONFIRMED] Kernel process callbacks
[CONFIRMED] Kernel thread callbacks
[CONFIRMED] Kernel image-load callbacks
[CONFIRMED] User/kernel communication capability

[OPEN] Exact meaning of rldbvm=1
[OPEN] Exact meaning of rldbvm=2
[OPEN] Exact meaning of rldbvm=3
[OPEN] Exact 0x09D8 enforcement behavior
[OPEN] Exact purpose of 0x09ED accessibility table
[OPEN] Exact VirtualBox indicator consumer
[OPEN] Exact Wine indicator consumers
[OPEN] Full device-pattern array
[OPEN] Full service detection table
[OPEN] Exact SMBIOS parsing logic
[OPEN] CPUID hypervisor-bit behavior
[OPEN] Exact kernel communication protocol
[OPEN] Exact cryptographic message format
```

---

## Disclaimer

This repository is intended as technical documentation of observed software behavior derived from reverse-engineering research.

It records:

* Static-analysis findings
* Dynamic-analysis findings
* Runtime observations
* Imported API capabilities
* Recovered strings
* Internal structures
* Detection-state observations
* Confirmed findings
* Unresolved research questions

Where the exact purpose of a recovered value has not been established, the repository explicitly labels that conclusion as unconfirmed rather than presenting speculation as fact.

## Credits

Special thanks to [arcticdev00](https://github.com/arcticdev00) and the [Respondus-LDB-Offsets](https://github.com/arcticdev00/Respondus-LDB-Offsets) project.

That work on the previous version of Respondus LockDown Browser provided an important foundation and starting point for this research. My analysis builds on that earlier work and extends it to version `2.1.5.01` with additional static analysis, runtime inspection, string-table recovery, process/device detection research, and kernel-driver analysis.
