# respondus-lockdown-browser-research-2.1.5.01
Reverse engineering notes and technical findings for Respondus LockDown Browser 2.1.5.01, including VM detection, process monitoring, runtime string tables, device/BIOS checks, and kernel driver behavior.

# Respondus LockDown Browser 2.1.5.01 — Reverse Engineering Research

Reverse engineering notes and technical findings for Respondus LockDown Browser 2.1.5.01, including VM detection, process monitoring, runtime string tables, device/BIOS checks, and kernel driver behavior.

> Research scope: static and dynamic analysis of Respondus LockDown Browser behavior and architecture.
>
> This repository documents findings and detection mechanisms. It does not contain a working bypass implementation.

---

## Target

- **Product:** Respondus LockDown Browser
- **Version:** 2.1.5.01
- **Installer:** `LockDownBrowser-2-1-5-01-158741422.msi`
- **Main executable:** `LockDownBrowser.exe`
- **DLL:** `LockDownBrowser.dll`
- **Kernel driver:** `LockDownService215.sys`

---

# Executive Summary

Respondus LockDown Browser does not appear to rely on one single virtual-machine check.

The application contains multiple independent environment-monitoring and enforcement systems, including:

- Device enumeration
- Device description inspection
- Device friendly-name inspection
- BIOS inspection
- Baseboard inspection
- System product inspection
- CPU identification
- Process enumeration
- Module enumeration
- Service enumeration
- Registry inspection
- Windows session/RDP inspection
- Recording/capture application detection
- Remote-control software detection
- Browser blocking
- Sysinternals-related detection
- Accessibility-software handling
- Wine-related indicators
- VirtualBox-related indicators
- Parallels detection
- Cameyo virtualization indicators
- Kernel filesystem monitoring
- Process/thread/image callbacks
- User-mode ↔ kernel communication
- Policy-controlled detection categories

A runtime string-table dump also exposed a large amount of Respondus' internal configuration and detection vocabulary in plaintext.

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

```text
VM State Encoding

Function:

FUN_1401ea670

Respondus exposes an internal VM state through the field:

rldbvm

Observed values:

rldbvm = "0"
rldbvm = "1"
rldbvm = "2"
rldbvm = "3"

Observed mapping:

DAT_140ccc948 + 0x4664a != 0  -> rldbvm = "1"
DAT_140ccc948 + 0x4664b != 0  -> rldbvm = "2"
DAT_140ccc948 + 0x46538 != 0  -> rldbvm = "3"

Otherwise:
rldbvm = "0"

Another flag:

DAT_140ccc948 + 0x46651

causes:

rldbvm     = "0"
rldbdetect = "0"

The exact semantic meaning of VM categories 1, 2, and 3 is still under investigation.

Detection Result Encoding

Function:

FUN_140262110

This function appears to serialize already-computed detection flags rather than perform the original checks itself.

Observed mappings:

object + 0x2d4  -> detection 1
object + 0x479  -> detection 2
object + 0x300  -> detection 3
object + 0x2d5  -> detection 4
object + 0x2d6  -> detection 5
object + 0x2d7  -> detection 6
object + 0x3fc  -> detection 9
global + 0x448  -> detection 10
object + 0x388  -> detection 13
object + 0x2d9  -> detection 16
object + 0x278  -> detection 17
object + 0x279  -> detection 18

The exact semantic meaning of each numeric detection code has not yet been fully mapped.

String Comparison Helpers
Case-Insensitive Prefix Match

Function:

FUN_140296900

This ultimately calls:

FUN_140a90090

Behavior is approximately:

_strnicmp(value, prefix, strlen(prefix))

Equivalent meaning:

Does value begin with pattern, ignoring ASCII case?
Case-Insensitive Substring Match

Function:

FUN_140297050

This scans through the source string one byte at a time and performs a case-insensitive bounded comparison.

Equivalent logic:

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
Device Enumeration

Function:

FUN_1402b30d0

Observed SetupAPI usage includes:

SetupDiGetClassDevsW
SetupDiEnumDeviceInfo
SetupDiEnumDeviceInterfaces
SetupDiGetDeviceInstanceIdA
SetupDiGetDeviceInterfaceDetailA
SetupDiGetDeviceRegistryPropertyA
SetupDiGetDeviceRegistryPropertyW

Respondus retrieves at least:

SPDRP_DEVICEDESC
SPDRP_FRIENDLYNAME

These values are subsequently checked against internal patterns.

A literal comparison with:

Bluetooth Enumerator

was also identified.

The function computes a 64-bit FNV-1a hash of device descriptions:

Offset basis: 0xCBF29CE484222325
Prime:        0x100000001B3

This hash-table path appears to be used for de-duplication or inventory tracking rather than direct blocking.

Device Pattern Array

The device enumeration path uses a structure containing:

object + 0x233d0 = list pointer
object + 0x233d8 = count

The list entries are checked against retrieved device descriptions/friendly names using the case-insensitive prefix matcher.

This runtime array has not yet been fully recovered.

COM FriendlyName Enumeration

Function:

FUN_14023dda0

The function initializes COM, enumerates objects, retrieves:

FriendlyName

and converts the property to a plaintext string.

The FriendlyName is checked using:

FUN_140297050

which is a case-insensitive substring search.

One dynamic string ID:

0xAAA

was recovered at runtime as:

FaceTime HD

If a FriendlyName contains:

FaceTime HD

Respondus sets:

DAT_140ccc948 + 0x4653a = 1

That flag later contributes to the path that can produce:

rldbvm = "1"

A literal:

virtual

is also passed to the same substring matcher in this function.

In the analyzed build, the return value of that specific virtual comparison was not visibly consumed.

BIOS / Baseboard / System Product Inspection

Function:

FUN_1402141b0

This function contains clear hardware/platform inspection behavior.

Recovered runtime strings include:

HARDWARE\DESCRIPTION\System\BIOS
BaseBoardManufacturer
BaseBoardProduct
SystemProductName
Parallels
FaceTime HD

The string:

Parallels

is used with the case-insensitive substring matcher.

This confirms explicit Parallels-related platform detection.

The same function also explicitly checks:

Apple M1 Pro

using the prefix matcher.

This suggests the surrounding logic is broader platform classification rather than a single one-vendor VM check.

Runtime String Table

Function:

FUN_1401fc0e0

This function acts as a runtime string-table accessor.

For:

param_2 == 0x3B

the table base is located at:

param_1[6]

or:

context + 0x30

Each element occupies:

0x20 bytes

and behaves like an MSVC std::string.

String IDs map to indexes using:

ID = index * 0x15

Examples:

index 0x7D -> ID 0xA41
index 0x81 -> ID 0xA95
index 0x82 -> ID 0xAAA

A Frida-based runtime dump successfully recovered hundreds of plaintext strings.

Important Runtime Strings

Recovered values include:

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
Virtualization / Environment Indicators
VirtualBox

Recovered runtime string:

VBoxAsw

This is strongly suggestive of VirtualBox-related detection.

Exact consumer still needs tracing.

Parallels

Recovered runtime string:

Parallels

Confirmed to participate in hardware/system substring matching.

Wine

Recovered strings:

winex11.drv
winepulse.drv

These strongly indicate Wine-environment detection or classification.

Cameyo

Recovered values:

CAMEYO_VIRTUALAPP
CAMEYO_RO_VIRTUALAPP
CAMEYO_RO_PROPERTY_VIRTUALAPP

These are application-virtualization related.

Other VM-Related Values
***vmdetected***
VM Detected
vm_device
moosevm
VBoxAsw
Parallels
Hardware / Registry Indicators

Recovered values include:

HARDWARE\DESCRIPTION\System\CentralProcessor\0
ProcessorNameString
HARDWARE\DESCRIPTION\System\BIOS
BaseBoardManufacturer
BaseBoardProduct
SystemProductName
Large Recording / Remote-Control / Capture Process List

Runtime entry:

index: 0x78
ID:    0x09D8

Recovered process list:

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

This list is strongly associated with:

Remote-control software
Remote desktop
Screen recording
Screen capture
Streaming
Support tools
Video capture

A nearby log string says:

Detected recording or capture file = %s

The exact consumer of ID 0x09D8 should still be traced before calling every entry an unconditional hard block.

Accessibility / Assistive Technology List

Runtime entry:

index: 0x79
ID:    0x09ED

Recovered list:

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

This list contains assistive/accessibility software including:

Dragon
NVDA
JAWS
ZoomText

This list should not yet be labeled a blacklist.

It may be:

an accessibility exception list
a compatibility list
a special-handling list
an allowlist
a detection list

The consumer still needs to be traced.

Browser Blocking List

Recovered value:

chrome.exe
firefox.exe
msedge.exe
brave.exe
safari.exe
opera.exe
vivaldi.exe
wavebrowser.exe
ghost.exe

Nearby policy name:

BlockBrowsers

This strongly suggests browser-process blocking.

Standalone Process / Application Indicators

Recovered individual process/application names include:

mstsc.exe
lsynchost.exe
unlocker.exe
teas helpers.exe
svchost.exe
tmagentsvc.exe
AlertusDesktopAlert.exe

Associated strings include:

BlockTeramind
Hacking program detected - %s
Hacking program detected - (Discord2025) =
Blocklisted process hacked to prevent detection %s = %s
Unclosed app %s
Second Process List:
Remote Desktop / Session Checks

Recovered values:

SYSTEM\CurrentControlSet\Control\Terminal Server\
GlassSessionId
mstsc.exe

Relevant imports include:

WTSRegisterSessionNotification
WTSUnRegisterSessionNotification
WTSGetActiveConsoleSessionId
ProcessIdToSessionId

This confirms Windows-session and likely RDP-related handling.

Sysinternals Detection

Recovered values:

Sysinternals
Hacked Sysinternals Desktops in use

This indicates explicit detection or special handling of Sysinternals-related utilities/desktops.

Recording / Capture Controls

Recovered configuration names include:

BlockRecording
AllowRecording
AllowCapture
BlockAll
BlockMirrors
BlockSplitters

Recovered filesystem-related values:

%USERPROFILE%\Videos\Captures
Screenshots

Recovered log string:

Detected recording or capture file = %s

This supports both:

process-based detection
output-artifact/file monitoring
Windows Game Bar / Capture Handling

Recovered values include:

AllowGameBar
%USERPROFILE%\Videos\Captures
Screenshots
AllowCapture

This indicates explicit Windows capture/Game Bar handling.

Speech / Voice Activation Checks

Recovered registry path:

SOFTWARE\Microsoft\Speech_OneCore\Preferences

Recovered values:

VoiceActivationOn
VoiceActivationEnableAboveLockscreen

Respondus appears to inspect Windows voice-activation state.

Process Enumeration Capability

Relevant imports include:

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

This confirms extensive user-mode process/module inspection capability.

Service Enumeration Capability

Relevant imports include:

EnumServicesStatusExA
OpenSCManagerA
OpenSCManagerW
OpenServiceW
QueryServiceConfigW
QueryServiceStatusEx
StartServiceW

This confirms Windows service enumeration and inspection capability.

The full service-related detection list has not yet been recovered.

Registry Inspection

Relevant imports include:

RegOpenKeyA
RegOpenKeyExA
RegQueryValueExA
RegCreateKey*
RegSetValue*
RegDelete*

Recovered registry targets include:

HARDWARE\DESCRIPTION\System\BIOS
HARDWARE\DESCRIPTION\System\CentralProcessor\0
SYSTEM\CurrentControlSet\Control\Terminal Server\
SYSTEM\CurrentControlSet\services\MainLSyncHost
SOFTWARE\Microsoft\Speech_OneCore\Preferences
Debugger / Timing Capabilities

Relevant imports include:

IsDebuggerPresent
QueryPerformanceCounter
QueryPerformanceFrequency
GetTickCount
GetTickCount64

These establish debugger/timing inspection capability.

Their exact role in VM detection still needs tracing.

Kernel Driver

Driver:

LockDownService215.sys

Version:

2.15.0.1

SHA256:

323FAE10C53E74C2418C8D1BD45E54DE63241135BEB81196FDA0F6A16C3D5996

Service name:

LockDownService215

Driver configuration:

FILE_SYSTEM_DRIVER
SYSTEM_START
FSFilter Bottom

Observed filter altitude:

47777

Dependency:

FltMgr

The driver was observed running as a Windows filesystem minifilter.

Driver FLTMGR Capabilities

Imports include:

FltRegisterFilter
FltStartFiltering
FltCreateCommunicationPort
FltSendMessage

This confirms:

Filesystem minifilter registration
Filesystem filtering
User/kernel communication
Message passing
Driver Process / Thread / Image Monitoring

Kernel imports include:

PsSetCreateProcessNotifyRoutineEx
PsSetCreateThreadNotifyRoutine
PsSetLoadImageNotifyRoutine

This confirms kernel-mode capability to monitor:

Process creation
Thread creation
Image/module loading
Driver Cryptographic Capabilities

CNG imports indicate functionality related to:

Hashing
Symmetric keys
Encryption
Decryption
Key-pair operations
Key import/export
Random generation

The following are not yet confirmed:

Exact AES mode
Exact AES key size
Exact RSA key size
Exact message format
User-Mode / Kernel Communication

User-mode imports include:

CreateFileA
CreateFileW
DeviceIoControl

The driver exposes minifilter communication facilities.

This strongly suggests a dedicated user/kernel communication protocol.

The exact protocol has not yet been mapped.

Tamper / Integrity Strings

Recovered strings include:

PROGRAM HACKED OR INFECTED
AUTOLAUNCH SHIM DETECTED
KEYBOARD HOOK REMOVED
ADMIN RIGHTS REMOVED
Blocklisted process hacked to prevent detection %s = %s
Early Exit - Sending to AWS
FRGND CHECK TMPR

These indicate a separate integrity/tamper-monitoring subsystem.

Policy / Configuration Names

Recovered values include:

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

This strongly suggests much of Respondus' behavior is policy-driven.

Respondus Infrastructure

Recovered hostnames include:

campusportal.respondus.com
server-profiles-respondus-com.s3-external-1.amazonaws.com
smc-service-cloud.respondus2.com
help-center-respondus-com.s3.amazonaws.com
notification-images-respondus-com.s3.amazonaws.com
autolaunch.respondus2.com
downloads.respondus.com

Recovered paths include:

/services/ldb/offline-allow.htm
/overrides/cldb8675309.htm
/MONServer/ldb/sdk_expired.do
Runtime Process Behavior

The Frida watcher observed multiple LockDownBrowser.exe instances during startup.

Observed PIDs included:

15428
4240
9176
3576
8232
8272
3172

Several were attachable concurrently.

This confirms Respondus launches or maintains multiple processes during startup/runtime.

Confirmed vs Unconfirmed Findings
Finding	Status
Device enumeration	Confirmed
DEVICEDESC inspection	Confirmed
FRIENDLYNAME inspection	Confirmed
Prefix matching against environment strings	Confirmed
Case-insensitive substring matching	Confirmed
BIOS registry inspection	Confirmed
BaseBoardManufacturer inspection	Confirmed
BaseBoardProduct inspection	Confirmed
SystemProductName inspection	Confirmed
Parallels string matching	Confirmed
FaceTime HD FriendlyName matching	Confirmed
VBoxAsw present in runtime configuration	Confirmed
Wine driver names present	Confirmed
vm_device present	Confirmed
CPU registry path present	Confirmed
Process enumeration	Confirmed
Module enumeration	Confirmed
Service inspection capability	Confirmed
RDP/session inspection	Confirmed
Sysinternals-related detection	Confirmed
Recording/remote-control process list	Confirmed
Browser list	Confirmed
Kernel minifilter	Confirmed
Kernel process/thread/image callbacks	Confirmed
Every 0x09D8 application always hard-blocked	Not yet confirmed
Accessibility list is a blacklist	Not confirmed
CPUID hypervisor-bit check	Not yet confirmed
Exact SMBIOS parsing logic	Not yet fully confirmed
Exact meaning of rldbvm values 1/2/3	Not yet confirmed
Exact driver communication protocol	Not yet confirmed
Highest-Value Recovered Indicators
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
Current Reverse Engineering Map
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
Next Research Targets
1. Trace the 0x09D8 Process List

Find consumers of:

FUN_1401fc0e0(..., 0x3B, 0x09D8)

Goal:

Determine whether entries are:

Exact process blocks
Substring matches
Recording-only detections
Remote-access detections
Terminate-on-detection entries
Policy-controlled entries
2. Trace the 0x09ED Accessibility List

Determine whether the assistive-technology list is:

Allowed
Blocked
Whitelisted
Special-cased
Compatibility-handled
3. Trace VM-Specific Strings

Priority values:

VBoxAsw
vm_device
winex11.drv
winepulse.drv
Parallels
moosevm
4. Finish rldbvm State Mapping

Continue tracing writers to:

+0x4664a
+0x4664b
+0x46538

Goal:

Determine exact meaning of:

rldbvm = 1
rldbvm = 2
rldbvm = 3
5. Recover the Device Pattern Array

The device enumeration routine uses:

object + 0x233d0 = list pointer
object + 0x233d8 = count

The list is compared against device descriptions and friendly names.

Recovering this runtime array should expose additional device-specific indicators.

6. Map Process / Service / Module Consumers

Correlate runtime strings with:

Process enumeration
Service enumeration
Module enumeration
Registry inspection
Device inspection
7. Reverse Driver Communication

Map:

FltCreateCommunicationPort
FltSendMessage
CreateFile
DeviceIoControl

Goal:

Document the exact user/kernel protocol.

Current Conclusion

Respondus LockDown Browser 2.1.5.01 implements a broad environmental enforcement system rather than one isolated VM check.

Confirmed findings include:

Hardware identity inspection
BIOS inspection
Baseboard inspection
CPU inspection
Device enumeration
Friendly-name inspection
Process enumeration
Service enumeration
Module enumeration
Registry inspection
Session/RDP inspection
Remote-control application detection
Recording/capture software detection
Browser blocking
Sysinternals-related detection
Parallels detection
VirtualBox-related indicators
Wine-related indicators
Cameyo virtualization indicators
Kernel filesystem monitoring
Kernel process/thread/image callbacks
Runtime policy/configuration tables
VM state reporting through rldbvm

The most significant discovery so far is the runtime plaintext string table, which exposes Respondus' internal detection vocabulary, platform indicators, configuration values, and extensive software lists.

The biggest unresolved question is no longer whether Respondus performs broad environment detection.

It clearly does.

The remaining work is to map each recovered value to its exact consumer and enforcement decision.
