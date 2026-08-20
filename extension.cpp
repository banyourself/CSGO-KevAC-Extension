#if defined __linux__ && !defined _GNU_SOURCE
	#define _GNU_SOURCE
#endif

#if SOURCE_ENGINE == SE_CSGO
	#include <netmessages.pb.h>
#endif

#include "extension.h"
#include "CDetour/detours.h"

#include <eiface.h>
#include <icvar.h>
#include <tier1/convar.h>

#include <algorithm>
#include <cctype>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#if defined __linux__ && defined __i386__
	#include <dlfcn.h>
	#include <link.h>
    #include <sys/mman.h>
    #include <unistd.h>
#endif

#if defined _WIN32
	#include <direct.h>
#else
	#include <sys/stat.h>
	#include <sys/types.h>
#endif

KevAC kevac;
SMEXT_LINK(&kevac);

CDetour* pDetour = nullptr;
IGameConfig* pGameConfig = nullptr;
IForward* forwardCheatDetected = nullptr;
IForward* forwardListenerUpdated = nullptr;
IForward* forwardListenerTelemetry = nullptr;
IForward* forwardListenerProbe = nullptr;
IGameEventManager2* gameevents = nullptr;
std::vector<std::string> events;


IVEngineServer* engineServer = nullptr;
ICvar* engineCvar = nullptr;

#if SOURCE_ENGINE == SE_CSGO
struct ListenerMaskState
{
	bool seen;
	std::vector<unsigned int> words;

	ListenerMaskState() : seen(false) {}
};

std::map<int, ListenerMaskState> listenerMasks;
std::map<int, ListenerMaskState> listenerVTableMasks;
std::map<int, uint32_t> listenerMaskFingerprints;
std::map<int, std::string> listenerBlacklistedEventNames;
std::map<int, IGameEventListener2*> listenerInterfaces;
std::vector<std::string> listenerAuditEvents;
int listenerProbeCalls = 0;
int listenerProbeHumanCalls = 0;
int listenerAcceptedPackets = 0;
int listenerVTablePackets = 0;
int listenerTelemetryPackets = 0;
bool listenerStaticDetourEnabled = false;

// CS:GO's final 32-bit Linux branch has a stable ProcessListenEvents prologue.
// SourceMod 1.12 uses SafetyHook for CDetour. If SafetyHook cannot attach to
// this exact function, retain a minimal five-byte x86 fallback for Route A.
// The gamedata signature is still the authority for the target address.
#if defined __linux__ && defined __i386__
class X86InlineRoute
{
public:
    bool Install(void* address, void* callback, void** original)
    {
        if (address == nullptr || callback == nullptr || original == nullptr || enabled)
            return false;

        constexpr size_t patchLength = 5;
        constexpr unsigned char expectedPrologue[patchLength] = {0x55, 0x89, 0xE5, 0x57, 0x56};
        if (std::memcmp(address, expectedPrologue, patchLength) != 0)
            return false;

        const long pageSize = sysconf(_SC_PAGESIZE);
        if (pageSize <= 0)
            return false;

        target = address;
        const uintptr_t targetAddress = reinterpret_cast<uintptr_t>(target);
        pageStart = targetAddress & ~static_cast<uintptr_t>(pageSize - 1);
        const uintptr_t pageEnd = (targetAddress + patchLength + pageSize - 1) & ~static_cast<uintptr_t>(pageSize - 1);
        pageLength = pageEnd - pageStart;

        trampoline = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (trampoline == MAP_FAILED)
        {
            trampoline = nullptr;
            return false;
        }

        std::memcpy(savedBytes, target, patchLength);
        std::memcpy(trampoline, savedBytes, patchLength);
        if (!WriteRelativeJump(static_cast<unsigned char*>(trampoline) + patchLength, static_cast<unsigned char*>(target) + patchLength))
        {
            munmap(trampoline, pageSize);
            trampoline = nullptr;
            return false;
        }

        if (mprotect(reinterpret_cast<void*>(pageStart), pageLength, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        {
            munmap(trampoline, pageSize);
            trampoline = nullptr;
            return false;
        }

        if (!WriteRelativeJump(target, callback))
        {
            mprotect(reinterpret_cast<void*>(pageStart), pageLength, PROT_READ | PROT_EXEC);
            munmap(trampoline, pageSize);
            trampoline = nullptr;
            return false;
        }

        __builtin___clear_cache(reinterpret_cast<char*>(target), reinterpret_cast<char*>(target) + patchLength);
        mprotect(reinterpret_cast<void*>(pageStart), pageLength, PROT_READ | PROT_EXEC);
        *original = trampoline;
        enabled = true;
        return true;
    }

    void Remove()
    {
        if (!enabled)
            return;

        constexpr size_t patchLength = 5;
        if (mprotect(reinterpret_cast<void*>(pageStart), pageLength, PROT_READ | PROT_WRITE | PROT_EXEC) == 0)
        {
            std::memcpy(target, savedBytes, patchLength);
            __builtin___clear_cache(reinterpret_cast<char*>(target), reinterpret_cast<char*>(target) + patchLength);
            mprotect(reinterpret_cast<void*>(pageStart), pageLength, PROT_READ | PROT_EXEC);
        }
        if (trampoline != nullptr)
            munmap(trampoline, sysconf(_SC_PAGESIZE));

        target = nullptr;
        trampoline = nullptr;
        pageStart = 0;
        pageLength = 0;
        enabled = false;
    }

private:
    bool WriteRelativeJump(void* from, const void* to)
    {
        const intptr_t relative = reinterpret_cast<intptr_t>(to) - (reinterpret_cast<intptr_t>(from) + 5);
        if (relative < INT32_MIN || relative > INT32_MAX)
            return false;

        unsigned char jump[5] = {0xE9, 0, 0, 0, 0};
        const int32_t displacement = static_cast<int32_t>(relative);
        std::memcpy(jump + 1, &displacement, sizeof(displacement));
        std::memcpy(from, jump, sizeof(jump));
        return true;
    }

    void* target = nullptr;
    void* trampoline = nullptr;
    unsigned char savedBytes[5]{};
    uintptr_t pageStart = 0;
    size_t pageLength = 0;
    bool enabled = false;
};

X86InlineRoute listenerFallbackRoute;

// Route A must patch the function that is already mapped into the srcds
// process. SourceMod's "engine" library alias does not resolve on every
// legacy CS:GO layout, even when the actual engine module is present. These
// alternatives never dlopen an on-disk engine file: a separately loaded copy
// would receive no client packets and is not a valid hook target.
static const unsigned char kProcessListenEventsSignature[] =
{
	0x55, 0x89, 0xE5, 0x57, 0x56, 0x53, 0x8D, 0x5D,
	0xA8, 0x83, 0xEC, 0x64, 0x8B, 0x35, 0x90, 0x5E
};

static const char* const kProcessListenEventsSymbols[] =
{
	"_ZN11CBaseClient19ProcessListenEventsEP16CLC_ListenEvents",
	"_ZN11CBaseClient19ProcessListenEventsEP20CCLCMsg_ListenEvents"
};

struct LoadedModuleScan
{
	void* address;
	int executableModules;
	char module[PLATFORM_MAX_PATH];
	std::vector<std::string> modules;
};

static int ScanLoadedModuleForListenEvents(struct dl_phdr_info* info, size_t, void* userData)
{
	LoadedModuleScan* scan = static_cast<LoadedModuleScan*>(userData);
	if (scan == nullptr || scan->address != nullptr)
		return 1;

	bool countedModule = false;
	for (int i = 0; i < info->dlpi_phnum; i++)
	{
		const ElfW(Phdr)& header = info->dlpi_phdr[i];
		if (header.p_type != PT_LOAD || (header.p_flags & PF_X) == 0 || header.p_memsz < sizeof(kProcessListenEventsSignature))
			continue;

		if (!countedModule)
		{
			scan->executableModules++;
			countedModule = true;
			const char* moduleName = (info->dlpi_name != nullptr && info->dlpi_name[0] != '\0') ? info->dlpi_name : "<srcds executable>";
			scan->modules.emplace_back(moduleName);
		}

		const unsigned char* begin = reinterpret_cast<const unsigned char*>(info->dlpi_addr + header.p_vaddr);
		const size_t length = static_cast<size_t>(header.p_memsz);
		for (size_t offset = 0; offset + sizeof(kProcessListenEventsSignature) <= length; offset++)
		{
			if (std::memcmp(begin + offset, kProcessListenEventsSignature, sizeof(kProcessListenEventsSignature)) != 0)
				continue;

			scan->address = const_cast<unsigned char*>(begin + offset);
			const char* moduleName = (info->dlpi_name != nullptr && info->dlpi_name[0] != '\0') ? info->dlpi_name : "<srcds executable>";
			std::strncpy(scan->module, moduleName, sizeof(scan->module) - 1);
			scan->module[sizeof(scan->module) - 1] = '\0';
			return 1;
		}
	}

	return 0;
}

static void* FindListenEventsInLoadedModules(char* module, size_t moduleLength, int& executableModules, std::vector<std::string>& modules)
{
	LoadedModuleScan scan{};
	dl_iterate_phdr(ScanLoadedModuleForListenEvents, &scan);
	executableModules = scan.executableModules;
	modules.swap(scan.modules);
	if (module != nullptr && moduleLength > 0)
	{
		std::strncpy(module, scan.module, moduleLength - 1);
		module[moduleLength - 1] = '\0';
	}
	return scan.address;
}

static void WriteRouteAModuleDiagnostic(const std::vector<std::string>& modules)
{
	char path[PLATFORM_MAX_PATH];
	smutils->BuildPath(Path_SM, path, sizeof(path), "logs/KevAC-routea-modules.log");
	std::ofstream output(path, std::ios::out | std::ios::trunc);
	if (!output.is_open())
		return;

	output << "KevAC Route A executable-module scan\n";
	output << "The current verified 2023 ProcessListenEvents signature did not match any entry below.\n";
	output << "Provide this file and the listed legacy CS:GO module(s) for build-specific signature analysis.\n\n";
	for (const std::string& module : modules)
		output << module << '\n';
}

// Build-independent Route A: resolve CBaseClient::ProcessListenEvents by the
// engine's own diagnostic string instead of a byte signature. The string has
// been present in every CS:GO branch for years; the raw signature pins
// build-specific frame sizes and an absolute global operand, so it breaks on any
// engine.so that differs from the one it was captured against. This does not.
static const char kProcessListenEventsDiagString[] = "ProcessListenEvents: game event %i not found.";

struct StringAnchorScan
{
	void* address;
	unsigned char prologue[32];
	bool prologueValid;
	bool stringFound;
	char module[PLATFORM_MAX_PATH];

	StringAnchorScan() : address(nullptr), prologueValid(false), stringFound(false)
	{
		std::memset(prologue, 0, sizeof(prologue));
		module[0] = '\0';
	}
};

static const unsigned char* FindBytesInRange(const unsigned char* begin, size_t length, const unsigned char* needle, size_t needleLength)
{
	if (begin == nullptr || length < needleLength || needleLength == 0)
		return nullptr;
	for (size_t offset = 0; offset + needleLength <= length; offset++)
	{
		if (begin[offset] == needle[0] && std::memcmp(begin + offset, needle, needleLength) == 0)
			return begin + offset;
	}
	return nullptr;
}

// Walk backwards from a reference site to the enclosing function prologue. GCC on
// this 32-bit CS:GO branch begins the function with push ebp / mov ebp,esp /
// push edi / push esi / push ebx and aligns functions after a ret or padding
// boundary. Preferring a boundary-qualified match avoids treating an in-body byte
// coincidence as the entry.
static void* WalkBackToPrologue(const unsigned char* segBegin, const unsigned char* ref)
{
	static const unsigned char kWide[] = {0x55, 0x89, 0xE5, 0x57, 0x56, 0x53};
	static const unsigned char kNarrow[] = {0x55, 0x89, 0xE5};
	if (segBegin == nullptr || ref == nullptr || ref < segBegin)
		return nullptr;
	const size_t maxScan = 8192;
	const unsigned char* lowest = segBegin;
	if (static_cast<size_t>(ref - segBegin) > maxScan)
		lowest = ref - maxScan;

	for (int pass = 0; pass < 2; pass++)
	{
		const unsigned char* pattern = (pass == 0) ? kWide : kNarrow;
		const size_t patternLength = (pass == 0) ? sizeof(kWide) : sizeof(kNarrow);
		if (ref < segBegin + patternLength)
			continue;
		for (const unsigned char* p = ref - patternLength; ; p--)
		{
			if (std::memcmp(p, pattern, patternLength) == 0)
			{
				const unsigned char prev = (p > segBegin) ? *(p - 1) : 0x00;
				if (prev == 0xC3 || prev == 0x90 || prev == 0xCC || prev == 0x00)
					return const_cast<unsigned char*>(p);
			}
			if (p == lowest)
				break;
		}
	}

	// No boundary-qualified prologue: accept the nearest wide prologue anyway.
	if (ref >= segBegin + sizeof(kWide))
	{
		for (const unsigned char* p = ref - sizeof(kWide); ; p--)
		{
			if (std::memcmp(p, kWide, sizeof(kWide)) == 0)
				return const_cast<unsigned char*>(p);
			if (p == lowest)
				break;
		}
	}
	return nullptr;
}

static int ScanModuleForListenEventsByString(struct dl_phdr_info* info, size_t, void* userData)
{
	StringAnchorScan* scan = static_cast<StringAnchorScan*>(userData);
	if (scan == nullptr || scan->address != nullptr)
		return 1;

	// 1) Locate the diagnostic string in any readable load segment of this module.
	const unsigned char* stringAddr = nullptr;
	for (int i = 0; i < info->dlpi_phnum && stringAddr == nullptr; i++)
	{
		const ElfW(Phdr)& header = info->dlpi_phdr[i];
		if (header.p_type != PT_LOAD || (header.p_flags & PF_R) == 0)
			continue;
		const unsigned char* begin = reinterpret_cast<const unsigned char*>(info->dlpi_addr + header.p_vaddr);
		stringAddr = FindBytesInRange(begin, static_cast<size_t>(header.p_memsz),
			reinterpret_cast<const unsigned char*>(kProcessListenEventsDiagString),
			sizeof(kProcessListenEventsDiagString) - 1);
	}
	if (stringAddr == nullptr)
		return 0;

	scan->stringFound = true;
	const char* moduleName = (info->dlpi_name != nullptr && info->dlpi_name[0] != '\0') ? info->dlpi_name : "<srcds executable>";
	std::strncpy(scan->module, moduleName, sizeof(scan->module) - 1);
	scan->module[sizeof(scan->module) - 1] = '\0';

	// 2) Find a push imm32 that references the string, then walk back to the
	//    prologue of the function that contains it.
	unsigned char pushBytes[5];
	pushBytes[0] = 0x68;
	const uint32_t stringVa = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(stringAddr));
	std::memcpy(pushBytes + 1, &stringVa, sizeof(stringVa));

	for (int i = 0; i < info->dlpi_phnum; i++)
	{
		const ElfW(Phdr)& header = info->dlpi_phdr[i];
		if (header.p_type != PT_LOAD || (header.p_flags & PF_X) == 0)
			continue;

		const unsigned char* segBegin = reinterpret_cast<const unsigned char*>(info->dlpi_addr + header.p_vaddr);
		const size_t segLength = static_cast<size_t>(header.p_memsz);
		const unsigned char* cursor = segBegin;
		size_t remaining = segLength;
		while (remaining >= sizeof(pushBytes))
		{
			const unsigned char* push = FindBytesInRange(cursor, remaining, pushBytes, sizeof(pushBytes));
			if (push == nullptr)
				break;

			void* prologue = WalkBackToPrologue(segBegin, push);
			if (prologue != nullptr)
			{
				scan->address = prologue;
				std::memcpy(scan->prologue, prologue, sizeof(scan->prologue));
				scan->prologueValid = true;
				return 1;
			}

			cursor = push + 1;
			remaining = segLength - static_cast<size_t>(cursor - segBegin);
		}
	}
	return 0;
}

static void* FindListenEventsByStringAnchor(StringAnchorScan& scan)
{
	dl_iterate_phdr(ScanModuleForListenEventsByString, &scan);
	return scan.address;
}

static void WriteRouteAStringAnchorDiagnostic(const StringAnchorScan& scan)
{
	char path[PLATFORM_MAX_PATH];
	smutils->BuildPath(Path_SM, path, sizeof(path), "logs/KevAC-routea-modules.log");
	std::ofstream output(path, std::ios::out | std::ios::app);
	if (!output.is_open())
		return;

	output << "\n--- string-anchor resolver ---\n";
	if (!scan.stringFound)
	{
		output << "The ProcessListenEvents diagnostic string was not found in any loaded module.\n";
		output << "This engine.so does not match a stock CS:GO build, or the engine is not loaded.\n";
		return;
	}

	output << "Diagnostic string found in module: " << scan.module << '\n';
	if (scan.prologueValid && scan.address != nullptr)
	{
		output << "Resolved ProcessListenEvents prologue bytes (send these back if the hook still misbehaves):\n";
		char hex[3 * sizeof(scan.prologue) + 1];
		int written = 0;
		for (size_t i = 0; i < sizeof(scan.prologue); i++)
			written += std::snprintf(hex + written, sizeof(hex) - written, "%02X ", scan.prologue[i]);
		output << hex << '\n';
	}
	else
	{
		output << "String located but no push-imm32 reference walked back to a prologue.\n";
		output << "The function layout differs from the expected CS:GO branch; capture-based analysis needed.\n";
	}
}
#endif

// CS:GO serializes ListenEvents as a protobuf message. The bit mask is split
// into fixed32 words, with bit 0 of word 0 representing event index 0.
static void CopyEventMask(const CCLCMsg_ListenEvents* msg, std::vector<unsigned int>& events)
{
	events.clear();
	if (msg == nullptr)
		return;

	const int maxWords = (MAX_EVENT_NUMBER + 31) / 32;
	const int words = std::min(msg->event_mask_size(), maxWords);
	for (int wordIndex = 0; wordIndex < words; wordIndex++)
	{
		const unsigned int word = msg->event_mask(wordIndex);
		for (int bit = 0; bit < 32; bit++)
		{
			const int eventIndex = wordIndex * 32 + bit;
			if (eventIndex >= MAX_EVENT_NUMBER)
				break;
			if ((word & (1u << bit)) != 0)
				events.push_back((unsigned int)eventIndex);
		}
	}
}

// A compact, stable identifier for an accepted subscription mask. This is
// telemetry only: different masks are useful for comparison but are never
// evidence of cheating by themselves.
static uint32_t FingerprintEventMask(const std::vector<unsigned int>& events)
{
	uint32_t hash = 2166136261u;
	for (unsigned int eventIndex : events)
	{
		hash ^= eventIndex;
		hash *= 16777619u;
	}
	hash ^= static_cast<uint32_t>(events.size());
	hash *= 16777619u;
	return hash == 0 ? 1u : hash;
}

static void DispatchListenerTelemetry(int client, int activeSubscriptions, int blacklistedSubscriptions)
{
	if (forwardListenerTelemetry == nullptr)
		return;

	forwardListenerTelemetry->PushCell(client);
	forwardListenerTelemetry->PushCell(activeSubscriptions);
	forwardListenerTelemetry->PushCell(blacklistedSubscriptions);
	forwardListenerTelemetry->Execute();
}

static void DispatchListenerProbe(int client)
{
	if (forwardListenerProbe == nullptr)
		return;

	forwardListenerProbe->PushCell(client);
	forwardListenerProbe->PushCell(listenerProbeCalls);
	forwardListenerProbe->PushCell(listenerProbeHumanCalls);
	forwardListenerProbe->Execute();
}

// CGameClient exposes IClient at base+4 and IClientMessageHandler at base+8
// on this 32-bit CS:GO branch. VoiceAnnounceEx uses the same relationship for
// its verified ProcessVoiceData hook. The first base is IGameEventListener2.
static IGameEventListener2* GetEventListenerFromMessageHandler(void* messageHandler)
{
	if (messageHandler == nullptr)
		return nullptr;

	return reinterpret_cast<IGameEventListener2*>(reinterpret_cast<char*>(messageHandler) - 8);
}

static void AppendListenerEventName(std::string& target, const std::string& eventName)
{
	if (!target.empty())
		target.append(", ");
	target.append(eventName);
}

static void TrimEventName(std::string& value);

static int CountBlacklistedListeners(IGameEventListener2* listener, std::string* matchedEvents = nullptr)
{
	if (gameevents == nullptr || listener == nullptr)
		return 0;

	int blacklisted = 0;
	for (const std::string& eventName : events)
	{
		if (gameevents->FindListener(listener, eventName.c_str()))
		{
			blacklisted++;
			if (matchedEvents != nullptr)
				AppendListenerEventName(*matchedEvents, eventName);
		}
	}
	return blacklisted;
}

static int CountBlacklistedListeners(void* messageHandler, std::string* matchedEvents = nullptr)
{
	return CountBlacklistedListeners(GetEventListenerFromMessageHandler(messageHandler), matchedEvents);
}

// The CLC packet contains an opaque event mask, so the engine does not expose a
// public index-to-name table for printing every subscription. This safe audit
// instead checks only administrator-supplied event names against the same live
// server listener table used by blacklist enforcement.
static int AuditListenerCandidates(int client, const char* candidates, std::string& matchedEvents)
{
	auto found = listenerInterfaces.find(client);
	if (gameevents == nullptr || found == listenerInterfaces.end() || found->second == nullptr)
		return -1;

	std::string list = candidates == nullptr ? "" : candidates;
	int matches = 0;
	size_t cursor = 0;
	while (cursor < list.size())
	{
		const size_t next = list.find_first_of(",;\r\n", cursor);
		std::string eventName = list.substr(cursor, next == std::string::npos ? std::string::npos : next - cursor);
		TrimEventName(eventName);

		const bool validName = !eventName.empty() && eventName.size() <= 64 &&
			std::all_of(eventName.begin(), eventName.end(), [](unsigned char ch)
			{
				return std::isalnum(ch) || ch == '_';
			});
		if (validName && gameevents->FindListener(found->second, eventName.c_str()))
		{
			matches++;
			AppendListenerEventName(matchedEvents, eventName);
		}

		if (next == std::string::npos)
			break;
		cursor = next + 1;
	}

	return matches;
}

static void TrimEventName(std::string& value)
{
	const std::string whitespace(" \t\r\n");
	const std::string::size_type first = value.find_first_not_of(whitespace);
	if (first == std::string::npos)
	{
		value.clear();
		return;
	}

	const std::string::size_type last = value.find_last_not_of(whitespace);
	value = value.substr(first, last - first + 1);
}

static bool IsValidGameEventName(const std::string& eventName)
{
	return !eventName.empty() && eventName.size() <= 64 &&
		std::all_of(eventName.begin(), eventName.end(), [](unsigned char ch)
		{
			return std::isalnum(ch) || ch == '_';
		});
}

// Extract an event label from the intentionally commented candidate lines in
// events_detection.txt without treating explanatory prose as an event name.
static bool ExtractAuditEventName(const std::string& source, std::string& eventName)
{
	std::string line(source);
	TrimEventName(line);
	if (line.empty() || line[0] == '#' || line[0] == ';')
		return false;

	bool commented = false;
	if (line.size() >= 2 && line[0] == '/' && line[1] == '/')
	{
		commented = true;
		line.erase(0, 2);
		TrimEventName(line);
	}
	if (line.empty())
		return false;

	const size_t separator = line.find_first_of(" \t");
	eventName = line.substr(0, separator);
	if (!IsValidGameEventName(eventName))
		return false;

	if (separator == std::string::npos)
		return true;

	std::string suffix = line.substr(separator);
	TrimEventName(suffix);
	// Retail-client exclusions carry a parenthesized explanation.
	return commented && !suffix.empty() && suffix[0] == '(';
}

static int GetAllAuditedListenerEvents(int client, std::string& matchedEvents)
{
	auto found = listenerInterfaces.find(client);
	if (gameevents == nullptr || found == listenerInterfaces.end() || found->second == nullptr)
		return -1;

	int matches = 0;
	for (const std::string& eventName : listenerAuditEvents)
	{
		if (gameevents->FindListener(found->second, eventName.c_str()))
		{
			matches++;
			AppendListenerEventName(matchedEvents, eventName);
		}
	}
	return matches;
}
#endif

#if SOURCE_ENGINE == SE_CSGO
DETOUR_DECL_MEMBER1(ListenEvents, bool, CCLCMsg_ListenEvents*, msg)
#else
DETOUR_DECL_MEMBER1(ListenEvents, bool, CLC_ListenEvents*, msg)
#endif
{
	#if SOURCE_ENGINE == SE_CSGO
	listenerProbeCalls++;
	#endif

	auto client = (reinterpret_cast<CBaseClient*>(this))->GetPlayerSlot() + 1;
	IGamePlayer* pClient = playerhelpers->GetGamePlayer(client);

	#if SOURCE_ENGINE == SE_CSGO
	if (pClient != nullptr && !pClient->IsFakeClient())
		listenerProbeHumanCalls++;
	DispatchListenerProbe((pClient != nullptr && !pClient->IsFakeClient()) ? client : 0);
	#endif

	if (pClient == nullptr || pClient->IsFakeClient())
		return DETOUR_MEMBER_CALL(ListenEvents)(msg);
	listenerInterfaces[client] = reinterpret_cast<IGameEventListener2*>(this);

	// Apply the packet before checking the listener table.  A cheat can defer
	// registration until a feature is enabled mid-round; checking first only
	// sees the previous table and can miss that first update.
	auto result = DETOUR_MEMBER_CALL(ListenEvents)(msg);
	if (!result || gameevents == nullptr)
		return result;

	auto detected = false;

	#if SOURCE_ENGINE == SE_CSGO
	std::vector<unsigned int> currentMask;
	CopyEventMask(msg, currentMask);
	const int activeSubscriptions = (int)currentMask.size();
	ListenerMaskState& maskState = listenerMasks[client];
	const bool changed = maskState.seen && maskState.words != currentMask;
	maskState.seen = true;
	maskState.words.swap(currentMask);
	listenerMaskFingerprints[client] = FingerprintEventMask(maskState.words);
	listenerAcceptedPackets++;
	std::string blacklistedEventNames;
	const int blacklistedSubscriptions = CountBlacklistedListeners(
		reinterpret_cast<IGameEventListener2*>(this), &blacklistedEventNames);
	detected = blacklistedSubscriptions > 0;
	listenerBlacklistedEventNames[client] = blacklistedEventNames;
	if (detected)
	{
		smutils->LogMessage(myself,
			"Listener audit: client %d has %d active subscription(s); blacklisted event(s): %s.",
			client, activeSubscriptions, blacklistedEventNames.c_str());
	}

	// The server can observe subscription-mask changes, but it cannot observe a
	// local-only FireEventIntern hook. Telemetry is sent unconditionally so the
	// plugin can prove the detour fires for every connecting client
	// (sm_kevac_ext) and include real counts in detection evidence.
	DispatchListenerTelemetry(client, activeSubscriptions, blacklistedSubscriptions);
	listenerTelemetryPackets++;

	#else

	auto counter = 0;

	for (auto i = 0; i < MAX_EVENT_NUMBER; i++) {
		if (msg->m_EventArray.Get(i)) 
		{
			counter++;
			#if SOURCE_ENGINE == SE_CSS
				if (counter > 48) 
				{
					detected = true;
				}
			#else 
				if (counter > 25)
				{
					detected = true;
				}
			#endif
		}
	}

	#endif

	if (detected)
	{
		if (forwardCheatDetected != nullptr)
		{
			forwardCheatDetected->PushCell(client);
			forwardCheatDetected->Execute();
		}
	}
	#if SOURCE_ENGINE == SE_CSGO
	else if (changed)
	#else
	else
	#endif
	{
		// Only an actual accepted mask change is forwarded on CS:GO. SourcePawn
		// applies the join and map-transition grace period before acting.
		if (forwardListenerUpdated != nullptr)
		{
			forwardListenerUpdated->PushCell(client);
			forwardListenerUpdated->Execute();
		}
	}

	return result;
}

#if SOURCE_ENGINE == SE_CSGO
static cell_t Native_GetListenerProbeStats(IPluginContext* pContext, const cell_t* params)
{
	if (params[0] != 5)
		return pContext->ThrowNativeError("KevAC_GetListenerProbeStats expects five output parameters");

	cell_t* rawCalls = nullptr;
	cell_t* humanCalls = nullptr;
	cell_t* acceptedPackets = nullptr;
	cell_t* vtablePackets = nullptr;
	cell_t* telemetryPackets = nullptr;
	if (pContext->LocalToPhysAddr(params[1], &rawCalls) != SP_ERROR_NONE ||
		pContext->LocalToPhysAddr(params[2], &humanCalls) != SP_ERROR_NONE ||
		pContext->LocalToPhysAddr(params[3], &acceptedPackets) != SP_ERROR_NONE ||
		pContext->LocalToPhysAddr(params[4], &vtablePackets) != SP_ERROR_NONE ||
		pContext->LocalToPhysAddr(params[5], &telemetryPackets) != SP_ERROR_NONE)
	{
		return pContext->ThrowNativeError("Could not access KevAC listener probe output parameters");
	}

	*rawCalls = listenerProbeCalls;
	*humanCalls = listenerProbeHumanCalls;
	*acceptedPackets = listenerAcceptedPackets;
	*vtablePackets = listenerVTablePackets;
	*telemetryPackets = listenerTelemetryPackets;
	return 1;
}

// This reports installation state, not observed traffic. A stock client is
// allowed to send no CLC_ListenEvents packet, so the packet counters alone
// cannot distinguish that case from a detour that never attached.
static cell_t Native_IsListenerStaticDetourEnabled(IPluginContext* pContext, const cell_t* params)
{
	if (params[0] != 0)
		return pContext->ThrowNativeError("KevAC_IsListenerStaticDetourEnabled expects no parameters");

	return listenerStaticDetourEnabled ? 1 : 0;
}

static cell_t Native_GetListenerMaskFingerprint(IPluginContext* pContext, const cell_t* params)
{
	if (params[0] != 1)
		return pContext->ThrowNativeError("KevAC_GetListenerMaskFingerprint expects one client parameter");

	const int client = params[1];
	auto found = listenerMaskFingerprints.find(client);
	if (found == listenerMaskFingerprints.end())
		return 0;

	return static_cast<cell_t>(found->second);
}

static cell_t Native_GetListenerBlacklistedEvents(IPluginContext* pContext, const cell_t* params)
{
	if (params[0] != 3)
		return pContext->ThrowNativeError("KevAC_GetListenerBlacklistedEvents expects client, buffer, and maxlength");

	const int client = params[1];
	auto found = listenerBlacklistedEventNames.find(client);
	const char* names = found == listenerBlacklistedEventNames.end() ? "" : found->second.c_str();
	pContext->StringToLocal(params[2], params[3], names);
	return 1;
}

static cell_t Native_AuditListenerCandidates(IPluginContext* pContext, const cell_t* params)
{
	if (params[0] != 4)
		return pContext->ThrowNativeError("KevAC_AuditListenerCandidates expects client, candidates, buffer, and maxlength");

	char* candidates = nullptr;
	if (pContext->LocalToString(params[2], &candidates) != SP_ERROR_NONE)
		return pContext->ThrowNativeError("Could not read KevAC listener-audit candidates");

	std::string matchedEvents;
	const int matches = AuditListenerCandidates(params[1], candidates, matchedEvents);
	pContext->StringToLocal(params[3], params[4], matchedEvents.c_str());
	return matches;
}

static cell_t Native_GetAllListenerAuditEvents(IPluginContext* pContext, const cell_t* params)
{
	if (params[0] != 3)
		return pContext->ThrowNativeError("KevAC_GetAllListenerAuditEvents expects client, buffer, and maxlength");

	std::string matchedEvents;
	const int matches = GetAllAuditedListenerEvents(params[1], matchedEvents);
	pContext->StringToLocal(params[2], params[3], matchedEvents.c_str());
	return matches;
}

static cell_t Native_InspectListenEvents(IPluginContext* pContext, const cell_t* params)
{
	if (params[0] != 6)
		return pContext->ThrowNativeError("KevAC_InspectListenEvents expects client, handler, message, and three output parameters");

	cell_t* activeSubscriptions = nullptr;
	cell_t* blacklistedListeners = nullptr;
	cell_t* changed = nullptr;
	if (pContext->LocalToPhysAddr(params[4], &activeSubscriptions) != SP_ERROR_NONE ||
		pContext->LocalToPhysAddr(params[5], &blacklistedListeners) != SP_ERROR_NONE ||
		pContext->LocalToPhysAddr(params[6], &changed) != SP_ERROR_NONE)
	{
		return pContext->ThrowNativeError("Could not access KevAC ListenEvents inspection output parameters");
	}

	const int client = params[1];
	void* messageHandler = reinterpret_cast<void*>(static_cast<uintptr_t>(static_cast<uint32_t>(params[2])));
	CCLCMsg_ListenEvents* message = reinterpret_cast<CCLCMsg_ListenEvents*>(static_cast<uintptr_t>(static_cast<uint32_t>(params[3])));
	if (client < 1 || playerhelpers->GetGamePlayer(client) == nullptr || messageHandler == nullptr || message == nullptr)
	{
		*activeSubscriptions = 0;
		*blacklistedListeners = 0;
		*changed = 0;
		return 0;
	}
	listenerInterfaces[client] = GetEventListenerFromMessageHandler(messageHandler);

	std::vector<unsigned int> currentMask;
	CopyEventMask(message, currentMask);
	ListenerMaskState& maskState = listenerVTableMasks[client];
	const bool didChange = maskState.seen && maskState.words != currentMask;
	maskState.seen = true;
	maskState.words.swap(currentMask);
	listenerMaskFingerprints[client] = FingerprintEventMask(maskState.words);

	listenerVTablePackets++;
	listenerTelemetryPackets++;
	*activeSubscriptions = static_cast<cell_t>(maskState.words.size());
	std::string blacklistedEventNames;
	*blacklistedListeners = CountBlacklistedListeners(messageHandler, &blacklistedEventNames);
	listenerBlacklistedEventNames[client] = blacklistedEventNames;
	if (!blacklistedEventNames.empty())
	{
		smutils->LogMessage(myself,
			"Listener audit: client %d has %d active subscription(s); blacklisted event(s): %s.",
			client, *activeSubscriptions, blacklistedEventNames.c_str());
	}
	*changed = didChange ? 1 : 0;
	return 1;
}

static sp_nativeinfo_t g_KevACNatives[] =
{
	{"KevAC_GetListenerProbeStats", Native_GetListenerProbeStats},
	{"KevAC_IsListenerStaticDetourEnabled", Native_IsListenerStaticDetourEnabled},
	{"KevAC_GetListenerMaskFingerprint", Native_GetListenerMaskFingerprint},
	{"KevAC_GetListenerBlacklistedEvents", Native_GetListenerBlacklistedEvents},
	{"KevAC_AuditListenerCandidates", Native_AuditListenerCandidates},
	{"KevAC_GetAllListenerAuditEvents", Native_GetAllListenerAuditEvents},
	{"KevAC_InspectListenEvents", Native_InspectListenEvents},
	{nullptr, nullptr}
};
#endif


bool KevAC::SDK_OnLoad(char* error, size_t maxlen, bool late)
{
	if (gameevents == nullptr)
	{
		smutils->Format(error, maxlen, "Failed to acquire the game event manager");
		return false;
	}

	if (!gameconfs->LoadGameConfigFile("kevac.games", &pGameConfig, error, maxlen)) 
	{
		smutils->Format(error, maxlen - 1, "Failed to load gamedata");
		return false;
	}

	#if SOURCE_ENGINE == SE_CSGO
	char path[PLATFORM_MAX_PATH];
	smutils->BuildPath(Path_SM, path, PLATFORM_MAX_PATH, "data/kevac/events_detection.txt");

	if (!libsys->PathExists(path))
	{
		smutils->Format(error, maxlen - 1, "File %s not found", path);
		return false;
	}

	events.clear();
	listenerAuditEvents.clear();
	listenerMasks.clear();
	listenerVTableMasks.clear();
	listenerMaskFingerprints.clear();
	listenerInterfaces.clear();
	listenerProbeCalls = 0;
	listenerProbeHumanCalls = 0;
	listenerAcceptedPackets = 0;
	listenerVTablePackets = 0;
	listenerTelemetryPackets = 0;
	listenerStaticDetourEnabled = false;
	std::string buffer;
    std::ifstream file(path);
	if (!file.is_open())
	{
		smutils->Format(error, maxlen, "Could not open %s", path);
		return false;
	}

	while (getline(file, buffer))
	{
		TrimEventName(buffer);
		std::string auditEvent;
		if (ExtractAuditEventName(buffer, auditEvent) && std::find(listenerAuditEvents.begin(), listenerAuditEvents.end(), auditEvent) == listenerAuditEvents.end())
			listenerAuditEvents.push_back(auditEvent);
        if (buffer.empty() || buffer[0] == '#' || buffer[0] == ';' || (buffer.size() >= 2 && buffer[0] == '/' && buffer[1] == '/'))
			continue;

        events.push_back(buffer);
    }

	file.close();
	if (events.empty())
	{
		smutils->Format(error, maxlen, "No event names loaded from %s", path);
		return false;
	}
	#endif

	CDetourManager::Init(smutils->GetScriptingEngine(), pGameConfig);
	#if SOURCE_ENGINE == SE_CSGO
	// Resolve once before asking SafetyHook to create the detour. Calling the
	// named CDetour helper when the gameconf alias has no matching module emits
	// a misleading "Sigscan failed" error and prevents the valid manual routes
	// below from explaining what actually happened.
	const char* detourName = "Signature";
	void* gamedataListenerAddress = nullptr;
	if (pGameConfig->GetMemSig(detourName, &gamedataListenerAddress) && gamedataListenerAddress != nullptr)
	{
		pDetour = CDetourManager::CreateDetour(
			GET_MEMBER_CALLBACK(ListenEvents),
			GET_MEMBER_TRAMPOLINE(ListenEvents),
			gamedataListenerAddress);
	}
	else
	{
		smutils->LogMessage(myself, "Route A gameconf alias 'engine' did not resolve ProcessListenEvents; checking already-loaded modules next.");
	}
	#else
	const char* detourName = "ProcessListenEvents";
	pDetour = DETOUR_CREATE_MEMBER(ListenEvents, detourName);
	if (pDetour == nullptr)
	{
		detourName = "Signature";
		pDetour = DETOUR_CREATE_MEMBER(ListenEvents, detourName);
	}
	#endif

	const char* detourBackend = "SafetyHook";
	if (pDetour != nullptr)
	{
		pDetour->EnableDetour();
		listenerStaticDetourEnabled = pDetour->IsEnabled();
		if (!listenerStaticDetourEnabled)
		{
			smutils->LogMessage(myself, "SafetyHook found ListenEvents but could not enable its Route A detour; trying the CS:GO x86 fallback.");
			pDetour->Destroy();
			pDetour = nullptr;
		}
	}

	if (!listenerStaticDetourEnabled)
	{
		#if SOURCE_ENGINE == SE_CSGO
		#if defined __linux__ && defined __i386__
		void* listenerAddress = gamedataListenerAddress;
		if (listenerAddress != nullptr
			&& listenerFallbackRoute.Install(listenerAddress, GET_MEMBER_CALLBACK(ListenEvents), GET_MEMBER_TRAMPOLINE(ListenEvents)))
		{
			listenerStaticDetourEnabled = true;
			detourBackend = "CS:GO x86 direct fallback";
			smutils->LogMessage(myself, "SafetyHook Route A was unavailable; installed the verified CS:GO x86 direct ListenEvents fallback.");
		}

		// A stripped engine has no exported member symbol, but some legacy builds
		// retain it. RTLD_DEFAULT queries only modules the server already loaded.
		if (!listenerStaticDetourEnabled)
		{
			for (const char* symbol : kProcessListenEventsSymbols)
			{
				listenerAddress = dlsym(RTLD_DEFAULT, symbol);
				if (listenerAddress == nullptr
					|| !listenerFallbackRoute.Install(listenerAddress, GET_MEMBER_CALLBACK(ListenEvents), GET_MEMBER_TRAMPOLINE(ListenEvents)))
					continue;

				listenerStaticDetourEnabled = true;
				detourBackend = "CS:GO x86 exported-symbol fallback";
				smutils->LogMessage(myself, "Route A resolved CBaseClient::ProcessListenEvents through already-loaded symbol '%s' and installed the direct x86 fallback.", symbol);
				break;
			}
		}

		// Build-independent route: resolve the function by the engine's own
		// diagnostic string reference. This does not depend on the frame sizes or
		// absolute operand that make the raw byte signature fragile across builds,
		// so it recovers servers whose engine.so differs from the captured one.
		StringAnchorScan anchorScan;
		if (!listenerStaticDetourEnabled)
		{
			listenerAddress = FindListenEventsByStringAnchor(anchorScan);
			if (listenerAddress != nullptr)
			{
				// Prefer SafetyHook at the anchored address: it decodes the prologue
				// itself, so it tolerates the frame-size and operand differences the raw
				// signature could not, and needs no assumption about the first bytes.
				pDetour = CDetourManager::CreateDetour(GET_MEMBER_CALLBACK(ListenEvents), GET_MEMBER_TRAMPOLINE(ListenEvents), listenerAddress);
				if (pDetour != nullptr)
				{
					pDetour->EnableDetour();
					listenerStaticDetourEnabled = pDetour->IsEnabled();
					if (listenerStaticDetourEnabled)
					{
						detourBackend = "SafetyHook via diagnostic-string anchor";
						smutils->LogMessage(myself, "Route A resolved ProcessListenEvents by its diagnostic string in module '%s' and hooked it with SafetyHook.", anchorScan.module);
					}
					else
					{
						pDetour->Destroy();
						pDetour = nullptr;
					}
				}

				// Manual x86 patch if SafetyHook could not attach to the anchored address.
				if (!listenerStaticDetourEnabled
					&& listenerFallbackRoute.Install(listenerAddress, GET_MEMBER_CALLBACK(ListenEvents), GET_MEMBER_TRAMPOLINE(ListenEvents)))
				{
					listenerStaticDetourEnabled = true;
					detourBackend = "CS:GO x86 diagnostic-string anchor";
					smutils->LogMessage(myself, "Route A resolved ProcessListenEvents by its diagnostic string in module '%s' and installed the direct x86 fallback.", anchorScan.module);
				}
			}
		}

		// Last valid Route A path: scan executable memory from every module that
		// is already mapped into srcds. This handles a server whose SourceMod
		// gameconf alias cannot name its engine module, without touching any file
		// that is not part of the live process.
		if (!listenerStaticDetourEnabled)
		{
			char module[PLATFORM_MAX_PATH];
			int executableModules = 0;
			std::vector<std::string> loadedModules;
			listenerAddress = FindListenEventsInLoadedModules(module, sizeof(module), executableModules, loadedModules);
			if (listenerAddress != nullptr
				&& listenerFallbackRoute.Install(listenerAddress, GET_MEMBER_CALLBACK(ListenEvents), GET_MEMBER_TRAMPOLINE(ListenEvents)))
			{
				listenerStaticDetourEnabled = true;
				detourBackend = "CS:GO x86 loaded-module signature fallback";
				smutils->LogMessage(myself, "Route A found and patched ProcessListenEvents in loaded module '%s' after scanning %d executable module(s).", module, executableModules);
			}
			else if (listenerAddress == nullptr)
			{
				WriteRouteAModuleDiagnostic(loadedModules);
				// Append the ground-truth prologue bytes the string anchor found (if
				// any) so a build mismatch can be diagnosed from one log file.
				WriteRouteAStringAnchorDiagnostic(anchorScan);
				smutils->LogError(myself, "Route A ListenEvents could not attach: gamedata, exported-symbol, diagnostic-string, and raw-signature lookups all failed (%d module(s) scanned). Wrote addons/sourcemod/logs/KevAC-routea-modules.log.", executableModules);
			}
			else
			{
				smutils->LogError(myself, "Route A found the verified ProcessListenEvents bytes in loaded module '%s' but the direct x86 patch could not be installed.", module);
			}
		}
		#else
		smutils->LogError(myself, "Route A ListenEvents could not attach. This build is not 32-bit Linux, so the CS:GO x86 fallback is unavailable.");
		#endif
		#else
		smutils->Format(error, maxlen - 1, "Failed to create interceptor");
		return false;
		#endif
	}

	forwardCheatDetected = forwards->CreateForward("KevAC_OnCheatDetected", ET_Event, 1, nullptr, Param_Cell);
	forwardListenerUpdated = forwards->CreateForward("KevAC_OnListenerUpdate", ET_Event, 1, nullptr, Param_Cell);
	forwardListenerTelemetry = forwards->CreateForward("KevAC_OnListenerTelemetry", ET_Ignore, 3, nullptr, Param_Cell, Param_Cell, Param_Cell);
	forwardListenerProbe = forwards->CreateForward("KevAC_OnListenerProbe", ET_Ignore, 3, nullptr, Param_Cell, Param_Cell, Param_Cell);
	#if SOURCE_ENGINE == SE_CSGO
	sharesys->AddNatives(myself, g_KevACNatives);
	#endif

	playerhelpers->AddClientListener(&kevac);

	sharesys->RegisterLibrary(myself, "kevac");

	// Creation alone does not prove the legacy byte pattern reaches a live
	// handler. Unsafe SourcePawn vtable probing is separately gated by KevAC.sp.
	if (listenerStaticDetourEnabled)
		smutils->LogMessage(myself, "Loaded: %d blacklisted event(s), %d listener-audit event(s), static ListenEvents probe '%s' enabled through %s.", (int)events.size(), (int)listenerAuditEvents.size(), detourName, detourBackend);
	else
		smutils->LogMessage(myself, "Loaded: %d blacklisted event(s), %d listener-audit event(s), static ListenEvents probe unavailable; unsafe vtable probing remains separately blocked by KevAC.sp.", (int)events.size(), (int)listenerAuditEvents.size());

	return true;
}

void KevAC::OnClientDisconnected(int client)
{
#if SOURCE_ENGINE == SE_CSGO
	listenerMasks.erase(client);
	listenerVTableMasks.erase(client);
	listenerMaskFingerprints.erase(client);
	listenerBlacklistedEventNames.erase(client);
	listenerInterfaces.erase(client);
#endif
}

void KevAC::SDK_OnUnload()
{
	playerhelpers->RemoveClientListener(&kevac);

	if (pDetour != nullptr)
	{
		// Restoring the patched prologue is not enough. Destroy the SafetyHook
		// owner before this extension is unloaded so its trampoline allocation
		// and callback state cannot outlive KevAC's code segment.
		pDetour->DisableDetour();
		pDetour->Destroy();
		pDetour = nullptr;
	}
	#if SOURCE_ENGINE == SE_CSGO
	#if defined __linux__ && defined __i386__
	listenerFallbackRoute.Remove();
	#endif
	#endif
	listenerStaticDetourEnabled = false;
	if (forwardCheatDetected != nullptr)
	{
		forwards->ReleaseForward(forwardCheatDetected);
		forwardCheatDetected = nullptr;
	}
	if (forwardListenerUpdated != nullptr)
	{
		forwards->ReleaseForward(forwardListenerUpdated);
		forwardListenerUpdated = nullptr;
	}
	if (forwardListenerTelemetry != nullptr)
	{
		forwards->ReleaseForward(forwardListenerTelemetry);
		forwardListenerTelemetry = nullptr;
	}
	if (forwardListenerProbe != nullptr)
	{
		forwards->ReleaseForward(forwardListenerProbe);
		forwardListenerProbe = nullptr;
	}
	if (pGameConfig != nullptr)
	{
		gameconfs->CloseGameConfigFile(pGameConfig);
		pGameConfig = nullptr;
	}
	events.clear();
	listenerMasks.clear();
	listenerVTableMasks.clear();
	listenerMaskFingerprints.clear();
}

bool KevAC::SDK_OnMetamodLoad(ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
	GET_V_IFACE_CURRENT(GetEngineFactory, gameevents, IGameEventManager2, INTERFACEVERSION_GAMEEVENTSMANAGER2);
	GET_V_IFACE_CURRENT(GetEngineFactory, engineServer, IVEngineServer, INTERFACEVERSION_VENGINESERVER);
	GET_V_IFACE_CURRENT(GetEngineFactory, engineCvar, ICvar, CVAR_INTERFACE_VERSION);

	return true;
}

