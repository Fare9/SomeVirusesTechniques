#pragma once
#ifndef PROCESS_INJECTOR_H
#define PROCESS_INJECTOR_H

#include "common.h"
#include "string_crypt.h"

struct PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	DWORD PebBaseAddress;
	PVOID Reserved2[2];
	DWORD UniqueProcessId;
	PVOID Reserved3;
};


struct PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
};


struct PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	struct PEB_LDR_DATA *Ldr;
	void * ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	void * FastPebLockRoutine;
	void * FastPebUnlockRoutine;
	ULONG EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID EventLogSection;
	PVOID EventLog;
	void * FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[0x2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	UCHAR Spare2[0x4];
	ULARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	PVOID GdiDCAttributeList;
	PVOID LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	ULONG OSBuildNumber;
	ULONG OSPlatformId;
	ULONG ImageSubSystem;
	ULONG ImageSubSystemMajorVersion;
	ULONG ImageSubSystemMinorVersion;
	ULONG GdiHandleBuffer[0x22];
	PVOID ProcessWindowStation;
};


class process_injector_t
{
public:
	static process_injector_t* get_instance(uint8_t *pointer_to_buffer, HANDLE hProcess, HANDLE hThread);

	process_injector_t(uint8_t *pointer_to_buffer, HANDLE hProcess, HANDLE hThread);
	~process_injector_t();

	bool inject_into_process();

	bool set_sections_protections();

	HANDLE create_thread_on_ep();

	PVOID base_address();
	uint32_t image_size();
	uint32_t header_size();
	uint32_t entry_point();

private:


	bool unmap_process(HANDLE hProcess, PVOID base_address);
	bool allocate_new_space(HANDLE hProcess, PVOID base_address, uint32_t image_size);
	bool get_binary_values();
	bool inject_pe_header(PVOID header_address, HANDLE hProcess);
	bool inject_sections_to_executable(PVOID base_address, HANDLE hProcess);

	bool load_imports(PVOID base_address, HANDLE hProcess);
	bool fix_relocs(PVOID base_address, HANDLE hProcess);
	bool fix_context(HANDLE hThread);


	uint64_t rva_to_offset(PVOID base_address, uint64_t rva);
	uint64_t offset_to_rva(PVOID base_address, uint64_t offset);

	static process_injector_t* instance;
	uint8_t* process_buffer;
	HANDLE process_handler;
	HANDLE thread_handler;

	// binary values
	PVOID allocated_virtual_address_;
	PVOID base_address_;
	uint32_t image_size_;
	uint32_t header_size_;
	uint32_t entry_point_;
};

#endif // !PROCESS_INJECTOR_H
