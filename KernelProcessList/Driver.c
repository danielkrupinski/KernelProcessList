#include <ntddk.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <wdf.h>

DRIVER_INITIALIZE DriverEntry;

typedef struct _SYSTEM_THREADS {
    LARGE_INTEGER  KernelTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  CreateTime;
    ULONG          WaitTime;
    PVOID          StartAddress;
    CLIENT_ID      ClientId;
    KPRIORITY      Priority;
    KPRIORITY      BasePriority;
    ULONG          ContextSwitchCount;
    LONG           State;
    LONG           WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES {
    ULONG            NextEntryDelta;
    ULONG            ThreadCount;
    ULONG            Reserved1[6];
    LARGE_INTEGER    CreateTime;
    LARGE_INTEGER    UserTime;
    LARGE_INTEGER    KernelTime;
    UNICODE_STRING   ProcessName;
    KPRIORITY        BasePriority;
    SIZE_T           ProcessId;
    SIZE_T           InheritedFromProcessId;
    ULONG            HandleCount;
    ULONG            Reserved2[2];
    VM_COUNTERS      VmCounters;
    IO_COUNTERS      IoCounters;
    SYSTEM_THREADS   Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

#define SystemProcessInformation 5

#define POOL_TAG 'enoN'

NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNICODE_STRING uniName = RTL_CONSTANT_STRING(L"\\SystemRoot\\KernelProcessList.txt");
    OBJECT_ATTRIBUTES objAttr;

    InitializeObjectAttributes(&objAttr, &uniName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);

    HANDLE handle;
    IO_STATUS_BLOCK ioStatusBlock;

    ntstatus = ZwCreateFile(&handle,
        GENERIC_WRITE,
        &objAttr, &ioStatusBlock, NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    
    if (NT_SUCCESS(ntstatus)) {
        ULONG bufferSize = 0;

        if (ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize) == STATUS_INFO_LENGTH_MISMATCH) {
            if (bufferSize) {
                PVOID memory = ExAllocatePoolWithTag(PagedPool, bufferSize, 'enoN');

                if (memory) {
                    ntstatus = ZwQuerySystemInformation(SystemProcessInformation, memory, bufferSize, &bufferSize);
                    if (NT_SUCCESS(ntstatus)) {
                        PSYSTEM_PROCESSES infoP = memory;

                        do {
                            if (infoP->ProcessName.Length) {
                                CHAR pidString[100];
                                ntstatus = RtlStringCbPrintfA(pidString, _countof(pidString), "%ws : %llu\n", infoP->ProcessName.Buffer, infoP->ProcessId);

                                if (NT_SUCCESS(ntstatus)) {
                                    size_t length;
                                    ntstatus = RtlStringCbLengthA(pidString, _countof(pidString), &length);

                                    if (NT_SUCCESS(ntstatus))
                                        ntstatus = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock, pidString, (ULONG)length, NULL, NULL);
                                }
                            }
                            infoP = (PSYSTEM_PROCESSES)((BYTE*)infoP + infoP->NextEntryDelta);
                        } while (infoP->NextEntryDelta);
                    }
                    ExFreePoolWithTag(memory, 'enoN');
                }
            }
        }
        ZwClose(handle);
    }
    return ntstatus;
}
