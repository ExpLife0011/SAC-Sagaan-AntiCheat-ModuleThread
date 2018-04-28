#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <wdf.h>
#include <ntdef.h>

// Request to retrieve the base address of client.dll in csgo.exe from kernel space
#define IO_PROGRAM_PROCESSID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0700 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to read virtual user memory (memory of a program) from kernel space
#define IO_TERMINATION_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to read virtual user memory (memory of a program) from kernel space
#define IO_THREADIDS_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define PROCESS_QUERY_LIMITED_INFORMATION      0x1000

PDEVICE_OBJECT pDeviceObject; // our driver object
UNICODE_STRING dev, dos; // Driver registry paths

// Local Varibles
ULONG CSGO = 0;
ULONG ProtectedThread = 0;
ULONG USERMODEPROGRAM = 0;
ULONG TerminateProcessID = 0;
ULONG CSRSS = 0;
ULONG CSRSS2 = 0;

ULONG THREAD1;
ULONG THREAD2;
ULONG THREAD3;
ULONG THREAD4;

BOOL ThreadID = FALSE;
BOOL ProcessID = FALSE;

NTSTATUS ImageCallback = STATUS_SUCCESS;
NTSTATUS ThreadCallback = STATUS_SUCCESS;
NTSTATUS HandleCallback = STATUS_SUCCESS;
NTSTATUS Returned = STATUS_UNSUCCESSFUL;

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp);

typedef struct _OB_REG_CONTEXT {
	USHORT Version;
	UNICODE_STRING Altitude;
	USHORT ulIndex;
	OB_OPERATION_REGISTRATION *OperationRegistration;
} REG_CONTEXT, *PREG_CONTEXT;

NTSTATUS TerminatingProcess(ULONG targetPid)
{
	NTSTATUS NtRet = STATUS_SUCCESS;
	PEPROCESS PeProc = { 0 };
	NtRet = PsLookupProcessByProcessId(targetPid, &PeProc);
	if (NtRet != STATUS_SUCCESS)
	{
		return NtRet;
	}
	HANDLE ProcessHandle;
	NtRet = ObOpenObjectByPointer(PeProc, NULL, NULL, 25, *PsProcessType, KernelMode, &ProcessHandle);
	if (NtRet != STATUS_SUCCESS)
	{
		return NtRet;
	}
	ZwTerminateProcess(ProcessHandle, 0);
	ZwClose(ProcessHandle);
	return NtRet;
}

OB_PREOP_CALLBACK_STATUS PreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (CSGO == 0)
		return OB_PREOP_SUCCESS;

	if (USERMODEPROGRAM == 0)
		return OB_PREOP_SUCCESS;

	if (CSRSS == 0)
		return OB_PREOP_SUCCESS;

	if (CSRSS2 == 0)
		return OB_PREOP_SUCCESS;

	PEPROCESS UserProcess;
	PEPROCESS Csrss1Process;
	PEPROCESS Csrss2Process;
	PEPROCESS ProtectedProcessProcess;

	PEPROCESS OpenedProcess = (PEPROCESS)OperationInformation->Object,
		CurrentProcess = PsGetCurrentProcess();

	PsLookupProcessByProcessId(CSGO, &ProtectedProcessProcess); // Getting the PEPROCESS using the PID 
	PsLookupProcessByProcessId(USERMODEPROGRAM, &UserProcess); // Getting the PEPROCESS using the PID 
	PsLookupProcessByProcessId(CSRSS, &Csrss1Process); // Getting the PEPROCESS using the PID 
	PsLookupProcessByProcessId(CSRSS2, &Csrss2Process); // Getting the PEPROCESS using the PID 


	if (OpenedProcess == Csrss1Process) // Making sure to not strip csrss's Handle, will cause BSOD
		return OB_PREOP_SUCCESS;

	if (OpenedProcess == Csrss2Process) // Making sure to not strip csrss's Handle, will cause BSOD
		return OB_PREOP_SUCCESS;

	if (OpenedProcess == UserProcess) // make sure the driver isnt getting stripped ( even though we have a second check )
		return OB_PREOP_SUCCESS;


	if (OperationInformation->KernelHandle) // allow drivers to get a handle
		return OB_PREOP_SUCCESS;


	// PsGetProcessId((PEPROCESS)OperationInformation->Object) equals to the created handle's PID, so if the created Handle equals to the protected process's PID, strip
	if (PsGetProcessId((PEPROCESS)OperationInformation->Object) == CSGO || PsGetProcessId((PEPROCESS)OperationInformation->Object) == USERMODEPROGRAM)
	{
		DbgPrintEx(0, 0, "ObRegisterCallback: Strip A Handle Permissions");

		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) // striping handle 
		{
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);
		}
		else
		{
			OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);
		}

		return OB_PREOP_SUCCESS;
	}
}

// This happens after everything. 
VOID PostCallBack(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
}

PVOID ObHandle = NULL;
VOID EnableObRegisterCallBack()
{

	OB_OPERATION_REGISTRATION OBOperationRegistration;
	OB_CALLBACK_REGISTRATION OBOCallbackRegistration;
	REG_CONTEXT regContext;
	UNICODE_STRING usAltitude;
	memset(&OBOperationRegistration, 0, sizeof(OB_OPERATION_REGISTRATION));
	memset(&OBOCallbackRegistration, 0, sizeof(OB_CALLBACK_REGISTRATION));
	memset(&regContext, 0, sizeof(REG_CONTEXT));
	regContext.ulIndex = 1;
	regContext.Version = 120;
	RtlInitUnicodeString(&usAltitude, L"389020");

	if ((USHORT)ObGetFilterVersion() == OB_FLT_REGISTRATION_VERSION)
	{
		OBOperationRegistration.ObjectType = PsProcessType; // Use To Strip Handle Permissions For Threads PsThreadType
		OBOperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		OBOperationRegistration.PostOperation = PostCallBack; // Giving the function which happens after creating
		OBOperationRegistration.PreOperation = PreCallback; // Giving the function which happens before creating

															// Setting the altitude of the driver
		OBOCallbackRegistration.Altitude = usAltitude;
		OBOCallbackRegistration.OperationRegistration = &OBOperationRegistration;
		OBOCallbackRegistration.RegistrationContext = &regContext;
		OBOCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
		OBOCallbackRegistration.OperationRegistrationCount = 1;

		HandleCallback = ObRegisterCallbacks(&OBOCallbackRegistration, &ObHandle); // Register The CallBack
	}

	if (HandleCallback != STATUS_SUCCESS)
	{
		DbgPrintEx(0, 0, "ObRegisterCallback: Returned = %d", HandleCallback);
	}
	else
	{
		DbgPrintEx(0, 0, "ObRegisterCallback: Returned = PASSED");
	}
}

VOID PsCreateProcessNotify(
	IN HANDLE  hParentId,
	IN HANDLE  hProcessId,
	_In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
		DbgPrintEx(0, 0, "CreateProcess: ProcessID = %d, ParentPID = %d, Created \n",
			hProcessId, hParentId);
}

int ModuleTesting = 0;
int ModuleTesting2 = 0;
// set a callback for every PE image loaded to user memory
// then find the client.dll & csgo.exe using the callback
PLOAD_IMAGE_NOTIFY_ROUTINE ImageLoadCallback(PUNICODE_STRING FullImageName,
	HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	if (ProcessId == CSGO && CSGO != 0)
	{
		DbgPrintEx(0, 0, "CSGO: Loaded Modules. ProcessID = %d, ThreadID = %d, Full ImageInfo = %d \n",
			ProcessId, ImageInfo, FullImageName->Buffer);
	}

	if (ProcessId == USERMODEPROGRAM && USERMODEPROGRAM != 0)
	{
		DbgPrintEx(0, 0, "USERMODEPROGRAM: Loaded Modules. ProcessID = %d, ThreadID = %d, Full ImageInfo = %d \n",
			ProcessId, ImageInfo, FullImageName->Buffer);
	}

}

VOID CreateThreadNotifyRoutine(
	IN HANDLE ProcessId,
	IN HANDLE ThreadId,
	IN BOOLEAN Create
)
{
	
	if (ProcessId == USERMODEPROGRAM && USERMODEPROGRAM != 0)
	{
		if (Create)
		{
			if (THREAD1 != 0 ||
				THREAD2 != 0 ||
				THREAD3 != 0 ||
				THREAD4 != 0)
			{
				if (ThreadId != THREAD1 ||
					ThreadId != THREAD2 ||
					ThreadId != THREAD3 ||
					ThreadId != THREAD4
					)
				{
					DbgPrintEx(0, 0, "USERMODEPROGRAM: Create Thread. ProcessID = %d, ThreadID = %d \n",
						ProcessId, ThreadId);
				}
			}
		}
		else
		{
			if (ThreadId == THREAD1)
			{
				TerminatingProcess(CSGO);
			}
			if (ThreadId == THREAD2)
			{
				TerminatingProcess(CSGO);
			}
			if (ThreadId == THREAD3)
			{
				TerminatingProcess(CSGO);
			}
			if (ThreadId == THREAD4)
			{
				TerminatingProcess(CSGO);
			}

			DbgPrintEx(0, 0, "USERMODEPROGRAM: Delete Thread. ProcessID = %d, ThreadID = %d \n",
				ProcessId, ThreadId);

		}

	}
	if (ProcessId == CSGO && CSGO != 0)
	{
		if (Create)
		{
			DbgPrintEx(0, 0, "CSGO: Create Thread. ProcessID = %d, ThreadID = %d \n",
				ProcessId, ThreadId);
		}
		else
		{
			DbgPrintEx(0, 0, "CSGO: Delete Thread. ProcessID = %d, ThreadID = %d \n",
				ProcessId, ThreadId);

		}
	}
}

typedef struct _KERNEL_PROCESSIDS_REQUEST
{
	ULONG CSGO;
	ULONG USERMODEPROGRAM;
	
	ULONG CSRSS;
	ULONG CSRSS2;

} KERNEL_PROCESSIDS_REQUEST, *PKERNEL_PROCESSIDS_REQUEST;

typedef struct _KERNEL_THREADIDS_REQUEST
{
	ULONG THREAD1;
	ULONG THREAD2;
	ULONG THREAD3;
	ULONG THREAD4;

} KERNEL_THREADIDS_REQUEST, *PKERNEL_THREADIDS_REQUEST;

typedef struct _KERNEL_TERMINATION_REQUEST
{
	ULONG TERMINATIONPROCESSID;

} KERNEL_TERMINATION_REQUEST, *PKERNEL_TERMINATION_REQUEST;

// IOCTL Call Handler function
NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS Status;
	ULONG BytesIO = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	// Code received from user space
	ULONG ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	if (ControlCode == IO_PROGRAM_PROCESSID)
	{
		if (ProcessID == FALSE)
		{
			// Get the input buffer & format it to our struct
			PKERNEL_PROCESSIDS_REQUEST ReadInput = (PKERNEL_PROCESSIDS_REQUEST)Irp->AssociatedIrp.SystemBuffer;

			if (ReadInput->CSGO != 0)
			{
				CSGO = ReadInput->CSGO;
			}
			if (ReadInput->USERMODEPROGRAM != 0)
			{
				USERMODEPROGRAM = ReadInput->USERMODEPROGRAM;
			}
			if (ReadInput->CSRSS != 0)
			{
				CSRSS = ReadInput->CSRSS;
			}
			if (ReadInput->CSRSS2 != 0)
			{
				CSRSS2 = ReadInput->CSRSS2;
			}

			Status = STATUS_SUCCESS;
			BytesIO = sizeof(KERNEL_PROCESSIDS_REQUEST);
			ProcessID = TRUE;
		}
	}
	else if (ControlCode == IO_THREADIDS_REQUEST)
	{
		if (ThreadID == FALSE)
		{
			// Get the input buffer & format it to our struct
			PKERNEL_THREADIDS_REQUEST ReadInput = (PKERNEL_THREADIDS_REQUEST)Irp->AssociatedIrp.SystemBuffer;

			if (ReadInput->THREAD1 != 0)
			{
				THREAD1 = ReadInput->THREAD1;
			}
			if (ReadInput->THREAD2 != 0)
			{
				THREAD2 = ReadInput->THREAD2;
			}
			if (ReadInput->THREAD3 != 0)
			{
				THREAD3 = ReadInput->THREAD3;
			}
			if (ReadInput->THREAD4 != 0)
			{
				THREAD4 = ReadInput->THREAD4;
			}

			Status = STATUS_SUCCESS;
			BytesIO = sizeof(KERNEL_TERMINATION_REQUEST);
			ThreadID = TRUE;
		}
	}
	else if (ControlCode == IO_TERMINATION_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PKERNEL_TERMINATION_REQUEST ReadInput = (PKERNEL_TERMINATION_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		if (ReadInput->TERMINATIONPROCESSID != 0)
		{
			TerminateProcessID = ReadInput->TERMINATIONPROCESSID;
			TerminatingProcess(TerminateProcessID);
			TerminateProcessID = 0;
		}

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_TERMINATION_REQUEST);
	}
	else
	{
		// if the code is unknown
		TerminatingProcess(CSGO);
		TerminatingProcess(USERMODEPROGRAM);
		Status = STATUS_INVALID_PARAMETER;
		BytesIO = 0;
	}

	// Complete the request
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

PDEVICE_OBJECT DeviceObject;
// Driver Entrypoint
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath)
{
	DbgPrintEx(0, 0, "SAC Driver Loaded\n");

	ImageCallback = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
	ThreadCallback = PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
	PsSetCreateProcessNotifyRoutineEx(PsCreateProcessNotify, FALSE);

	PLDR_DATA_TABLE_ENTRY CurDriverEntry = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	PLDR_DATA_TABLE_ENTRY NextDriverEntry = (PLDR_DATA_TABLE_ENTRY)CurDriverEntry->InLoadOrderLinks.Flink;
	PLDR_DATA_TABLE_ENTRY PrevDriverEntry = (PLDR_DATA_TABLE_ENTRY)CurDriverEntry->InLoadOrderLinks.Blink;

	PrevDriverEntry->InLoadOrderLinks.Flink = CurDriverEntry->InLoadOrderLinks.Flink;
	NextDriverEntry->InLoadOrderLinks.Blink = CurDriverEntry->InLoadOrderLinks.Blink;

	CurDriverEntry->InLoadOrderLinks.Flink = (PLIST_ENTRY)CurDriverEntry;
	CurDriverEntry->InLoadOrderLinks.Blink = (PLIST_ENTRY)CurDriverEntry;

	RtlInitUnicodeString(&dev, L"\\Device\\SACDriverModuleThread");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\SACDriverModuleThread");

	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&dos, &dev);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCall;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	pDriverObject->DriverUnload = UnloadDriver;

	EnableObRegisterCallBack();

	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}



NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	DbgPrintEx(0, 0, "SAC Unload routine called.\n");
	if (ObHandle != NULL)
	{
		ObUnRegisterCallbacks(ObHandle);
	}
	PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
	PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
	PsSetCreateProcessNotifyRoutineEx(PsCreateProcessNotify, TRUE);
	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
