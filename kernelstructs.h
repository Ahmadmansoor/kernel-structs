#pragma once

typedef struct _EX_RUNDOWN_REF
{
	union
	{
		ULONG Count;
		PVOID Ptr;
	};
} EX_RUNDOWN_REF, *PEX_RUNDOWN_REF;

typedef struct _EX_PUSH_LOCK
{
	union
	{
		ULONG Locked : 1;
		ULONG Waiting : 1;
		ULONG Waking : 1;
		ULONG MultipleShared : 1;
		ULONG Shared : 28;
		ULONG Value;
		PVOID Ptr;
	};
} EX_PUSH_LOCK, *PEX_PUSH_LOCK;

typedef enum _PROCESSOR_CACHE_TYPE {
	CacheUnified,
	CacheInstruction,
	CacheData,
	CacheTrace
} PROCESSOR_CACHE_TYPE;

typedef enum _EXCEPTION_DISPOSITION
{
	ExceptionContinueExecution = 0,
	ExceptionContinueSearch = 1,
	ExceptionNestedException = 2,
	ExceptionCollidedUnwind = 3
} EXCEPTION_DISPOSITION, *PEXCEPTION_DISPOSITION;

typedef struct _TERMINATION_PORT
{
	_TERMINATION_PORT* Next;
	PVOID Port;
} TERMINATION_PORT, *PTERMINATION_PORT;

typedef struct _PS_CLIENT_SECURITY_CONTEXT
{
	union
	{
		ULONG ImpersonationData;
		PVOID ImpersonationToken;
		ULONG ImpersonationLevel : 2;
		ULONG EffectiveOnly : 1;
	};
} PS_CLIENT_SECURITY_CONTEXT, *PPS_CLIENT_SECURITY_CONTEXT;


typedef struct _EXCEPTION_REGISTRATION_RECORD
{
	_EXCEPTION_REGISTRATION_RECORD* Next;
	PEXCEPTION_DISPOSITION Handler;
} EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;


typedef struct _CACHE_DESCRIPTOR {
	BYTE                 Level;
	BYTE                 Associativity;
	WORD                 LineSize;
	DWORD                Size;
	PROCESSOR_CACHE_TYPE Type;
} CACHE_DESCRIPTOR, *PCACHE_DESCRIPTOR;

typedef struct
{
	LONG * IdleHandler;
	ULONG Context;
	ULONG Latency;
	ULONG Power;
	ULONG TimeCheck;
	ULONG StateFlags;
	UCHAR PromotePercent;
	UCHAR DemotePercent;
	UCHAR PromotePercentBase;
	UCHAR DemotePercentBase;
	UCHAR StateType;
} PPM_IDLE_STATE, *PPPM_IDLE_STATE;

typedef struct
{
	ULONG Type;
	ULONG Count;
	ULONG Flags;
	ULONG TargetState;
	ULONG ActualState;
	ULONG OldState;
	ULONG TargetProcessors;
	PPM_IDLE_STATE State[1];
} PPM_IDLE_STATES, *PPPM_IDLE_STATES;

typedef struct
{
	UINT64 StartTime;
	UINT64 EndTime;
	ULONG Reserved[4];
} PROCESSOR_IDLE_TIMES, *PPROCESSOR_IDLE_TIMES;

typedef struct
{
	ULONG IdleTransitions;
	ULONG FailedTransitions;
	ULONG InvalidBucketIndex;
	UINT64 TotalTime;
	ULONG IdleTimeBuckets[6];
} PPM_IDLE_STATE_ACCOUNTING, *PPPM_IDLE_STATE_ACCOUNTING;

typedef struct
{
	ULONG StateCount;
	ULONG TotalTransitions;
	ULONG ResetCount;
	UINT64 StartTime;
	PPM_IDLE_STATE_ACCOUNTING State[1];
} PPM_IDLE_ACCOUNTING, *PPPM_IDLE_ACCOUNTING;

typedef struct
{
	ULONG Frequency;
	ULONG Power;
	UCHAR PercentFrequency;
	UCHAR IncreaseLevel;
	UCHAR DecreaseLevel;
	UCHAR Type;
	UINT64 Control;
	UINT64 Status;
	ULONG TotalHitCount;
	ULONG DesiredCount;
} PPM_PERF_STATE, *PPPM_PERF_STATE;

typedef struct
{
	ULONG Count;
	ULONG MaxFrequency;
	ULONG MaxPerfState;
	ULONG MinPerfState;
	ULONG LowestPState;
	ULONG IncreaseTime;
	ULONG DecreaseTime;
	UCHAR BusyAdjThreshold;
	UCHAR Reserved;
	UCHAR ThrottleStatesOnly;
	UCHAR PolicyType;
	ULONG TimerInterval;
	ULONG Flags;
	ULONG TargetProcessors;
	LONG * PStateHandler;
	ULONG PStateContext;
	LONG * TStateHandler;
	ULONG TStateContext;
	ULONG * FeedbackHandler;
	PPM_PERF_STATE State[1];
} PPM_PERF_STATES, *PPPM_PERF_STATES;

typedef struct _DISPATCHER_HEADER
{
	union
	{
		struct
		{
			UCHAR Type;
			union
			{
				UCHAR Abandoned;
				UCHAR Absolute;
				UCHAR NpxIrql;
				UCHAR Signalling;
			};
			union
			{
				UCHAR Size;
				UCHAR Hand;
			};
			union
			{
				UCHAR Inserted;
				UCHAR DebugActive;
				UCHAR DpcActive;
			};
		};
		LONG Lock;
	};
	LONG SignalState;
	LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER, *PDISPATCHER_HEADER;

typedef struct _ULARGE_INTEGER
{
	union
	{
		struct
		{
			ULONG LowPart;
			ULONG HighPart;
		};
		UINT64 QuadPart;
	};
} ULARGE_INTEGER, *PULARGE_INTEGER;

typedef struct _KDPC
{
	UCHAR Type;
	UCHAR Importance;
	WORD Number;
	LIST_ENTRY DpcListEntry;
	PVOID DeferredRoutine;
	PVOID DeferredContext;
	PVOID SystemArgument1;
	PVOID SystemArgument2;
	PVOID DpcData;
} KDPC, *PKDPC;

typedef struct _KTIMER
{
	DISPATCHER_HEADER Header;
	ULARGE_INTEGER DueTime;
	LIST_ENTRY TimerListEntry;
	PKDPC Dpc;
	LONG Period;
} KTIMER, *PKTIMER;

typedef struct _FX_SAVE_AREA
{
	BYTE U[520];
	ULONG NpxSavedCpu;
	ULONG Cr0NpxState;
} FX_SAVE_AREA, *PFX_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA
{
	ULONG ControlWord;
	ULONG StatusWord;
	ULONG TagWord;
	ULONG ErrorOffset;
	ULONG ErrorSelector;
	ULONG DataOffset;
	ULONG DataSelector;
	UCHAR RegisterArea[80];
	ULONG Cr0NpxState;
} FLOATING_SAVE_AREA, *PFLOATING_SAVE_AREA;


typedef struct _SINGLE_LIST_ENTRY
{
	_SINGLE_LIST_ENTRY* Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;


typedef struct _KEXECUTE_OPTIONS
{
	ULONG ExecuteDisable : 1;
	ULONG ExecuteEnable : 1;
	ULONG DisableThunkEmulation : 1;
	ULONG Permanent : 1;
	ULONG ExecuteDispatchEnable : 1;
	ULONG ImageDispatchEnable : 1;
	ULONG Spare : 2;
} KEXECUTE_OPTIONS, *PKEXECUTE_OPTIONS;


typedef struct _KIDTENTRY
{
	WORD Offset;
	WORD Selector;
	WORD Access;
	WORD ExtendedOffset;
} KIDTENTRY, *PKIDTENTRY;


typedef struct _KGDTENTRY
{
	WORD LimitLow;
	WORD BaseLow;
	ULONG HighWord;
} KGDTENTRY, *PKGDTENTRY;


typedef struct _flags
{
	unsigned char Removable : 1;
	unsigned char GroupAssigned : 1;
	unsigned char GroupCommitted : 1;
	unsigned char GroupAssignmentFixed : 1;
	unsigned char Fill : 4;
} flags;


typedef struct _SLIST_HEADER
{
	union
	{
		UINT64 Alignment;
		struct
		{
			SINGLE_LIST_ENTRY Next;
			WORD Depth;
			WORD Sequence;
		};
	};
} SLIST_HEADER, *PSLIST_HEADER;


typedef struct _KSPIN_LOCK_QUEUE
{
	_KSPIN_LOCK_QUEUE* Next;
	ULONG * Lock;
} KSPIN_LOCK_QUEUE, *PKSPIN_LOCK_QUEUE;


typedef struct _DESCRIPTOR
{
	WORD Pad;
	WORD Limit;
	ULONG Base;
} DESCRIPTOR, *PDESCRIPTOR;


typedef struct _CACHED_KSTACK_LIST
{
	SLIST_HEADER SListHead;
	LONG MinimumFree;
	ULONG Misses;
	ULONG MissesLast;
} CACHED_KSTACK_LIST, *PCACHED_KSTACK_LIST;


typedef struct _KNODE
{
	SLIST_HEADER PagedPoolSListHead;
	SLIST_HEADER NonPagedPoolSListHead[3];
	SLIST_HEADER PfnDereferenceSListHead;
	ULONG ProcessorMask;
	UCHAR Color;
	UCHAR Seed;
	UCHAR NodeNumber;
	_flags Flags;
	ULONG MmShiftedColor;
	ULONG FreeCount[2];
	PSINGLE_LIST_ENTRY PfnDeferredList;
	CACHED_KSTACK_LIST CachedKernelStacks;
} KNODE, *PKNODE;

typedef struct _KDPC_DATA
{
	LIST_ENTRY DpcListHead;
	ULONG DpcLock;
	LONG DpcQueueDepth;
	ULONG DpcCount;
} KDPC_DATA, *PKDPC_DATA;

typedef struct _CONTEXT
{
	ULONG ContextFlags;
	ULONG Dr0;
	ULONG Dr1;
	ULONG Dr2;
	ULONG Dr3;
	ULONG Dr6;
	ULONG Dr7;
	FLOATING_SAVE_AREA FloatSave;
	ULONG SegGs;
	ULONG SegFs;
	ULONG SegEs;
	ULONG SegDs;
	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG Ebp;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG Esp;
	ULONG SegSs;
	UCHAR ExtendedRegisters[512];
} CONTEXT, *PCONTEXT;


typedef struct _KSPECIAL_REGISTERS
{
	ULONG Cr0;
	ULONG Cr2;
	ULONG Cr3;
	ULONG Cr4;
	ULONG KernelDr0;
	ULONG KernelDr1;
	ULONG KernelDr2;
	ULONG KernelDr3;
	ULONG KernelDr6;
	ULONG KernelDr7;
	DESCRIPTOR Gdtr;
	DESCRIPTOR Idtr;
	WORD Tr;
	WORD Ldtr;
	ULONG Reserved[6];
} KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;


typedef struct _KPROCESSOR_STATE
{
	CONTEXT ContextFrame;
	KSPECIAL_REGISTERS SpecialRegisters;
} KPROCESSOR_STATE, *PKPROCESSOR_STATE;


typedef struct _PP_LOOKASIDE_LIST
{
	PGENERAL_LOOKASIDE P;
	PGENERAL_LOOKASIDE L;
} PP_LOOKASIDE_LIST, *PPP_LOOKASIDE_LIST;


typedef struct _GENERAL_LOOKASIDE_POOL
{
	union
	{
		SLIST_HEADER ListHead;
		SINGLE_LIST_ENTRY SingleListHead;
	};
	WORD Depth;
	WORD MaximumDepth;
	ULONG TotalAllocates;
	union
	{
		ULONG AllocateMisses;
		ULONG AllocateHits;
	};
	ULONG TotalFrees;
	union
	{
		ULONG FreeMisses;
		ULONG FreeHits;
	};
	POOL_TYPE Type;
	ULONG Tag;
	ULONG Size;
	union
	{
		PVOID * AllocateEx;
		PVOID * Allocate;
	};
	union
	{
		PVOID FreeEx;
		PVOID Free;
	};
	LIST_ENTRY ListEntry;
	ULONG LastTotalAllocates;
	union
	{
		ULONG LastAllocateMisses;
		ULONG LastAllocateHits;
	};
	ULONG Future[2];
} GENERAL_LOOKASIDE_POOL, *PGENERAL_LOOKASIDE_POOL;


typedef struct _KPRCB
{
	WORD MinorVersion;
	WORD MajorVersion;
	_KTHREAD* CurrentThread;
	_KTHREAD* NextThread;
	_KTHREAD* IdleThread;
	UCHAR Number;
	UCHAR NestingLevel;
	WORD BuildType;
	ULONG SetMember;
	CHAR CpuType;
	CHAR CpuID;
	union
	{
		WORD CpuStep;
		struct
		{
			UCHAR CpuStepping;
			UCHAR CpuModel;
		};
	};
	KPROCESSOR_STATE ProcessorState;
	ULONG KernelReserved[16];
	ULONG HalReserved[16];
	ULONG CFlushSize;
	UCHAR PrcbPad0[88];
	KSPIN_LOCK_QUEUE LockQueue[33];
	_KTHREAD* NpxThread;
	ULONG InterruptCount;
	ULONG KernelTime;
	ULONG UserTime;
	ULONG DpcTime;
	ULONG DpcTimeCount;
	ULONG InterruptTime;
	ULONG AdjustDpcThreshold;
	ULONG PageColor;
	UCHAR SkipTick;
	UCHAR DebuggerSavedIRQL;
	UCHAR NodeColor;
	UCHAR PollSlot;
	ULONG NodeShiftedColor;
	PKNODE ParentNode;
	ULONG MultiThreadProcessorSet;
	_KPRCB* MultiThreadSetMaster;
	ULONG SecondaryColorMask;
	ULONG DpcTimeLimit;
	ULONG CcFastReadNoWait;
	ULONG CcFastReadWait;
	ULONG CcFastReadNotPossible;
	ULONG CcCopyReadNoWait;
	ULONG CcCopyReadWait;
	ULONG CcCopyReadNoWaitMiss;
	LONG MmSpinLockOrdering;
	LONG IoReadOperationCount;
	LONG IoWriteOperationCount;
	LONG IoOtherOperationCount;
	LARGE_INTEGER IoReadTransferCount;
	LARGE_INTEGER IoWriteTransferCount;
	LARGE_INTEGER IoOtherTransferCount;
	ULONG CcFastMdlReadNoWait;
	ULONG CcFastMdlReadWait;
	ULONG CcFastMdlReadNotPossible;
	ULONG CcMapDataNoWait;
	ULONG CcMapDataWait;
	ULONG CcPinMappedDataCount;
	ULONG CcPinReadNoWait;
	ULONG CcPinReadWait;
	ULONG CcMdlReadNoWait;
	ULONG CcMdlReadWait;
	ULONG CcLazyWriteHotSpots;
	ULONG CcLazyWriteIos;
	ULONG CcLazyWritePages;
	ULONG CcDataFlushes;
	ULONG CcDataPages;
	ULONG CcLostDelayedWrites;
	ULONG CcFastReadResourceMiss;
	ULONG CcCopyReadWaitMiss;
	ULONG CcFastMdlReadResourceMiss;
	ULONG CcMapDataNoWaitMiss;
	ULONG CcMapDataWaitMiss;
	ULONG CcPinReadNoWaitMiss;
	ULONG CcPinReadWaitMiss;
	ULONG CcMdlReadNoWaitMiss;
	ULONG CcMdlReadWaitMiss;
	ULONG CcReadAheadIos;
	ULONG KeAlignmentFixupCount;
	ULONG KeExceptionDispatchCount;
	ULONG KeSystemCalls;
	ULONG PrcbPad1[3];
	PP_LOOKASIDE_LIST PPLookasideList[16];
	GENERAL_LOOKASIDE_POOL PPNPagedLookasideList[32];
	GENERAL_LOOKASIDE_POOL PPPagedLookasideList[32];
	ULONG PacketBarrier;
	LONG ReverseStall;
	PVOID IpiFrame;
	UCHAR PrcbPad2[52];
	PVOID CurrentPacket[3];
	ULONG TargetSet;
	PVOID WorkerRoutine;
	ULONG IpiFrozen;
	UCHAR PrcbPad3[40];
	ULONG RequestSummary;
	_KPRCB* SignalDone;
	UCHAR PrcbPad4[56];
	KDPC_DATA DpcData[2];
	PVOID DpcStack;
	LONG MaximumDpcQueueDepth;
	ULONG DpcRequestRate;
	ULONG MinimumDpcRate;
	UCHAR DpcInterruptRequested;
	UCHAR DpcThreadRequested;
	UCHAR DpcRoutineActive;
	UCHAR DpcThreadActive;
	ULONG PrcbLock;
	ULONG DpcLastCount;
	ULONG TimerHand;
	ULONG TimerRequest;
	PVOID PrcbPad41;
	KEVENT DpcEvent;
	UCHAR ThreadDpcEnable;
	UCHAR QuantumEnd;
	UCHAR PrcbPad50;
	UCHAR IdleSchedule;
	LONG DpcSetEventRequest;
	LONG Sleeping;
	ULONG PeriodicCount;
	ULONG PeriodicBias;
	UCHAR PrcbPad5[6];
	LONG TickOffset;
	KDPC CallDpc;
	LONG ClockKeepAlive;
	UCHAR ClockCheckSlot;
	UCHAR ClockPollCycle;
	UCHAR PrcbPad6[2];
	LONG DpcWatchdogPeriod;
	LONG DpcWatchdogCount;
	LONG ThreadWatchdogPeriod;
	LONG ThreadWatchdogCount;
	ULONG PrcbPad70[2];
	LIST_ENTRY WaitListHead;
	ULONG WaitLock;
	ULONG ReadySummary;
	ULONG QueueIndex;
	SINGLE_LIST_ENTRY DeferredReadyListHead;
	UINT64 StartCycles;
	UINT64 CycleTime;
	UINT64 PrcbPad71[3];
	LIST_ENTRY DispatcherReadyListHead[32];
	PVOID ChainedInterruptList;
	LONG LookasideIrpFloat;
	LONG MmPageFaultCount;
	LONG MmCopyOnWriteCount;
	LONG MmTransitionCount;
	LONG MmCacheTransitionCount;
	LONG MmDemandZeroCount;
	LONG MmPageReadCount;
	LONG MmPageReadIoCount;
	LONG MmCacheReadCount;
	LONG MmCacheIoCount;
	LONG MmDirtyPagesWriteCount;
	LONG MmDirtyWriteIoCount;
	LONG MmMappedPagesWriteCount;
	LONG MmMappedWriteIoCount;
	ULONG CachedCommit;
	ULONG CachedResidentAvailable;
	PVOID HyperPte;
	UCHAR CpuVendor;
	UCHAR PrcbPad9[3];
	UCHAR VendorString[13];
	UCHAR InitialApicId;
	UCHAR CoresPerPhysicalProcessor;
	UCHAR LogicalProcessorsPerPhysicalProcessor;
	ULONG MHz;
	ULONG FeatureBits;
	LARGE_INTEGER UpdateSignature;
	UINT64 IsrTime;
	UINT64 SpareField1;
	FX_SAVE_AREA NpxSaveArea;
	PROCESSOR_POWER_STATE PowerState;
	KDPC DpcWatchdogDpc;
	KTIMER DpcWatchdogTimer;
	PVOID WheaInfo;
	PVOID EtwSupport;
	SLIST_HEADER InterruptObjectPool;
	LARGE_INTEGER HypercallPagePhysical;
	PVOID HypercallPageVirtual;
	PVOID RateControl;
	CACHE_DESCRIPTOR Cache[5];
	ULONG CacheCount;
	ULONG CacheProcessorMask[5];
	UCHAR LogicalProcessorsPerCore;
	UCHAR PrcbPad8[3];
	ULONG PackageProcessorSet;
	ULONG CoreProcessorSet;
} KPRCB, *PKPRCB;

typedef struct _PROCESSOR_POWER_STATE
{
	PVOID IdleFunction;
	PPPM_IDLE_STATES IdleStates;
	UINT64 LastTimeCheck;
	UINT64 LastIdleTime;
	PROCESSOR_IDLE_TIMES IdleTimes;
	PPPM_IDLE_ACCOUNTING IdleAccounting;
	PPPM_PERF_STATES PerfStates;
	ULONG LastKernelUserTime;
	ULONG LastIdleThreadKTime;
	UINT64 LastGlobalTimeHv;
	UINT64 LastProcessorTimeHv;
	UCHAR ThermalConstraint;
	UCHAR LastBusyPercentage;
	BYTE Flags[6];
	KTIMER PerfTimer;
	KDPC PerfDpc;
	ULONG LastSysTime;
	_KPRCB* PStateMaster;
	ULONG PStateSet;
	ULONG CurrentPState;
	ULONG Reserved0;
	ULONG DesiredPState;
	ULONG Reserved1;
	ULONG PStateIdleStartTime;
	ULONG PStateIdleTime;
	ULONG LastPStateIdleTime;
	ULONG PStateStartTime;
	ULONG WmiDispatchPtr;
	LONG WmiInterfaceEnabled;
} PROCESSOR_POWER_STATE, *PPROCESSOR_POWER_STATE;


typedef struct _KTRAP_FRAME
{
	ULONG DbgEbp;
	ULONG DbgEip;
	ULONG DbgArgMark;
	ULONG DbgArgPointer;
	WORD TempSegCs;
	UCHAR Logging;
	UCHAR Reserved;
	ULONG TempEsp;
	ULONG Dr0;
	ULONG Dr1;
	ULONG Dr2;
	ULONG Dr3;
	ULONG Dr6;
	ULONG Dr7;
	ULONG SegGs;
	ULONG SegEs;
	ULONG SegDs;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG PreviousPreviousMode;
	PEXCEPTION_REGISTRATION_RECORD ExceptionList;
	ULONG SegFs;
	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Ebp;
	ULONG ErrCode;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG HardwareEsp;
	ULONG HardwareSegSs;
	ULONG V86Es;
	ULONG V86Ds;
	ULONG V86Fs;
	ULONG V86Gs;
} KTRAP_FRAME, *PKTRAP_FRAME;


typedef struct _KQUEUE
{
	DISPATCHER_HEADER Header;
	LIST_ENTRY EntryListHead;
	ULONG CurrentCount;
	ULONG MaximumCount;
	LIST_ENTRY ThreadListHead;
} KQUEUE, *PKQUEUE;

typedef struct _KGATE
{
	DISPATCHER_HEADER Header;
} KGATE, *PKGATE;

typedef struct _KPROCESS
{
	DISPATCHER_HEADER Header;
	LIST_ENTRY ProfileListHead;
	ULONG DirectoryTableBase;
	ULONG Unused0;
	KGDTENTRY LdtDescriptor;
	KIDTENTRY Int21Descriptor;
	WORD IopmOffset;
	UCHAR Iopl;
	UCHAR Unused;
	ULONG ActiveProcessors;
	ULONG KernelTime;
	ULONG UserTime;
	LIST_ENTRY ReadyListHead;
	SINGLE_LIST_ENTRY SwapListEntry;
	PVOID VdmTrapcHandler;
	LIST_ENTRY ThreadListHead;
	ULONG ProcessLock;
	ULONG Affinity;
	union
	{
		ULONG AutoAlignment : 1;
		ULONG DisableBoost : 1;
		ULONG DisableQuantum : 1;
		ULONG ReservedFlags : 29;
		LONG ProcessFlags;
	};
	CHAR BasePriority;
	CHAR QuantumReset;
	UCHAR State;
	UCHAR ThreadSeed;
	UCHAR PowerState;
	UCHAR IdealNode;
	UCHAR Visited;
	union
	{
		KEXECUTE_OPTIONS Flags;
		UCHAR ExecuteOptions;
	};
	ULONG StackCount;
	LIST_ENTRY ProcessListEntry;
	UINT64 CycleTime;
} KPROCESS, *PKPROCESS;

typedef struct _KAPC_STATE
{
	LIST_ENTRY ApcListHead[2];
	PKPROCESS Process;
	UCHAR KernelApcInProgress;
	UCHAR KernelApcPending;
	UCHAR UserApcPending;
} KAPC_STATE, *PKAPC_STATE;

typedef struct _KTHREAD
{
	DISPATCHER_HEADER Header;
	UINT64 CycleTime;
	ULONG HighCycleTime;
	UINT64 QuantumTarget;
	PVOID InitialStack;
	PVOID StackLimit;
	PVOID KernelStack;
	ULONG ThreadLock;
	union
	{
		KAPC_STATE ApcState;
		UCHAR ApcStateFill[23];
	};
	CHAR Priority;
	WORD NextProcessor;
	WORD DeferredProcessor;
	ULONG ApcQueueLock;
	ULONG ContextSwitches;
	UCHAR State;
	UCHAR NpxState;
	UCHAR WaitIrql;
	CHAR WaitMode;
	LONG WaitStatus;
	union
	{
		PKWAIT_BLOCK WaitBlockList;
		PKGATE GateObject;
	};
	union
	{
		ULONG KernelStackResident : 1;
		ULONG ReadyTransition : 1;
		ULONG ProcessReadyQueue : 1;
		ULONG WaitNext : 1;
		ULONG SystemAffinityActive : 1;
		ULONG Alertable : 1;
		ULONG GdiFlushActive : 1;
		ULONG Reserved : 25;
		LONG MiscFlags;
	};
	UCHAR WaitReason;
	UCHAR SwapBusy;
	UCHAR Alerted[2];
	union
	{
		LIST_ENTRY WaitListEntry;
		SINGLE_LIST_ENTRY SwapListEntry;
	};
	PKQUEUE Queue;
	ULONG WaitTime;
	union
	{
		struct
		{
			SHORT KernelApcDisable;
			SHORT SpecialApcDisable;
		};
		ULONG CombinedApcDisable;
	};
	PVOID Teb;
	union
	{
		KTIMER Timer;
		UCHAR TimerFill[40];
	};
	union
	{
		ULONG AutoAlignment : 1;
		ULONG DisableBoost : 1;
		ULONG EtwStackTraceApc1Inserted : 1;
		ULONG EtwStackTraceApc2Inserted : 1;
		ULONG CycleChargePending : 1;
		ULONG CalloutActive : 1;
		ULONG ApcQueueable : 1;
		ULONG EnableStackSwap : 1;
		ULONG GuiThread : 1;
		ULONG ReservedFlags : 23;
		LONG ThreadFlags;
	};
	union
	{
		KWAIT_BLOCK WaitBlock[4];
		struct
		{
			UCHAR WaitBlockFill0[23];
			UCHAR IdealProcessor;
		};
		struct
		{
			UCHAR WaitBlockFill1[47];
			CHAR PreviousMode;
		};
		struct
		{
			UCHAR WaitBlockFill2[71];
			UCHAR ResourceIndex;
		};
		UCHAR WaitBlockFill3[95];
	};
	UCHAR LargeStack;
	LIST_ENTRY QueueListEntry;
	PKTRAP_FRAME TrapFrame;
	PVOID FirstArgument;
	union
	{
		PVOID CallbackStack;
		ULONG CallbackDepth;
	};
	PVOID ServiceTable;
	UCHAR ApcStateIndex;
	CHAR BasePriority;
	CHAR PriorityDecrement;
	UCHAR Preempted;
	UCHAR AdjustReason;
	CHAR AdjustIncrement;
	UCHAR Spare01;
	CHAR Saturation;
	ULONG SystemCallNumber;
	ULONG Spare02;
	ULONG UserAffinity;
	PKPROCESS Process;
	ULONG Affinity;
	PKAPC_STATE ApcStatePointer[2];
	union
	{
		KAPC_STATE SavedApcState;
		UCHAR SavedApcStateFill[23];
	};
	CHAR FreezeCount;
	CHAR SuspendCount;
	UCHAR UserIdealProcessor;
	UCHAR Spare03;
	UCHAR Iopl;
	PVOID Win32Thread;
	PVOID StackBase;
	union
	{
		KAPC SuspendApc;
		struct
		{
			UCHAR SuspendApcFill0[1];
			CHAR Spare04;
		};
		struct
		{
			UCHAR SuspendApcFill1[3];
			UCHAR QuantumReset;
		};
		struct
		{
			UCHAR SuspendApcFill2[4];
			ULONG KernelTime;
		};
		struct
		{
			UCHAR SuspendApcFill3[36];
			PKPRCB WaitPrcb;
		};
		struct
		{
			UCHAR SuspendApcFill4[40];
			PVOID LegoData;
		};
		UCHAR SuspendApcFill5[47];
	};
	UCHAR PowerState;
	ULONG UserTime;
	union
	{
		KSEMAPHORE SuspendSemaphore;
		UCHAR SuspendSemaphorefill[20];
	};
	ULONG SListFaultCount;
	LIST_ENTRY ThreadListEntry;
	LIST_ENTRY MutantListHead;
	PVOID SListFaultAddress;
	PVOID MdlForLockedTeb;
} KTHREAD, *PKTHREAD;

typedef struct _ETHREAD                                                         // 108 / 111 elements; 0x0480 / 0x0810 Bytes
{
	KTHREAD                     Tcb;                                            // 0x0000 / 0x0000; 0x0350 / 0x05E8 Bytes
	LARGE_INTEGER               CreateTime;                                     // 0x0350 / 0x05E8; 0x0008 / 0x0008 Bytes
	union                                                                       // 2 / 2 elements; 0x0008 / 0x0010 Bytes
	{
		LARGE_INTEGER           ExitTime;                                       // 0x0358 / 0x05F0; 0x0008 / 0x0008 Bytes
		LIST_ENTRY              KeyedWaitChain;                                 // 0x0358 / 0x05F0; 0x0008 / 0x0010 Bytes
	};
	PVOID                       ChargeOnlySession;                              // 0x0360 / 0x0600; 0x0004 / 0x0008 Bytes
	union                                                                       // 2 / 2 elements; 0x0008 / 0x0010 Bytes
	{
		LIST_ENTRY              PostBlockList;                                  // 0x0364 / 0x0608; 0x0008 / 0x0010 Bytes
		struct                                                                  // 2 / 2 elements; 0x0008 / 0x0010 Bytes
		{
			PVOID               ForwardLinkShadow;                              // 0x0364 / 0x0608; 0x0004 / 0x0008 Bytes
			PVOID               StartAddress;                                   // 0x0368 / 0x0610; 0x0004 / 0x0008 Bytes
		};
	};
	union                                                                       // 3 / 3 elements; 0x0004 / 0x0008 Bytes
	{
		PTERMINATION_PORT       TerminationPort;                                // 0x036C / 0x0618; 0x0004 / 0x0008 Bytes
		PETHREAD                ReaperLink;                                     // 0x036C / 0x0618; 0x0004 / 0x0008 Bytes
		PVOID                   KeyedWaitValue;                                 // 0x036C / 0x0618; 0x0004 / 0x0008 Bytes
	};
	UINT_PTR                    ActiveTimerListLock;                            // 0x0370 / 0x0620; 0x0004 / 0x0008 Bytes
	LIST_ENTRY                  ActiveTimerListHead;                            // 0x0374 / 0x0628; 0x0008 / 0x0010 Bytes
	CLIENT_ID                   Cid;                                            // 0x037C / 0x0638; 0x0008 / 0x0010 Bytes
	union                                                                       // 2 / 2 elements; 0x0014 / 0x0020 Bytes
	{
		KSEMAPHORE              KeyedWaitSemaphore;                             // 0x0384 / 0x0648; 0x0014 / 0x0020 Bytes
		KSEMAPHORE              AlpcWaitSemaphore;                              // 0x0384 / 0x0648; 0x0014 / 0x0020 Bytes
	};
	PS_CLIENT_SECURITY_CONTEXT  ClientSecurity;                                 // 0x0398 / 0x0668; 0x0004 / 0x0008 Bytes
	LIST_ENTRY                  IrpList;                                        // 0x039C / 0x0670; 0x0008 / 0x0010 Bytes
	UINT_PTR                    TopLevelIrp;                                    // 0x03A4 / 0x0680; 0x0004 / 0x0008 Bytes
	PDEVICE_OBJECT              DeviceToVerify;                                 // 0x03A8 / 0x0688; 0x0004 / 0x0008 Bytes
	PVOID                       Win32StartAddress;                              // 0x03AC / 0x0690; 0x0004 / 0x0008 Bytes
	PVOID                       LegacyPowerObject;                              // 0x03B0 / 0x0698; 0x0004 / 0x0008 Bytes
	LIST_ENTRY                  ThreadListEntry;                                // 0x03B4 / 0x06A0; 0x0008 / 0x0010 Bytes
	EX_RUNDOWN_REF              RundownProtect;                                 // 0x03BC / 0x06B0; 0x0004 / 0x0008 Bytes
	EX_PUSH_LOCK                ThreadLock;                                     // 0x03C0 / 0x06B8; 0x0004 / 0x0008 Bytes
	ULONG32                     ReadClusterSize;                                // 0x03C4 / 0x06C0; 0x0004 / 0x0004 Bytes
	LONG32                      MmLockOrdering;                                 // 0x03C8 / 0x06C4; 0x0004 / 0x0004 Bytes
	union                                                                       // 2 / 2 elements; 0x0004 / 0x0004 Bytes
	{
		ULONG32                 CrossThreadFlags;                               // 0x03CC / 0x06C8; 0x0004 / 0x0004 Bytes
		struct                                                                  // 19 / 19 elements; 0x0004 / 0x0004 Bytes
		{
			ULONG32             Terminated : 1; // 0x03CC / 0x06C8; Bit:   0
			ULONG32             ThreadInserted : 1; // 0x03CC / 0x06C8; Bit:   1
			ULONG32             HideFromDebugger : 1; // 0x03CC / 0x06C8; Bit:   2
			ULONG32             ActiveImpersonationInfo : 1; // 0x03CC / 0x06C8; Bit:   3
			ULONG32             HardErrorsAreDisabled : 1; // 0x03CC / 0x06C8; Bit:   4
			ULONG32             BreakOnTermination : 1; // 0x03CC / 0x06C8; Bit:   5
			ULONG32             SkipCreationMsg : 1; // 0x03CC / 0x06C8; Bit:   6
			ULONG32             SkipTerminationMsg : 1; // 0x03CC / 0x06C8; Bit:   7
			ULONG32             CopyTokenOnOpen : 1; // 0x03CC / 0x06C8; Bit:   8
			ULONG32             ThreadIoPriority : 3; // 0x03CC / 0x06C8; Bits:  9 - 11
			ULONG32             ThreadPagePriority : 3; // 0x03CC / 0x06C8; Bits: 12 - 14
			ULONG32             RundownFail : 1; // 0x03CC / 0x06C8; Bit:  15
			ULONG32             UmsForceQueueTermination : 1; // 0x03CC / 0x06C8; Bit:  16
			ULONG32             IndirectCpuSets : 1; // 0x03CC / 0x06C8; Bit:  17
			ULONG32             DisableDynamicCodeOptOut : 1; // 0x03CC / 0x06C8; Bit:  18
			ULONG32             ExplicitCaseSensitivity : 1; // 0x03CC / 0x06C8; Bit:  19
			ULONG32             PicoNotifyExit : 1; // 0x03CC / 0x06C8; Bit:  20
			ULONG32             DbgWerUserReportActive : 1; // 0x03CC / 0x06C8; Bit:  21
			ULONG32             ReservedCrossThreadFlags : 10; // 0x03CC / 0x06C8; Bits: 22 - 31
		};
	};
	union                                                                       // 2 / 2 elements; 0x0004 / 0x0004 Bytes
	{
		ULONG32                 SameThreadPassiveFlags;                         // 0x03D0 / 0x06CC; 0x0004 / 0x0004 Bytes
		struct                                                                  // 9 / 9 elements; 0x0004 / 0x0004 Bytes
		{
			ULONG32             ActiveExWorker : 1; // 0x03D0 / 0x06CC; Bit:   0
			ULONG32             MemoryMaker : 1; // 0x03D0 / 0x06CC; Bit:   1
			ULONG32             StoreLockThread : 2; // 0x03D0 / 0x06CC; Bits:  2 -  3
			ULONG32             ClonedThread : 1; // 0x03D0 / 0x06CC; Bit:   4
			ULONG32             KeyedEventInUse : 1; // 0x03D0 / 0x06CC; Bit:   5
			ULONG32             SelfTerminate : 1; // 0x03D0 / 0x06CC; Bit:   6
			ULONG32             RespectIoPriority : 1; // 0x03D0 / 0x06CC; Bit:   7
			ULONG32             ActivePageLists : 1; // 0x03D0 / 0x06CC; Bit:   8
			ULONG32             ReservedSameThreadPassiveFlags : 23; // 0x03D0 / 0x06CC; Bits:  9 - 31
		};
	};
	union                                                                       // 2 / 2 elements; 0x0004 / 0x0004 Bytes
	{
		ULONG32                 SameThreadApcFlags;                             // 0x03D4 / 0x06D0; 0x0004 / 0x0004 Bytes
		struct                                                                  // 2 / 2 elements; 0x0002 / 0x0002 Bytes
		{
			struct                                                              // 8 / 8 elements; 0x0001 / 0x0001 Bytes
			{
				UINT8           OwnsProcessAddressSpaceExclusive : 1; // 0x03D4 / 0x06D0; Bit:   0
				UINT8           OwnsProcessAddressSpaceShared : 1; // 0x03D4 / 0x06D0; Bit:   1
				UINT8           HardFaultBehavior : 1; // 0x03D4 / 0x06D0; Bit:   2
				UINT8           StartAddressInvalid : 1; // 0x03D4 / 0x06D0; Bit:   3
				UINT8           EtwCalloutActive : 1; // 0x03D4 / 0x06D0; Bit:   4
				UINT8           SuppressSymbolLoad : 1; // 0x03D4 / 0x06D0; Bit:   5
				UINT8           Prefetching : 1; // 0x03D4 / 0x06D0; Bit:   6
				UINT8           OwnsVadExclusive : 1; // 0x03D4 / 0x06D0; Bit:   7
			};
			struct                                                              // 2 / 2 elements; 0x0001 / 0x0001 Bytes
			{
				UINT8           SystemPagePriorityActive : 1; // 0x03D5 / 0x06D1; Bit:   0
				UINT8           SystemPagePriority : 3; // 0x03D5 / 0x06D1; Bits:  1 -  3
			};
		};
	};
	UINT8                       CacheManagerActive;                             // 0x03D8 / 0x06D4; 0x0001 / 0x0001 Bytes
	UINT8                       DisablePageFaultClustering;                     // 0x03D9 / 0x06D5; 0x0001 / 0x0001 Bytes
	UINT8                       ActiveFaultCount;                               // 0x03DA / 0x06D6; 0x0001 / 0x0001 Bytes
	UINT8                       LockOrderState;                                 // 0x03DB / 0x06D7; 0x0001 / 0x0001 Bytes
	UINT_PTR                    AlpcMessageId;                                  // 0x03DC / 0x06D8; 0x0004 / 0x0008 Bytes
	union                                                                       // 2 / 2 elements; 0x0004 / 0x0008 Bytes
	{
		PVOID                   AlpcMessage;                                    // 0x03E0 / 0x06E0; 0x0004 / 0x0008 Bytes
		ULONG32                 AlpcReceiveAttributeSet;                        // 0x03E0 / 0x06E0; 0x0004 / 0x0004 Bytes
	};
	LIST_ENTRY                  AlpcWaitListEntry;                              // 0x03E4 / 0x06E8; 0x0008 / 0x0010 Bytes
	LONG32                      ExitStatus;                                     // 0x03EC / 0x06F8; 0x0004 / 0x0004 Bytes
	ULONG32                     CacheManagerCount;                              // 0x03F0 / 0x06FC; 0x0004 / 0x0004 Bytes
	ULONG32                     IoBoostCount;                                   // 0x03F4 / 0x0700; 0x0004 / 0x0004 Bytes
	ULONG32                     IoQoSBoostCount;                                // 0x03F8 / 0x0704; 0x0004 / 0x0004 Bytes
	ULONG32                     IoQoSThrottleCount;                             // 0x03FC / 0x0708; 0x0004 / 0x0004 Bytes
#if defined(_M_X64)
	UINT8                       _PADDING0_[4];                                  // ------ / 0x070C; ------ / 0x0004 Bytes
#endif                                                                          // #if defined(_M_X64)
	LIST_ENTRY                  BoostList;                                      // 0x0400 / 0x0710; 0x0008 / 0x0010 Bytes
	LIST_ENTRY                  DeboostList;                                    // 0x0408 / 0x0720; 0x0008 / 0x0010 Bytes
	UINT_PTR                    BoostListLock;                                  // 0x0410 / 0x0730; 0x0004 / 0x0008 Bytes
	UINT_PTR                    IrpListLock;                                    // 0x0414 / 0x0738; 0x0004 / 0x0008 Bytes
	PVOID                       ReservedForSynchTracking;                       // 0x0418 / 0x0740; 0x0004 / 0x0008 Bytes
	SINGLE_LIST_ENTRY           CmCallbackListHead;                             // 0x041C / 0x0748; 0x0004 / 0x0008 Bytes
	PVOID                       ActivityId;                                     // 0x0420 / 0x0750; 0x0004 / 0x0008 Bytes
	SINGLE_LIST_ENTRY           SeLearningModeListHead;                         // 0x0424 / 0x0758; 0x0004 / 0x0008 Bytes
	PVOID                       VerifierContext;                                // 0x0428 / 0x0760; 0x0004 / 0x0008 Bytes
	ULONG32                     KernelStackReference;                           // 0x042C / 0x0768; 0x0004 / 0x0004 Bytes
#if defined(_M_X64)
	UINT8                       _PADDING1_[4];                                  // ------ / 0x076C; ------ / 0x0004 Bytes
#endif                                                                          // #if defined(_M_X64)
	PVOID                       AdjustedClientToken;                            // 0x0430 / 0x0770; 0x0004 / 0x0008 Bytes
	PVOID                       WorkOnBehalfThread;                             // 0x0434 / 0x0778; 0x0004 / 0x0008 Bytes
	CHAR						PropertySet[0x18];                                    // 0x0438 / 0x0780; 0x000C / 0x0018 Bytes
	PVOID                       PicoContext;                                    // 0x0444 / 0x0798; 0x0004 / 0x0008 Bytes
	UINT_PTR                    UserFsBase;                                     // 0x0448 / 0x07A0; 0x0004 / 0x0008 Bytes
	UINT_PTR                    UserGsBase;                                     // 0x044C / 0x07A8; 0x0004 / 0x0008 Bytes
	PVOID       EnergyValues;                                   // 0x0450 / 0x07B0; 0x0004 / 0x0008 Bytes
	PVOID                       CmDbgInfo;                                      // 0x0454 / 0x07B8; 0x0004 / 0x0008 Bytes
	union                                                                       // 2 / 2 elements; 0x0004 / 0x0008 Bytes
	{
		UINT_PTR                SelectedCpuSets;                                // 0x0458 / 0x07C0; 0x0004 / 0x0008 Bytes
		UINT_PTR *              SelectedCpuSetsIndirect;                        // 0x0458 / 0x07C0; 0x0004 / 0x0008 Bytes
	};
	PVOID                       Silo;                                           // 0x045C / 0x07C8; 0x0004 / 0x0008 Bytes
	PUNICODE_STRING             ThreadName;                                     // 0x0460 / 0x07D0; 0x0004 / 0x0008 Bytes
#if defined(_M_X64)
	PCONTEXT                    SetContextState;                                // ------ / 0x07D8; ------ / 0x0008 Bytes
#endif                                                                          // #if defined(_M_X64)
	ULONG32                     LastExpectedRunTime;                            // 0x0464 / 0x07E0; 0x0004 / 0x0004 Bytes
#if defined(_M_X64)
	UINT8                       _PADDING2_[4];                                  // ------ / 0x07E4; ------ / 0x0004 Bytes
#endif                                                                          // #if defined(_M_X64)
	LIST_ENTRY                  OwnerEntryListHead;                             // 0x0468 / 0x07E8; 0x0008 / 0x0010 Bytes
	UINT_PTR                    DisownedOwnerEntryListLock;                     // 0x0470 / 0x07F8; 0x0004 / 0x0008 Bytes
	LIST_ENTRY                  DisownedOwnerEntryListHead;                     // 0x0474 / 0x0800; 0x0008 / 0x0010 Bytes
#if !defined(_M_X64)
	UINT8                       _PADDING0_[4];                                  // 0x047C / ------; 0x0004 / ------ Bytes
#endif                                                                          // #if !defined(_M_X64)
} ETHREAD, *PETHREAD;