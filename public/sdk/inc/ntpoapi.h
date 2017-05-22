/*++ BUILD Version: 0001    // Increment this if a change has global effects

Copyright (c) 1995  Microsoft Corporation

Module Name:

    ntpoapi.h

Abstract:

    This module contains the user APIs for the NT Power Management.

Author:

Revision History:

--*/

#ifndef _NTPOAPI_
#define _NTPOAPI_

#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4201) // nameless struct/union
#pragma warning(disable:4214) // bit field types other than int


#ifdef __cplusplus
extern "C" {
#endif
//
// Power Management user APIs
//

// begin_ntddk begin_ntifs begin_nthal begin_ntminiport

typedef enum _POWER_STATES {
    PowerUnspecified = 0,
    PowerUp,
    PowerQuery,
    PowerStandby,
    PowerSuspend,
    PowerHibernate,
    PowerDown,
    PowerDownRemove,
    MaximumPowerState
} POWER_STATE, *PPOWER_STATE;

// end_ntddk end_nthal end_ntifs end_ntminiport

NTSYSAPI
NTSTATUS
NTAPI
NtSetSystemPowerState(
    IN POWER_STATE SystemPowerState,
    IN BOOLEAN NoResumeAlarm,
    IN BOOLEAN ForcePowerDown
    );

// begin_ntddk begin_nthal begin_ntminiport

typedef enum {
    BatteryCurrent,
    BatteryCycleCount,
    BatteryDesignedChargeCapacity,
    BatteryDeviceChemistry,
    BatteryDeviceName,
    BatteryFullChargeCapacity,
    BatteryManufactureData,
    BatteryManufactureName,
    BatteryReportingUnits,
    BatteryRemainingCapacity,
    BatterySerialNumber,
    BatterySuppliesSystemPower,
    BatteryVoltage
} BatteryInformationLevel, *PBatterInformationLevel;

typedef struct _BATTERY_CHARGE_WAIT {
    ULONG       BatteryTag;
    BOOLEAN     ACOnLine;
    BOOLEAN     StatusCharging;
    BOOLEAN     StatusDischarging;
    ULONG       LowChargeMark;
    ULONG       HighChargeMark;
} BATTERY_CHARGE_WAIT, *PBATTERY_CHARGE_WAIT;

typedef struct _BATTERY_CHARGE {
    ULONG       BatteryTag;
    BOOLEAN     ACOnLine;
    BOOLEAN     StatusCharging;
    BOOLEAN     StatusDischarging;
    ULONG       EstimatedCharge;
} BATTERY_CHARGE, *PBATTERY_CHARGE;


//
// Power management IOCTLs
//

#define IOCTL_SET_RESUME    \
        CTL_CODE(FILE_DEVICE_BATTERY, 0, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_POWER_DOWN    \
        CTL_CODE(FILE_DEVICE_BATTERY, 1, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_BATTERY_QUERY_INFORMATION   \
        CTL_CODE(FILE_DEVICE_BATTERY, 2, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_BATTERY_CHARGE_STATUS       \
        CTL_CODE(FILE_DEVICE_BATTERY, 3, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_BATTERY_SET_RESUME          \
        CTL_CODE(FILE_DEVICE_BATTERY, 4, METHOD_BUFFERED, FILE_READ_ACCESS)

// end_ntddk end_nthal end_ntminiport

// WinLogonFlags:
#define WINLOGON_LOCK_ON_SLEEP  0x00000001

// begin_winnt
/*
typedef struct {
    // Misc supported system features
    BOOLEAN             PowerButtonPresent;
    BOOLEAN             SleepButtonPresent;
    BOOLEAN             LidPresent;
    BOOLEAN             SystemS1;
    BOOLEAN             SystemS2;
    BOOLEAN             SystemS3;
    BOOLEAN             SystemS4;           // hibernate
    BOOLEAN             SystemS5;           // off
    BOOLEAN             HiberFilePresent;
    BOOLEAN             FullWake;
    BOOLEAN             VideoDimPresent;
    BOOLEAN             ApmPresent;
    BOOLEAN             UpsPresent;

    // Processors
    BOOLEAN             ThermalControl;
    BOOLEAN             ProcessorThrottle;
    UCHAR               ProcessorMinThrottle;

#if (NTDDI_VERSION < NTDDI_WINXP)
    UCHAR               ProcessorThrottleScale;
    UCHAR               spare2[4];
#else
    UCHAR               ProcessorMaxThrottle;
    BOOLEAN             FastSystemS4;
    UCHAR               spare2[3];
#endif // (NTDDI_VERSION < NTDDI_WINXP)

    // Disk
    BOOLEAN             DiskSpinDown;
    UCHAR               spare3[8];

    // System Battery
    BOOLEAN             SystemBatteriesPresent;
    BOOLEAN             BatteriesAreShortTerm;
    BATTERY_REPORTING_SCALE BatteryScale[3];

    // Wake
    SYSTEM_POWER_STATE  AcOnLineWake;
    SYSTEM_POWER_STATE  SoftLidWake;
    SYSTEM_POWER_STATE  RtcWake;
    SYSTEM_POWER_STATE  MinDeviceWakeState; // note this may change on driver load
    SYSTEM_POWER_STATE  DefaultLowLatencyWake;
} SYSTEM_POWER_CAPABILITIES, *PSYSTEM_POWER_CAPABILITIES;
*/
typedef struct {
    BOOLEAN             AcOnLine;
    BOOLEAN             BatteryPresent;
    BOOLEAN             Charging;
    BOOLEAN             Discharging;
    BOOLEAN             Spare1[4];

    ULONG               MaxCapacity;
    ULONG               RemainingCapacity;
    ULONG               Rate;
    ULONG               EstimatedTime;

    ULONG               DefaultAlert1;
    ULONG               DefaultAlert2;
} SYSTEM_BATTERY_STATE, *PSYSTEM_BATTERY_STATE;

// end_winnt

typedef struct {
    ULONG64 StartTime;
    ULONG64 EndTime;
    ULONG Reserved[4];
} PROCESSOR_IDLE_TIMES, *PPROCESSOR_IDLE_TIMES;

__drv_functionClass(PROCESSOR_IDLE_HANDLER)
typedef
NTSTATUS
(FASTCALL PROCESSOR_IDLE_HANDLER) (
    __in ULONG_PTR Context,
    __inout PPROCESSOR_IDLE_TIMES IdleTimes
    );

typedef PROCESSOR_IDLE_HANDLER *PPROCESSOR_IDLE_HANDLER;

//
// valid flags for SYSTEM_POWER_STATE_DISABLE_REASON.PowerReasonCode
//
#define SPSD_REASON_NONE                        0x00000000
#define SPSD_REASON_NOBIOSSUPPORT               0x00000001
#define SPSD_REASON_BIOSINCOMPATIBLE            0x00000002
#define SPSD_REASON_NOOSPM                      0x00000003
#define SPSD_REASON_LEGACYDRIVER                0x00000004
#define SPSD_REASON_HIBERSTACK                  0x00000005
#define SPSD_REASON_HIBERFILE                   0x00000006
#define SPSD_REASON_POINTERNAL                  0x00000007
#define SPSD_REASON_MEMORYLIMIT                 0x00000008
#define SPSD_REASON_MPOVERRIDE                  0x00000009
#define SPSD_REASON_DRIVERDOWNGRADE             0x0000000A
#define SPSD_REASON_PREVIOUSATTEMPTFAILED       0x0000000B
#define SPSD_REASON_UNKNOWN                     0x0000000C
#define SPSD_REASON_INTERNALLYDISABLED          0x0000000D
#define SPSD_REASON_DISABLEDBYPOLICY            0x0000000E
#define SPSD_REASON_UPGRADEINPROGRESS           0x0000000F

#define POWER_STATE_HANDLER_TYPE_MAX 8

__struct_bcount(sizeof(SYSTEM_POWER_STATE_DISABLE_REASON) + PowerReasonLength)
typedef struct _SYSTEM_POWER_STATE_DISABLE_REASON {
    BOOLEAN AffectedState[POWER_STATE_HANDLER_TYPE_MAX];
    ULONG PowerReasonCode;
    ULONG PowerReasonLength;
    //UCHAR PowerReasonInfo[ANYSIZE_ARRAY];
} SYSTEM_POWER_STATE_DISABLE_REASON, *PSYSTEM_POWER_STATE_DISABLE_REASON;

//
// valid flags for SYSTEM_POWER_LOGGING_ENTRY.LoggingType
//
#define LOGGING_TYPE_SPSD                       0x00000001
#define LOGGING_TYPE_POWERTRANSITION            0x00000002

typedef struct _SYSTEM_POWER_LOGGING_ENTRY {
        ULONG LoggingType;
        PVOID LoggingEntry;
} SYSTEM_POWER_LOGGING_ENTRY, *PSYSTEM_POWER_LOGGING_ENTRY;

#if (NTDDI_VERSION < NTDDI_WINXP) // win2k only

//
// Power structure in each processors PRCB
//
struct _PROCESSOR_POWER_STATE;      // forward ref

__drv_functionClass(PROCESSOR_IDLE_FUNCTION)
typedef
VOID
(FASTCALL PROCESSOR_IDLE_FUNCTION) (
    __inout struct _PROCESSOR_POWER_STATE   *PState
    );

typedef PROCESSOR_IDLE_FUNCTION *PPROCESSOR_IDLE_FUNCTION;

typedef struct _PROCESSOR_POWER_STATE {
    PPROCESSOR_IDLE_FUNCTION    IdleFunction;
    ULONG                       Idle0KernelTimeLimit;
    ULONG                       Idle0LastTime;

    PVOID                       IdleState;
    ULONGLONG                   LastCheck;
    PROCESSOR_IDLE_TIMES        IdleTimes;

    ULONG                       IdleTime1;
    ULONG                       PromotionCheck;
    ULONG                       IdleTime2;

    UCHAR                       CurrentThrottle;    // current throttle setting
    UCHAR                       ThrottleLimit;      // max available throttle setting
    UCHAR                       Spare1[2];

    ULONG                       SetMember;
    PVOID                       AbortThrottle;

// temp for debugging
    ULONGLONG                   DebugDelta;
    ULONG                       DebugCount;

    ULONG                       LastSysTime;
    ULONG                       Spare2[10];

    
} PROCESSOR_POWER_STATE, *PPROCESSOR_POWER_STATE;

#endif // (NTDDI_VERSION < NTDDI_WINXP)

typedef struct _PROCESSOR_POWER_INFORMATION {
    ULONG                   Number;
    ULONG                   MaxMhz;
    ULONG                   CurrentMhz;
    ULONG                   MhzLimit;
    ULONG                   MaxIdleState;
    ULONG                   CurrentIdleState;
} PROCESSOR_POWER_INFORMATION, *PPROCESSOR_POWER_INFORMATION;
/*
typedef struct _SYSTEM_POWER_INFORMATION {
    ULONG                   MaxIdlenessAllowed;
    ULONG                   Idleness;
    ULONG                   TimeRemaining;
    UCHAR                   CoolingMode;
} SYSTEM_POWER_INFORMATION, *PSYSTEM_POWER_INFORMATION;
*/
// end_nthal

typedef struct _SYSTEM_HIBERFILE_INFORMATION {
    ULONG NumberOfMcbPairs;
    LARGE_INTEGER Mcb[1];
} SYSTEM_HIBERFILE_INFORMATION, *PSYSTEM_HIBERFILE_INFORMATION;


// Wake source tracking
//

typedef enum {
    DeviceWakeSourceType,
    FixedWakeSourceType,
    TimerWakeSourceType
} PO_WAKE_SOURCE_TYPE, *PPO_WAKE_SOURCE_TYPE;

typedef enum {
    FixedWakeSourcePowerButton,
    FixedWakeSourceSleepButton,
    FixedWakeSourceRtc,
    FixedWakeSourceDozeToHibernate
} PO_FIXED_WAKE_SOURCE_TYPE, *PPO_FIXED_WAKE_SOURCE_TYPE;

typedef struct _PO_WAKE_SOURCE_HEADER {
    PO_WAKE_SOURCE_TYPE Type;
    ULONG Size;
} PO_WAKE_SOURCE_HEADER, *PPO_WAKE_SOURCE_HEADER;

typedef struct _PO_WAKE_SOURCE_DEVICE {
    PO_WAKE_SOURCE_HEADER Header;
    WCHAR InstancePath[ANYSIZE_ARRAY];
} PO_WAKE_SOURCE_DEVICE, *PPO_WAKE_SOURCE_DEVICE;

typedef struct _PO_WAKE_SOURCE_FIXED {
    PO_WAKE_SOURCE_HEADER Header;
    PO_FIXED_WAKE_SOURCE_TYPE FixedWakeSourceType;
} PO_WAKE_SOURCE_FIXED, *PPO_WAKE_SOURCE_FIXED;

typedef struct _PO_WAKE_SOURCE_INFO {
    ULONG Count;
    ULONG Offsets[ANYSIZE_ARRAY];
} PO_WAKE_SOURCE_INFO, *PPO_WAKE_SOURCE_INFO;

typedef struct _PO_WAKE_SOURCE_HISTORY {
    ULONG Count;
    ULONG Offsets[ANYSIZE_ARRAY];
} PO_WAKE_SOURCE_HISTORY, *PPO_WAKE_SOURCE_HISTORY;

#ifdef __cplusplus
}
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning(default:4201)
#pragma warning(default:4214)
#endif
#endif // _NTPOAPI_

