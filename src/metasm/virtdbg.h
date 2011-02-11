
typedef unsigned long ULONG;
typedef ULONG *PULONG;
typedef unsigned short USHORT;
typedef USHORT *PUSHORT;
typedef unsigned char UCHAR;
typedef UCHAR *PUCHAR;
typedef char *PSZ;

typedef char CHAR;
typedef short SHORT;
typedef long LONG;
typedef int INT;
typedef SHORT *PSHORT;  // winnt
typedef LONG *PLONG;    // winnt

typedef __int64 LONGLONG;
typedef unsigned __int64 ULONGLONG;
typedef void *PVOID;

typedef signed char         INT8, *PINT8;
typedef signed short        INT16, *PINT16;
typedef signed int          INT32, *PINT32;
typedef signed __int64      INT64, *PINT64;
typedef unsigned char       UINT8, *PUINT8;
typedef unsigned short      UINT16, *PUINT16;
typedef unsigned int        UINT32, *PUINT32;
typedef unsigned __int64    UINT64, *PUINT64;

typedef signed int LONG32, *PLONG32;
typedef unsigned int ULONG32, *PULONG32;

typedef __int64 LONG64, *PLONG64;
typedef unsigned __int64 ULONG64, *PULONG64;
typedef unsigned __int64 DWORD64, *PDWORD64;

typedef struct _LARGE_INTEGER_unnamed1 {
    ULONG32 LowPart;
    LONG32 HighPart;
} LARGE_INTEGER_unnamed1;

typedef union _LARGE_INTEGER {
    LARGE_INTEGER_unnamed1 u;
    LONG64 QuadPart;
} LARGE_INTEGER;

typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

typedef struct _VIRTDBG_CONTROL_AREA
{
    ULONG32 Magic1;
    ULONG32 Magic2;
    PHYSICAL_ADDRESS SendArea;
    PHYSICAL_ADDRESS RecvArea;
    PVOID KernelBase;
    PVOID DebuggerData;
    PVOID LogBuffer;
    ULONG32 ClientId;
    ULONG32 ServerId;
} VIRTDBG_CONTROL_AREA, *PVIRTDBG_CONTROL_AREA;

#define CONTROL_AREA_SIZE 0x1000
#define CONTROL_AREA_MAGIC1 0xbabebabe
#define CONTROL_AREA_MAGIC2 0xcafecafe

typedef struct _PACKET_HEADER {
    ULONG32 Magic;
    ULONG32 Type;
    ULONG32 Size;
    ULONG32 Id;
    ULONG32 ClientId;
    ULONG32 Checksum;
} PACKET_HEADER, *PPACKET_HEADER;

typedef struct _BREAKIN_PACKET {
    ULONG64 Cr3;
} BREAKIN_PACKET, *PBREAKIN_PACKET;

#define CONTINUE_STATUS_SINGLE_STEP 0x1
#define CONTINUE_STATUS_UNLOAD 0x2

typedef struct _CONTINUE_PACKET {
    ULONG32 Status;
} CONTINUE_PACKET, *PCONTINUE_PACKET;

typedef struct _SOFTWARE_BREAKPOINT_PACKET {
    ULONG64 Address;
} SOFTWARE_BREAKPOINT_PACKET, *PSOFTWARE_BREAKPOINT_PACKET;

typedef struct _HARDWARE_BREAKPOINT_PACKET {
    ULONG64 Address;
} HARDWARE_BREAKPOINT_PACKET, *PHARDWARE_BREAKPOINT_PACKET;

typedef struct _MEMORY_BREAKPOINT_PACKET {
    ULONG64 Address;
} MEMORY_BREAKPOINT_PACKET, *PMEMORY_BREAKPOINT_PACKET;

typedef struct _STATE_CHANGE_PACKET {
    ULONG32 Exception;
    ULONG64 Address;
} STATE_CHANGE_PACKET, *PSTATE_CHANGE_PACKET;

typedef struct _READ_VIRTUAL_MEMORY_PACKET {
    ULONG64 Address;
    ULONG32 Size;
} READ_VIRTUAL_MEMORY_PACKET, *PREAD_VIRTUAL_MEMORY_PACKET;

typedef struct _WRITE_VIRTUAL_MEMORY_PACKET {
    ULONG64 Address;
    ULONG32 Size;
} WRITE_VIRTUAL_MEMORY_PACKET, *PWRITE_VIRTUAL_MEMORY_PACKET;

typedef struct _READ_PHYSICAL_MEMORY_PACKET {
    ULONG64 Address;
    ULONG32 Size;
} READ_PHYSICAL_MEMORY_PACKET, *PREAD_PHYSICAL_MEMORY_PACKET;

typedef struct _WRITE_PHYSICAL_MEMORY_PACKET {
    ULONG64 Address;
    ULONG32 Size;
} WRITE_PHYSICAL_MEMORY_PACKET, *PWRITE_PHYSICAL_MEMORY_PACKET;

typedef struct _DEBUG_CONTEXT {
    ULONG64 rax;
    ULONG64 rbx;
    ULONG64 rcx;
    ULONG64 rdx;
    ULONG64 rsi;
    ULONG64 rdi;
    ULONG64 rbp;
    ULONG64 rsp;
    ULONG64 r8;
    ULONG64 r9;
    ULONG64 r10;
    ULONG64 r11;
    ULONG64 r12;
    ULONG64 r13;
    ULONG64 r14;
    ULONG64 r15;
    ULONG64 rip;
    ULONG64 rflags;
    ULONG64 cr0;
    ULONG64 cr3;
    ULONG64 cr4;
    ULONG64 cr8;
    ULONG64 dr0;
    ULONG64 dr1;
    ULONG64 dr2;
    ULONG64 dr3;
    ULONG64 dr6;
    ULONG64 dr7;
    USHORT cs;
    USHORT ds;
    USHORT es;
    USHORT fs;
    USHORT ss;
    USHORT gs;
} DEBUG_CONTEXT, *PDEBUG_CONTEXT;

typedef struct _GET_CONTEXT_PACKET {
    ULONG32 Flags;
} GET_CONTEXT_PACKET, *PGET_CONTEXT_PACKET;

typedef struct _SET_CONTEXT_PACKET {
    ULONG32 Flags;
} SET_CONTEXT_PACKET, *PSET_CONTEXT_PACKET;

typedef struct _MANIPULATE_STATE_PACKET {
    ULONG32 ApiNumber;
    ULONG32 Error;
    union {
        READ_VIRTUAL_MEMORY_PACKET ReadVirtualMemory;
        WRITE_VIRTUAL_MEMORY_PACKET WriteVirtualMemory;
        READ_PHYSICAL_MEMORY_PACKET ReadPhysicalMemory;
        WRITE_PHYSICAL_MEMORY_PACKET WritePhysicalMemory;
        GET_CONTEXT_PACKET GetContext;
        SET_CONTEXT_PACKET SetContext;
    } u;
} MANIPULATE_STATE_PACKET, *PMANIPULATE_STATE_PACKET;

#define PACKET_TYPE_RESET 1
#define PACKET_TYPE_BREAKIN 2
#define PACKET_TYPE_ACK 3
#define PACKET_TYPE_RESEND 4
#define PACKET_TYPE_STATE_CHANGE 5
#define PACKET_TYPE_MANIPULATE_STATE 6
#define PACKET_TYPE_CONTINUE 7

#define READ_VIRTUAL_MEMORY_API 0x41
#define WRITE_VIRTUAL_MEMORY_API 0x42
#define GET_CONTEXT_API 0x43
#define SET_CONTEXT_API 0x44

#define INITIAL_ID 0x41424344
#define PACKET_MAGIC 0xdeadbabe

#define MAX_PACKET_SIZE 0x800

#define MAX_RETRIES 0x1000000
#define HEADER_SIZE sizeof(PACKET_HEADER)


