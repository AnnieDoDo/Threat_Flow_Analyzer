#ifndef BPF_GEN_STRUCT_H
#define BPF_GEN_STRUCT_H
#include <linux/filter.h>

struct sock_filter code[] = {
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 24, 0x000086dd },
{ 0x30, 0, 0, 0x00000014 },
{ 0x15, 2, 0, 0x00000084 },
{ 0x15, 1, 0, 0x00000006 },
{ 0x15, 0, 4, 0x00000011 },
{ 0x28, 0, 0, 0x00000036 },
{ 0x15, 51, 0, 0x00000016 },
{ 0x28, 0, 0, 0x00000038 },
{ 0x15, 49, 0, 0x00000016 },
{ 0x20, 0, 0, 0x00000026 },
{ 0x15, 0, 6, 0x00000000 },
{ 0x20, 0, 0, 0x0000002a },
{ 0x15, 0, 4, 0x00000000 },
{ 0x20, 0, 0, 0x0000002e },
{ 0x15, 0, 2, 0x00000000 },
{ 0x20, 0, 0, 0x00000032 },
{ 0x15, 41, 0, 0x00000001 },
{ 0x20, 0, 0, 0x00000016 },
{ 0x15, 0, 31, 0x00000000 },
{ 0x20, 0, 0, 0x0000001a },
{ 0x15, 0, 29, 0x00000000 },
{ 0x20, 0, 0, 0x0000001e },
{ 0x15, 0, 27, 0x00000000 },
{ 0x20, 0, 0, 0x00000022 },
{ 0x15, 33, 25, 0x00000001 },
{ 0x15, 0, 16, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 2, 0, 0x00000084 },
{ 0x15, 1, 0, 0x00000006 },
{ 0x15, 0, 7, 0x00000011 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 5, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x0000000e },
{ 0x15, 23, 0, 0x00000016 },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 21, 0, 0x00000016 },
{ 0x20, 0, 0, 0x0000001e },
{ 0x15, 19, 0, 0x7f000001 },
{ 0x15, 18, 0, 0x00000000 },
{ 0x20, 0, 0, 0x0000001a },
{ 0x15, 16, 7, 0x7f000001 },
{ 0x15, 1, 0, 0x00000806 },
{ 0x15, 0, 6, 0x00008035 },
{ 0x20, 0, 0, 0x00000026 },
{ 0x15, 12, 0, 0x7f000001 },
{ 0x15, 11, 0, 0x00000000 },
{ 0x20, 0, 0, 0x0000001c },
{ 0x15, 9, 0, 0x7f000001 },
{ 0x15, 8, 0, 0x00000000 },
{ 0x20, 0, 0, 0x00000008 },
{ 0x15, 0, 2, 0x012f1711 },
{ 0x28, 0, 0, 0x00000006 },
{ 0x15, 4, 0, 0x0000e45f },
{ 0x20, 0, 0, 0x00000002 },
{ 0x15, 0, 3, 0x012f1711 },
{ 0x28, 0, 0, 0x00000000 },
{ 0x15, 0, 1, 0x0000e45f },
{ 0x6, 0, 0, 0x00000000 },
{ 0x6, 0, 0, 0x00040000 },
};

#endif // BPF_GEN_STRUCT_H
