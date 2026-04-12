#include <stdint.h>

#pragma pack(push, 1)
typedef struct _ipheader
{
    uint8_t version_ihl;
    uint8_t DSCP_ECN;
    uint16_t Total_Length;
    uint16_t Identification;
    uint16_t Flags_Offset;
    uint8_t TTL;
    uint8_t Protocol;
    uint16_t Checksum;
    uint32_t SrcIP;
    uint32_t DstIP;
    
}ipheader;
#pragma pack(pop)