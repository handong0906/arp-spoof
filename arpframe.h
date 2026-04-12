#pragma pack(push, 1)
typedef struct _arpframe
{
    uint16_t Hardware_Type;
    uint16_t Protocol;
    uint8_t Hardware_Length;
    uint8_t Protocol_Length;
    uint16_t Operation;
    unsigned char Sender_MAC[6];
    uint32_t Sender_Protocol_Addr;
    unsigned char Target_MAC[6];
    uint32_t Target_Protocol_Addr;
}arpframe;
#pragma pack(pop)
