#pragma pack(push, 1)
typedef struct _ethheader
{
    unsigned char ether_dstMAC[6];
    unsigned char ether_srcMAC[6];
    uint16_t ether_next_type;
}ethheader;
#pragma pack(pop)
