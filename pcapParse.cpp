#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include "HttpParse.h"
#include "HttpsParse.h"


#pragma pack(1)
//pacp文件头结构体
struct pcap_file_header
{
    uint32_t magic;       /* 0xa1b2c3d4 */
    uint16_t version_major;   /* magjor Version 2 */
    uint16_t version_minor;   /* magjor Version 4 */
    uint32_t thiszone;      /* gmt to local correction */
    uint32_t sigfigs;     /* accuracy of timestamps */
    uint32_t snaplen;     /* max length saved portion of each pkt */
    uint32_t linktype;    /* data link type (LINKTYPE_*) */
};

//时间戳
struct time_val
{
    int tv_sec;         /* seconds 含义同 time_t 对象的值 */
    int tv_usec;        /* and microseconds */
};

//pcap数据包头结构体
struct pcap_pkthdr
{
    struct time_val ts;  /* time stamp */
    uint32_t caplen; /* length of portion present */
    uint32_t len;    /* length this packet (off wire) */
};

// ethnet协议头
struct EthnetHeader_t 
{
    unsigned char srcMac[6];
    unsigned char dstMac[6];
    uint16_t protoType;
};

//IP数据报头 20字节
struct IPHeader_t
{
    uint8_t Ver_HLen;       //版本+报头长度
    uint8_t TOS;            //服务类型
    uint16_t TotalLen;       //总长度
    uint16_t ID; //标识
    uint16_t Flag_Segment;   //标志+片偏移
    uint8_t TTL;            //生存周期
    uint8_t Protocol;       //协议类型
    uint16_t Checksum;       //头部校验和
    uint32_t SrcIP; //源IP地址
    uint32_t DstIP; //目的IP地址
};

struct IPV6Header_t
{
    uint32_t Ver_FL;       //版本+流标号
    uint16_t TotalLen;       //总长度
    uint8_t NHead;       //下一个首部
    uint8_t HopL;       //跳数限制
    uint32_t SrcIP0; //源IP地址
    uint32_t SrcIP1; 
    uint32_t SrcIP2; 
    uint32_t SrcIP3; 
    uint32_t DstIP0; //目的IP地址
    uint32_t DstIP1;
    uint32_t DstIP2;
    uint32_t DstIP3;
};

// UDP头 (8字节)
struct UDPHeader_t
{
    uint16_t SrcPort;    // 源端口号16bit
    uint16_t DstPort;    // 目的端口号16bit
    uint16_t Length;     // 长度
    uint16_t CheckSum;   // 校验码
};

// TCP头 (20字节)
struct TCPHeader_t 
{
    uint16_t srcPort;          // 源端口
    uint16_t dstPort;          // 目的端口
    uint32_t SeqNo;            // 序列号
    uint32_t AckNo;            // 确认号
    uint16_t headAndFlags;     // 首部长度即标志位
    uint16_t WinSize;          // 窗口大小
    uint16_t CheckSum;         // 校验和
    uint16_t UrgPtr;           // 紧急指针
};

#pragma pack()
class PcapParser
{
private:
    uint32_t mPackIndex;

    void ipDecode(const char* buf);
    void ipv6Decode(const char* buf);
    void udpDecode(const char* buf, int len);
    void tcpDecode(const char* buf, int len);

public:
    // pcap文件解析
    void parse(const char* filename);
};

void PcapParser::tcpDecode(const char* buf, int len)
{
    TCPHeader_t* tcpHeader = (TCPHeader_t*) buf;
    uint16_t lenOfHead = (tcpHeader->headAndFlags & 0x00f0)>>2;

    uint16_t srcPort = ntohs(tcpHeader->srcPort);
    uint16_t dstPort = ntohs(tcpHeader->dstPort);
    // 用户数据长度
    uint16_t dataLen = len - lenOfHead;

    printf("srcPort->dstPort:[%d]->[%d] userDataLen:%d ", srcPort, dstPort, dataLen);

    uint16_t tcp_flags = ((tcpHeader->headAndFlags>>8) & 0x003f);
    if (tcp_flags)
    {
        char flag_name[6][10] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"};
        int k = 0;
        printf("flags:[");
        int tmp = tcp_flags;
        while (tmp)
        {
            int a = tmp % 2;
            tmp /= 2;
            if (a == 1)
            {
                printf(" %s ", flag_name[k]);
            }
            k++;
        }
        printf("]\n");
    }

    if (tcp_flags == 24) // (PSH, ACK) 3路握手成功后
    {   
        //需要立即处理的数据置PSH位
        //HTTP请求报文置PSH位
        //HTTP响应报文可能跨越多个数据包，仅第一个数据包（含有状态行等信息）置PSH位
        if (dstPort == 80 || srcPort == 80)
        { 
            printf("proto:HTTP\n");
            bool b=false;
            if(dstPort==80) b=true;
            HttpParser httpPackage(buf + lenOfHead, dataLen, b);
            httpPackage.show();
        }
        else if (dstPort == 443 || srcPort == 443)
        {
            printf("proto:HTTPS\n");
            HttpsParser httpsPackage(buf + lenOfHead, dataLen); 
        }
    }
}

// udp协议解析
void PcapParser::udpDecode(const char* buf, int len)
{
    int offset = 0;
    UDPHeader_t* udpHeader = (UDPHeader_t*)(buf + offset);
    offset += sizeof(UDPHeader_t);

    uint16_t srcPort = ntohs(udpHeader->SrcPort);
    uint16_t dstPort = ntohs(udpHeader->DstPort);
    uint16_t packLen = ntohs(udpHeader->Length);

    // 用户数据长度
    uint16_t dataLen = packLen - sizeof(UDPHeader_t);
    printf("srcPort->dstPort:[%d]->[%d] userDataLen:%d\n", srcPort, dstPort, dataLen);

    if (srcPort == 53 || dstPort == 53){
        printf("proto:DNS\n");
        //too tired
    }
}

// IP 协议解析
void PcapParser::ipDecode(const char* buf)
{
    int offset = 0;
    IPHeader_t* ipHeader = (IPHeader_t*)(buf + offset);
    offset += sizeof(IPHeader_t);

    char srcIp[32] = { 0 };
    char dstIp[32] = { 0 };

    inet_ntop(AF_INET, &ipHeader->SrcIP, srcIp, sizeof(srcIp));
    inet_ntop(AF_INET, &ipHeader->DstIP, dstIp, sizeof(dstIp));

    uint16_t ipPackLen = ntohs(ipHeader->TotalLen);

    printf("srcIP->dstIP:[%s]->[%s] ipPackLen=%d \nproto:%s ", srcIp, dstIp, ipPackLen, ipHeader->Protocol==6?"TCP":(ipHeader->Protocol==17?"UDP":"Unknown"));

    switch (ipHeader->Protocol)
    {
        case 17:// UDP协议
            udpDecode(buf + offset, ipPackLen - sizeof(IPHeader_t));
            break;
        case 6: // TCP协议
            tcpDecode(buf + offset, ipPackLen - sizeof(IPHeader_t));
            break;
        default:
            printf("[%s:%d]unsupported protocol %#x\n", __FILE__, __LINE__,
                   ipHeader->Protocol);
            break;
    }
}

void PcapParser::ipv6Decode(const char* buf)
{
    int offset = 0;
    IPV6Header_t* ipv6Header = (IPV6Header_t*)(buf + offset);
    offset += sizeof(IPV6Header_t);

    char srcIpv6[128] = { 0 };
    char dstIpv6[128] = { 0 };

    inet_ntop(AF_INET6, &ipv6Header->SrcIP0, srcIpv6, sizeof(srcIpv6));
    inet_ntop(AF_INET6, &ipv6Header->DstIP0, dstIpv6, sizeof(dstIpv6));

    uint16_t ipPackLen = ntohs(ipv6Header->TotalLen);

    printf("srcIPv6->dstIPv6:[%s]->[%s] payLoadLen=%d \nproto:%s ", srcIpv6, dstIpv6, ipPackLen, ipv6Header->NHead==6?"TCP":(ipv6Header->NHead==17?"UDP":"Unknown"));

    switch (ipv6Header->NHead)
    {
        case 17:// UDP协议
            udpDecode(buf + offset, ipPackLen );
            break;
        case 6: // TCP协议
            tcpDecode(buf + offset, ipPackLen );
            break;
        default:
            printf("[%s:%d]unsupported protocol %#x\n", __FILE__, __LINE__,
                   ipv6Header->NHead);
            break;
    }
}

void PcapParser::parse(const char* filename)
{
    struct stat st;
    if (stat(filename, &st))
    {
        printf("stat file %s failed, errno=%d errmsg=%s\n", filename, errno, strerror(errno));
        return;
    }

    size_t fileSize = st.st_size;

    if (!fileSize)
    {
        printf("file is empty!\n");
        return;
    }

    char *buf = (char*)malloc(fileSize + 1);

    FILE* fp = fopen(filename, "r");
    if (!fp)
    {
        printf("open file %s failed, errno=%d errmsg=%s\n", filename, errno, strerror(errno));
        return;
    }
    fread(buf, sizeof(char), fileSize, fp);
    fclose(fp);


    size_t offset = 0;
    // pcap 文件头
    pcap_file_header* fileHeader = (pcap_file_header*)(buf + offset);
    offset += sizeof(pcap_file_header);
    printf("pcap file - magic:%#x version:%d.%d\n", fileHeader->magic, fileHeader->version_major, fileHeader->version_minor);

    size_t proto_offset = 0;
    mPackIndex = 0;
    while (offset < fileSize)
    {
        printf("Frame number: %d\n",mPackIndex+1);
        // pcap 包头
        pcap_pkthdr* pcapHeader = (pcap_pkthdr*)(buf + offset);

        //抓包时间
	    struct tm cap_time;
        time_t tt= (time_t)pcapHeader->ts.tv_sec;
	    localtime_r(&tt,&cap_time);
	    printf("%d-%d-%d %d:%d:%d captured!\n", cap_time.tm_year + 1900, cap_time.tm_mon + 1, cap_time.tm_mday, cap_time.tm_hour, cap_time.tm_min, cap_time.tm_sec);


        proto_offset = offset + sizeof(pcap_pkthdr);

        // arp协议头
        EthnetHeader_t* ethHeader = (EthnetHeader_t*)(buf + proto_offset);
        proto_offset += sizeof(EthnetHeader_t);

        uint16_t protocol = ntohs(ethHeader->protoType);
        char* netProto;
        switch(protocol){
            case 0x0800:netProto=(char*)"IPv4";
            break;
            case 0x0806:netProto=(char*)"ARP";
            break;
            case 0x8035:netProto=(char*)"RARP";
            break;
            case 0x86DD:netProto=(char*)"IPv6";
            break;
            case 0x8137:netProto=(char*)"IPX/SPX";
            break;
            case 0x888E:netProto=(char*)"802.1x";
            break;
            default:netProto=(char*)"Unknown";
        }
        
        printf("srcMac->dstMac:[%02x:%02x:%02x:%02x:%02x:%02x]->[%02x:%02x:%02x:%02x:%02x:%02x] \nproto:%s ",
               ethHeader->srcMac[0], ethHeader->srcMac[1], ethHeader->srcMac[2], ethHeader->srcMac[3], ethHeader->srcMac[4], ethHeader->srcMac[5],
               ethHeader->dstMac[0], ethHeader->dstMac[1], ethHeader->dstMac[2], ethHeader->dstMac[3], ethHeader->dstMac[4], ethHeader->dstMac[5],
               netProto);
        
        // ip 协议
        if (protocol == 0x0800)
        {
            ipDecode(buf + proto_offset);
        }
        else if(protocol == 0x86DD){
           ipv6Decode(buf + proto_offset);
        }
        else
        {
            printf("[%s:%d]unsupported protocol %#x\n", __FILE__, __LINE__,
                   protocol);
        }
        printf("\n");
        offset += (pcapHeader->caplen + sizeof(pcap_pkthdr));
        mPackIndex++;
    }

    printf("total package count:%d\n", mPackIndex);

    if (buf)
    {
        free(buf);
        buf = NULL;
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Please enter the name of the file to be parsed correctly!\n");
        return 0;
    }
    const char* filename=argv[1];

    PcapParser parser;
    parser.parse(filename);
    return 0;
}