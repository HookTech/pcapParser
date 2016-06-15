#ifndef PCAP_H
#define PCAP_H
typedef short _Int16;
typedef unsigned short u_Int16;
typedef unsigned long _Int32;
typedef char _Int8;
typedef unsigned char u_Int8;
typedef char Byte;

struct _pcap_header
{//pcap header 24B
	_Int32 iMagic;
	_Int16 iMaVersion;
	_Int16 iMiVersion;
	_Int32 iTimezone;
	_Int32 iSigFlags;
	_Int32 iSnapLen;
	_Int32 iLinkType;
};

struct _packet_header
{//packet header 16B
	_Int32 iTimeSecond;
	_Int32 iTimeSS;
	_Int32 iPLength;
	_Int32 iLength;//帧的长度
};

struct FrameHeader_t
{//frame header 14B
	_Int8 DstMac[6];
	_Int8 SrcMac[6];
	_Int16 FrameType;//0x0800
};

struct IpHeader_t
{//20B 20--60B
	_Int8 Ver_HLen;//头长度后四位
	_Int8 TOS;
	_Int16 TotalLen;
	_Int16 ID;
	_Int16 Flag_Segment;
	_Int8 TTL;
	_Int8 Protocal;//6
	_Int16 Checksum;
	_Int32 SrcIP;
	_Int32 DstIP;
};

struct TcpHeader_t
{//20B 20--60B
	u_Int16 srcPort;
	u_Int16 dstPort;
	_Int32 sequence_num;
	_Int32 ACK_num;
	u_Int8 dataoffset;//首部长度
	_Int8 flag;
	u_Int16 wind;
	u_Int16 checknum;
	u_Int16 urgent_point;
};

struct UdpHeader_t
{//8B
	_Int16 srcPort;
	_Int16 dstPort;
	_Int16 Length;
	_Int16 Checksum;
};
#endif
