#pragma once
#include <string>
#include <iostream>

using namespace std;
typedef unsigned char byte;
#define VER_IPV4 0x04FF
#define VER_IPV6 0x06FF
#define PTC_ICMP 0x11FF
#define PTC_IP 0x14FF
#define PTC_TCP 0x16FF
class IPHeader
{
private:
	byte header[60];
	__int16 totalLen;
public:
	IPHeader();
	IPHeader(string src, string dst);
	~IPHeader();
	void SetVer(__int32 ver);
	void SetHdrLen(__int8 len);
	void SetDiff();
	void SetTotalLen(__int16 len);
	void SetId(__int16 id);
	void SetFlag(__int8 flag);
	void SetOffset(__int16 offset);
	void SetTTL(__int8 ttl);
	void SetProtocol(__int32 ptc);
	void SetCheckSum();
	void SetSrcAddr(string addr);
	void SetDstAddr(string addr);
	friend std::ostream &operator<<(ostream &os, const IPHeader &iph);
};

