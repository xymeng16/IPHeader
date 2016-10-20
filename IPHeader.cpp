#include "IPHeader.h"
#include <cstring>
#include <winsock.h>
#include<iomanip>

__int32 ver_t;
__int16 flag_offset;

IPHeader::IPHeader()
{
	IPHeader("0.0.0.0", "0.0.0.0");
}

IPHeader::IPHeader(string src, string dst)
{
	memset(header + 10, 0, 2);
	SetVer(VER_IPV4);
	SetHdrLen(20);
	SetDiff();
	SetTotalLen(0x14);
	SetId(0xD667);
	SetFlag(0x00);
	SetOffset(0x0);
	SetTTL(255);
	SetProtocol(PTC_ICMP);
	SetSrcAddr(src);
	SetDstAddr(dst);
	SetCheckSum();
}


IPHeader::~IPHeader()
{

}

void IPHeader::SetVer(__int32 ver)
{
	ver_t = ver;
}

void IPHeader::SetHdrLen(__int8 len)
{
	__int8 ver_len = 0;
	totalLen = len;
	if (ver_t == VER_IPV4)
		ver_len = 0x4;
	else
		ver_len = 0x6;
	ver_len <<= 4;
	ver_len += ((len%4==0)?len/4:len/4+1)&0x0F;
	memcpy(header, &ver_len, 1);
}

void IPHeader::SetDiff()
{
	memset(header + 1, 0x0, 1);
}

void IPHeader::SetTotalLen(__int16 len)
{
	len = htons(len);
	memcpy(header + 2, &len, 2);
}

void IPHeader::SetId(__int16 id)
{
	id = htons(id);
	memcpy(header + 4, &id, 2);
}

void IPHeader::SetFlag(__int8 flag)
{
	flag_offset = flag & 0x07;
}

void IPHeader::SetOffset(__int16 offset)
{
	flag_offset += offset << 3;

	memcpy(header + 6, &flag_offset, 2);
}

void IPHeader::SetTTL(__int8 ttl)
{
	memcpy(header + 8, &ttl, 1);
}

void IPHeader::SetProtocol(__int32 ptc)
{
	if (ptc == PTC_ICMP)
		memset(header + 9, 0x01, 1);
	if (ptc == PTC_IP)
		memset(header + 9, 0x04, 1);
	if (ptc == PTC_TCP)
		memset(header + 9, 0x06, 1);
}

void IPHeader::SetCheckSum()
{
	// Divide the IP Header into serval 16-bit sequences and plus all of them under the rule of one's complement's addition
	//unsigned short *hdr_ptr = (unsigned short *)header;
	
	
	unsigned short hdr_ptr[10];
	memcpy(hdr_ptr, header, 20);
	unsigned short rtn=0;
	unsigned long sum=0; // In order to get the carry bit, we use a 32-bit sum var, which the carry bit is saved in the high 16-bits of the sum.
	int n = totalLen / 2;
	for (int i = 0; i < n; i++)
	{
		sum += (hdr_ptr[i]);
		//sum >>= 16; 
		sum += (sum >> 16); // Add the carry bit to the sum.
	}
	rtn = ~sum;
	memcpy(header + 10, &rtn, 2);
}

void IPHeader::SetSrcAddr(std::string addr)
{
	__int32 addr_int=0x0,count=0;
	size_t off = 0U, index = 0U;
	while ((index=addr.find('.', off))!=-1)
	{
		int t = atoi(addr.substr(off, index - off).c_str());
		addr_int += (t << (count * 8))&(0xFF<<count*8);
		off = index + 1;
		count++;
	}
	int t = atoi(addr.substr(off, addr.length() - off).c_str());
	addr_int += (t << (count * 8))&(0xFF << count * 8);

	memcpy(header + 12, &addr_int, 4);
}

void IPHeader::SetDstAddr(std::string addr)
{
	__int32 addr_int = 0x0, count = 0;
	size_t off = 0U, index = 0U;
	while ((index = addr.find('.', off)) != -1)
	{
		int t = atoi(addr.substr(off, index - off).c_str());
		addr_int += (t << (count * 8))&(0xFF << count * 8);
		off = index + 1;
		count++;
	}
	int t = atoi(addr.substr(off, addr.length() - off).c_str());
	addr_int += (t << (count * 8))&(0xFF << count * 8);

	memcpy(header + 16, &addr_int, 4);
}

std::ostream & operator<<(ostream & os, const IPHeader & iph)
{
	// TODO: insert return statement here
	for (int i = 0; i < 20; i++)
	{

		os << setw(2) << setfill('0') <<setiosflags(ios::uppercase) << hex << (unsigned short)iph.header[i] << " ";
		if (i % 4 == 3)
			os << endl;
	}
	return os;
}

int main()
{
	string src, dst;
	cout << "Please input the source IP address:";
	cin >> src;
	cout << "Please input the destination IP address:";
	cin >> dst;
	IPHeader iph(src, dst);
	cout << iph<<endl;
	iph.SetCheckSum();
	cout << iph;
	return 0;
}