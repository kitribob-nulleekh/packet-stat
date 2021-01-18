#pragma once

#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    uint8_t ver_;
    uint8_t tos_;
    uint16_t len_;
    uint16_t id_;
    uint16_t flag_;
    uint8_t ttl_;
    uint8_t protocol_;
    uint16_t checksum_;
    Ip sip_;
    Ip dip_;

	Ip       dip() { return dip_; }
	Ip       sip() { return sip_; }
	uint16_t size() { return len_; }
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)
