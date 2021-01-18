#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <unistd.h>
#include <map>
#include "ethhdr.h"
#include "iphdr.h"
#include "ip.h"

void usage(const char* name) {
    printf("syntax : %s <pcap file>\n"
           "sample : %s test.pcap\n",
           name, name);
}

struct Pkt {
    EthHdr eth;
    IpHdr ip;
};

struct IpPair{
    Ip source_;
    Ip destination_;

    bool operator <(const IpPair& other) const {
        if (source_ == other.source_) {
            return destination_ < other.destination_;
        } else {
            return source_ < other.source_;
        }
    }
};

struct StatData {
    unsigned int packets;
    unsigned int bytes;
    unsigned int tPackets;
    unsigned int tBytes;
    unsigned int rPackets;
    unsigned int rBytes;
};

void ConvInsert(std::map<IpPair, StatData>&_conv, IpPair _ipPair, Pkt* _pktData, pcap_pkthdr* _hdr) {
    std::map<IpPair, StatData>::iterator iter;
    iter = _conv.find(_ipPair);
    if (_conv.end() == iter) {
        StatData temp{1, _hdr->caplen, 1, _hdr->caplen, 0, 0};
        _conv.insert(std::pair<IpPair, StatData>(_ipPair, temp));
    } else {
        iter->second.packets++; iter->second.bytes+=_hdr->caplen;
        iter->second.tPackets++; iter->second.tBytes+=_hdr->caplen;
    }
};

void ConvJoin(std::map<IpPair, StatData>&_conv) {
    std::map<IpPair, StatData>::iterator iter;
    for(iter = _conv.begin(); iter != _conv.end(); ++iter){
        IpPair temp;
        temp.source_ = iter->first.destination_;
        temp.destination_ = iter->first.source_;

        auto innerIter = _conv.find(temp);
        if( innerIter != _conv.end()){
            iter->second.bytes += innerIter->second.bytes; iter->second.packets += innerIter->second.packets;
            iter->second.rBytes += innerIter->second.tBytes; iter->second.rPackets += innerIter->second.tPackets;
            _conv.erase(innerIter);
        }
    }
}

void _ConvToEnd(std::map<IpPair, StatData>&_conv, std::map<Ip, StatData>&_end, Ip _ip, StatData _stat) {
    std::map<IpPair, StatData>::iterator innerIter;
    for(innerIter = _conv.begin(); innerIter != _conv.end(); ++innerIter){
        if(_ip == innerIter->first.source_){
            _stat.packets += innerIter->second.packets; _stat.bytes += innerIter->second.bytes;
            _stat.tPackets += innerIter->second.tPackets; _stat.tBytes += innerIter->second.tBytes;
            _stat.rPackets += innerIter->second.rPackets; _stat.rBytes += innerIter->second.rBytes;
        }
        if(_ip == innerIter->first.destination_){
            _stat.packets += innerIter->second.packets; _stat.bytes += innerIter->second.bytes;
            _stat.tPackets += innerIter->second.rPackets; _stat.tBytes += innerIter->second.rBytes;
            _stat.rPackets += innerIter->second.tPackets; _stat.rBytes += innerIter->second.tBytes;
        }
    }
    _end.insert(std::pair<Ip, StatData>(_ip, _stat));
}

void ConvToEnd(std::map<IpPair, StatData>&_conv, std::map<Ip, StatData>&_end) {
    std::map<IpPair, StatData>::iterator iter;
    for(iter = _conv.begin(); iter != _conv.end(); ++iter){
        Ip tIp = iter->first.source_;
        Ip rIp = iter->first.destination_;
        StatData tStatData, rStatData;

        if(_end.find(tIp) == _end.end()){
            tStatData.packets = 0; tStatData.bytes = 0;
            tStatData.tPackets = 0; tStatData.tBytes = 0;
            tStatData.rPackets = 0; tStatData.rBytes = 0;
        }
        _ConvToEnd(_conv, _end, tIp, tStatData);

        if(_end.find(rIp) == _end.end()){
            rStatData.packets = 0; rStatData.bytes = 0;
            rStatData.tPackets = 0; rStatData.tBytes = 0;
            rStatData.rPackets = 0; rStatData.rBytes = 0;
        }
        _ConvToEnd(_conv, _end, rIp, rStatData);
    }
}

void PrintEnd(std::map<Ip, StatData>&end){
    std::map<Ip, StatData>::iterator iter;
    for(iter = end.begin(); iter != end.end(); ++iter){
        printf("\n\n\n");
        printf("%s\n", std::string((*iter).first).c_str());
        printf("*  : %d(%dbytes)\n",(*iter).second.packets,(*iter).second.bytes);
        printf("-> : %d(%dbytes)\n", (*iter).second.tPackets, (*iter).second.tBytes);
        printf("<- : %d(%dbytes)\n", (*iter).second.rPackets, (*iter).second.rBytes);
    }
}

void PrintConv(std::map<IpPair, StatData>&_conv){
    std::map<IpPair, StatData>::iterator iter;
    for(iter = _conv.begin(); iter != _conv.end(); ++iter){
        printf("\n\n\n");
        printf("%s - %s\n", std::string((*iter).first.source_).c_str(), std::string((*iter).first.destination_).c_str());
        printf("*  : %d(%dbytes)\n",(*iter).second.packets,(*iter).second.bytes);
        printf("-> : %d(%dbytes)\n", (*iter).second.tPackets, (*iter).second.tBytes);
        printf("<- : %d(%dbytes)\n", (*iter).second.rPackets, (*iter).second.rBytes);
    }
}

int main(int argc, char** argv) {
    if(2 != argc){
        usage(argv[0]);
        return -1;
    }

    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errBuf);
    if (NULL == handle) {
        printf("ERROR : pcap file %s is not accessible or empty | errBuf=%s\n",
               argv[1], errBuf);
        return -2;
    }

    std::map<Ip, StatData> ipEndStat;
    std::map<IpPair, StatData> ipConvStat;

    while(handle != NULL){
        struct pcap_pkthdr* hdr;
        const u_char* data;

        int res = pcap_next_ex(handle, &hdr, &data);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        Pkt * pktData = (Pkt *)data;
        IpPair ipPair;

        if(pktData->eth.type() == EthHdr::Ip4){
            ipPair.source_ = pktData->ip.sip();
            ipPair.destination_ = pktData->ip.dip();

            ConvInsert(ipConvStat, ipPair, pktData, hdr);
        }
    }
    ConvJoin(ipConvStat);
    ConvToEnd(ipConvStat, ipEndStat);


    int selection;

    printf("=========  Select Type  =========\n");
    printf("   1:endpoint   2:conversation   \n");
    printf("=================================\n");
    scanf("%d", &selection);

    switch (selection) {
        case 1:
            PrintEnd(ipEndStat);
            break;
        case 2:
            PrintConv(ipConvStat);
            break;
        default:
            printf("ERROR : %d is not available value\n", selection);
    }

    return 0;
}
