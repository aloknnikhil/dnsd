#include "message.hh"
#include <arpa/inet.h>
#include <bitset>
#include <iomanip>
#include <ios>
#include <iostream>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace DNS {
std::stringstream &operator<<(std::stringstream &ss,
                              const DNS::Message::Header &hdr) {
  ss << "\nID: " << ntohs(hdr.m_id) << "\nQR: " << hdr.m_qr
     << " OPCODE: " << hdr.m_opcode << " AA: " << hdr.m_aa
     << " TC: " << hdr.m_tc << " RD: " << hdr.m_rd << " RA: " << hdr.m_ra
     << " Z: " << hdr.m_z << " AD: " << hdr.m_ad << " CD: " << hdr.m_cd
     << " RCODE: " << hdr.m_rcode << "\nQDCOUNT: " << ntohs(hdr.m_qdcount)
     << " ANCOUNT: " << ntohs(hdr.m_ancount)
     << " NSCOUNT: " << ntohs(hdr.m_nscount)
     << " ARCOUNT: " << ntohs(hdr.m_arcount);
  return ss;
}

std::ostream &operator<<(std::ostream &os, const DNS::Message::Header &hdr) {
  int octets = hdr.m_qr << 15;
  octets += hdr.m_opcode << 14;
  octets += hdr.m_aa << 10;
  octets += hdr.m_tc << 9;
  octets += hdr.m_rd << 8;
  octets += hdr.m_ra << 7;
  octets += hdr.m_z << 6;
  octets += hdr.m_ad << 5;
  octets += hdr.m_cd << 4;
  octets += hdr.m_rcode;
  os << htons(hdr.m_id) << htons(octets) << htons(hdr.m_qdcount)
     << htons(hdr.m_ancount) << htons(hdr.m_nscount) << htons(hdr.m_arcount);
  return os;
}
} // namespace DNS