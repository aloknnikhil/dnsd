#include "message.hh"
#include <bitset>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <arpa/inet.h>

DNS::Message::Header::Header(const char *data, int len) {
  if (len < DNS::Default::HDR_SIZE) {
    std::stringstream message;
    message << "Incomplete message. Size is < " << Default::HDR_SIZE
            << " bytes";
    throw std::runtime_error(message.str());
  }

  m_id = (static_cast<unsigned char>(data[0]) << 8) +
         static_cast<unsigned char>(data[1]);
  data += 2;

  int octets = (static_cast<unsigned char>(data[0]) << 8) +
               static_cast<unsigned char>(data[1]);
  data += 2;
  std::bitset<16> bitfields(octets);
  m_qr = bitfields[0];
  m_opcode = (bitfields[1] << 3) + (bitfields[2] << 2) + (bitfields[3] << 1) +
             bitfields[4];
  m_aa = bitfields[5];
  m_tc = bitfields[6];
  m_rd = bitfields[7];
  m_ra = bitfields[8];
  m_z = (bitfields[9] << 2) + (bitfields[10] << 1) + bitfields[11];
  m_rcode = (bitfields[12] << 3) + (bitfields[13] << 2) + (bitfields[14] << 1) +
            bitfields[15];

  m_qdcount = (static_cast<unsigned char>(data[0]) << 8) +
              static_cast<unsigned char>(data[1]);
  data += 2;

  m_ancount = (static_cast<unsigned char>(data[0]) << 8) +
              static_cast<unsigned char>(data[1]);
  data += 2;

  m_nscount = (static_cast<unsigned char>(data[0]) << 8) +
              static_cast<unsigned char>(data[1]);
  data += 2;

  m_arcount = (static_cast<unsigned char>(data[0]) << 8) +
              static_cast<unsigned char>(data[1]);
  data += 2;
}

namespace DNS {
std::stringstream &operator<<(std::stringstream &ss,
                              const DNS::Message::Header &hdr) {
  ss << "ID: " << hdr.m_id << " QDCOUNT: " << hdr.m_qdcount;
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
  octets += hdr.m_rcode;
  os << htons(hdr.m_id) << htons(octets) << htons(hdr.m_qdcount)
     << htons(hdr.m_ancount) << htons(hdr.m_nscount) << htons(hdr.m_arcount);
  return os;
}
} // namespace DNS