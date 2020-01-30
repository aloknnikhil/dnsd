#include "message.hh"
#include <arpa/inet.h>
#include <sstream>

namespace DNS {
// Message
std::stringstream &operator<<(std::stringstream &ss, const DNS::Message &msg) {
  ss << "+++++++++++++++++++" << std::endl;
  ss << "Header:" << std::endl;
  ss << msg.m_hdr << std::endl;
  ss << "Questions:" << std::endl;
  for (const auto &iter : msg.m_questions) {
    ss << iter << std::endl;
  }
  ss << "Answers:" << std::endl;
  for (const auto &iter : msg.m_answers) {
    ss << iter << std::endl;
  }
  return ss;
}

// Header
std::stringstream &operator<<(std::stringstream &ss,
                              const DNS::Message::Header &hdr) {
  ss << "ID: " << ntohs(hdr.m_id) << std::endl
     << "QR: " << hdr.m_qr << " OPCODE: " << hdr.m_opcode << " AA: " << hdr.m_aa
     << " TC: " << hdr.m_tc << " RD: " << hdr.m_rd << " RA: " << hdr.m_ra
     << " Z: " << hdr.m_z << " AD: " << hdr.m_ad << " CD: " << hdr.m_cd
     << " RCODE: " << hdr.m_rcode << std::endl
     << "QDCOUNT: " << ntohs(hdr.m_qdcount)
     << " ANCOUNT: " << ntohs(hdr.m_ancount)
     << " NSCOUNT: " << ntohs(hdr.m_nscount)
     << " ARCOUNT: " << ntohs(hdr.m_arcount);
  return ss;
}

// Question
std::stringstream &operator<<(std::stringstream &ss,
                              const DNS::Message::Question &q) {
  ss << "QNAME: ";
  for (auto iter = q.m_qname.begin(); iter < q.m_qname.end();
       iter = std::next(iter, 1)) {
    ss << *iter;
    if (std::next(iter, 1) != q.m_qname.end()) {
      ss << ".";
    }
  }
  ss << " QTYPE: " << ntohs(q.m_qtype) << " QCLASS: " << ntohs(q.m_qclass)
     << " Size: " << q.m_size;
  return ss;
}

// ResourceRecord
std::stringstream &operator<<(std::stringstream &ss,
                              const DNS::Message::ResourceRecord &rr) {
  ss << "NAME: ";
  for (auto iter = rr.m_name.begin(); iter < rr.m_name.end();
       iter = std::next(iter, 1)) {
    ss << *iter;
    if (std::next(iter, 1) != rr.m_name.end()) {
      ss << ".";
    }
  }
  ss << " TYPE: " << ntohs(rr.m_type) << " CLASS: " << ntohs(rr.m_class)
     << " TTL: " << ntohl(rr.m_ttl) << " RDLENGTH: " << ntohs(rr.m_rdLength)
     << " SIZE: " << rr.m_size << std::endl;
  return ss;
}
} // namespace DNS