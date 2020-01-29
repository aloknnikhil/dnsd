#include <cstdint>
#include <ostream>
#include <sstream>

namespace DNS {
namespace Default {
static const int MAX_DOMAIN_NAME_SIZE = 255;
static const int HDR_SIZE = 12;
} // namespace Default
class Message {
public:
  struct Header {
  public:
    uint16_t m_id;
#if (BYTE_ORDER == BIG_ENDIAN)
    uint16_t m_qr : 1;
    uint16_t m_opcode : 4;
    uint16_t m_aa : 1;
    uint16_t m_tc : 1;
    uint16_t m_rd : 1;
    uint16_t m_ra : 1;
    uint16_t m_z : 1;
    uint16_t m_ad : 1;
    uint16_t m_cd : 1;
    uint16_t m_rcode : 4;
#elif (BYTE_ORDER == LITTLE_ENDIAN)
    uint16_t m_rd : 1;
    uint16_t m_tc : 1;
    uint16_t m_aa : 1;
    uint16_t m_opcode : 4;
    uint16_t m_qr : 1;
    uint16_t m_rcode : 4;
    uint16_t m_cd : 1;
    uint16_t m_ad : 1;
    uint16_t m_z : 1;
    uint16_t m_ra : 1;
#endif
    uint16_t m_qdcount;
    uint16_t m_ancount;
    uint16_t m_nscount;
    uint16_t m_arcount;
  };
  struct Question {
  public:
    char m_qname[Default::MAX_DOMAIN_NAME_SIZE];
    unsigned int m_qtype : 16;
    unsigned int m_qclass : 16;
    Question(const char *data);
  };
  class ResourceRecord {
  public:
    char m_name[Default::MAX_DOMAIN_NAME_SIZE];
    unsigned int m_type : 16;
    unsigned int m_class : 16;
    unsigned int m_ttl : 32;
    unsigned int m_rdLength : 16;
    char *m_rdata;
  };
  Message(const char *data, int len);
};

static const Message::Header *Parse(const unsigned char *data) {
  return reinterpret_cast<const DNS::Message::Header *>(data);
}
std::stringstream &operator<<(std::stringstream &ss,
                              const DNS::Message::Header &hdr);
std::ostream &operator<<(std::ostream &os, const DNS::Message::Header &hdr);
} // namespace DNS