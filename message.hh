#include <ostream>
#include <sstream>

namespace DNS {
namespace Default {
static const int MAX_DOMAIN_NAME_SIZE = 255;
static const int HDR_SIZE = 12;
} // namespace Default
class Message {
public:
  class Header {
  public:
    unsigned int m_id : 16;
    unsigned int m_qr : 1;
    unsigned int m_opcode : 4;
    unsigned int m_aa : 1;
    unsigned int m_tc : 1;
    unsigned int m_rd : 1;
    unsigned int m_ra : 1;
    unsigned int m_z : 3;
    unsigned int m_rcode : 4;
    unsigned int m_qdcount : 16;
    unsigned int m_ancount : 16;
    unsigned int m_nscount : 16;
    unsigned int m_arcount : 16;
    Header(const char *data, int len);
    std::string String();

  private:
    friend std::stringstream &operator<<(std::stringstream &ss,
                                         const DNS::Message::Header &hdr);
    friend std::ostream &operator<<(std::ostream &os,
                                    const DNS::Message::Header &hdr);
  };
  class Question {
  public:
    char m_qname[Default::MAX_DOMAIN_NAME_SIZE];
    unsigned int m_qtype : 16;
    unsigned int m_qclass : 16;
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
} // namespace DNS