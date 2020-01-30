#include <arpa/inet.h>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace DNS {
namespace Default {
// Defined by RFC1035
static const int MAX_LABEL_LENGTH = 63;
static const int MAX_DOMAIN_NAME_SIZE = 255;
static const int HDR_SIZE = 12;
} // namespace Default

// The Message describes a classic DNS message according to RFC1035
// The Message minimally contains
// - a header field laid out in the big endian order
// - a vector of Questions (The Question Section)
// - a vector of Answers (The Answer Section)
// Note: The message serialization does NOT support message compression
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

  class Question {
  public:
    // Construct an empty question
    // NOTE: Using the default constructor requires explicitly updating m_size
    Question() : m_qtype(0), m_qclass(0), m_size(0) {}

    // Builds a question by parsing the buffer at the given offset
    Question(unsigned char *buf, uint16_t offset);
    uint16_t Size() { return m_size; }
    std::vector<std::string> m_qname;
    uint16_t m_qtype;
    uint16_t m_qclass;
    uint16_t m_size;
  };

  class ResourceRecord {
  public:
    // Construct an empty resource record
    // NOTE: Using the default constructor requires explicitly updating m_size
    ResourceRecord()
        : m_type(0), m_class(0), m_ttl(0), m_rdLength(0), m_rdata(nullptr),
          m_size(0) {}

    // Builds a resource record by parsing the buffer at the given offset
    ResourceRecord(unsigned char *buf, uint16_t offset);
    uint16_t Size() { return m_size; }
    std::vector<std::string> m_name;
    uint16_t m_type;
    uint16_t m_class;
    uint32_t m_ttl;
    uint16_t m_rdLength;
    unsigned char *m_rdata;
    uint16_t m_size;
  };

  Message() : m_hdr({0}) {}
  Message(unsigned char *data, int len);
  Header m_hdr;
  std::vector<Question> m_questions;
  std::vector<ResourceRecord> m_answers;
};

// Stream operators for serializing and pretty-printing packet data
// Header
std::stringstream &operator<<(std::stringstream &ss,
                              const DNS::Message::Header &hdr);
std::ostream &operator<<(std::ostream &os, const DNS::Message::Header &hdr);

// Message
std::stringstream &operator<<(std::stringstream &ss, const DNS::Message &msg);
std::ostream &operator<<(std::ostream &os, const DNS::Message &msg);

// Question
std::stringstream &operator<<(std::stringstream &ss,
                              const DNS::Message::Question &q);
std::ostream &operator<<(std::ostream &os, const DNS::Message::Question &q);

// ResourceRecord
std::stringstream &operator<<(std::stringstream &ss,
                              const DNS::Message::ResourceRecord &rr);
std::ostream &operator<<(std::ostream &os,
                         const DNS::Message::ResourceRecord &rr);
} // namespace DNS