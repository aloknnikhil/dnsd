#include "message.hh"
#include <iostream>
#include <ostream>
#include <sstream>

// Parses a DNS message from the buffer and the given length
// Note: This daemon minimally parses only the question & answer sections and
// ignores the authority records & additional records
DNS::Message::Message(unsigned char *data, int len) {
  // Check for minimum required size (= Header size)
  if (len < DNS::Default::HDR_SIZE) {
    std::stringstream message;
    message << "[HEADER] Incomplete message. Current offset: 0"
            << "; Actual total: " << len;
    throw std::runtime_error(message.str());
  }
  m_hdr = *reinterpret_cast<DNS::Message::Header *>(data);

  // Parse questions
  uint16_t offset = DNS::Default::HDR_SIZE;
  for (int i = 0; i < ntohs(m_hdr.m_qdcount); i++) {
    Question q(data, offset);
    m_questions.push_back(q);
    offset += q.Size();
    if (offset >= len && i < (ntohs(m_hdr.m_qdcount) - 1)) {
      std::stringstream message;
      message << "[QUESTION] Incomplete message. Current offset: " << offset
              << "; Actual total: " << len;
      throw std::runtime_error(message.str());
    }
  }

  // Validate message length before proceeding
  if (offset >= len && ntohs(m_hdr.m_ancount) > 0) {
    std::stringstream message;
    message << "[ANSWER] Incomplete message. Current offset: " << offset
            << "; Actual total: " << len;
    throw std::runtime_error(message.str());
  }

  // Parse answers
  for (int i = 0; i < ntohs(m_hdr.m_ancount); i++) {
    ResourceRecord rr(data, offset);
    m_answers.push_back(rr);
    offset += rr.Size();
    if (offset >= len && i < (ntohs(m_hdr.m_ancount) - 1)) {
      std::stringstream message;
      message << "[ANSWER] Incomplete message. Current offset: " << offset
              << "; Actual total: " << len;
      throw std::runtime_error(message.str());
    }
  }
}

// Question is built from the offset given.
// Since the question section is a variable field, this constructor reads from
// the buffer and follows the algorithm described in RFC1035 to parse domain
// labels and question type/class.
DNS::Message::Question::Question(unsigned char *data, uint16_t offset) {
  m_size = 0;
  // Label length
  // Start parsing from the offset
  auto buffer = data + offset;
  // Every domain label length precedes the data
  int length = *buffer++;

  // End of the QNAME field is marked by a 0-length octet
  while (length != 0) {
    m_size += length;
    std::string label;
    for (int i = 0; i < length; i++) {
      char c = *buffer++;
      label.append(1, c);
    }

    // Add a byte for the length octet for every label
    m_size += 1;

    length = *buffer++;
    // Each label is stored as an element in a vector
    m_qname.push_back(label);
  }
  // Add a byte for the final 0-length octet
  m_size += 1;

  m_qtype = *reinterpret_cast<uint16_t *>(buffer);
  buffer += 2;
  m_size += 2;

  m_qclass = *reinterpret_cast<uint16_t *>(buffer);
  buffer += 2;
  m_size += 2;
}

// ResourceRecord is built from the offset given.
// Since the answer/authority/additional sections are variable fields, this
// constructor reads from the buffer and follows the algorithm described in
// RFC1035 to parse domain labels and the other fields.
DNS::Message::ResourceRecord::ResourceRecord(unsigned char *data,
                                             uint16_t offset) {
  m_size = 0;
  // Label length
  // Start parsing from the offset
  auto buffer = data + offset;
  // Every domain label length precedes the data
  int length = *buffer++;

  // End of the NAME field is marked by a 0-length octet
  while (length != 0) {
    m_size += length;
    std::string label;
    for (int i = 0; i < length; i++) {
      char c = *buffer++;
      label.append(1, c);
    }
    length = *buffer++;
    // Each label is stored as an element in a vector
    m_name.push_back(label);
  }
  m_type = *reinterpret_cast<uint16_t *>(buffer);
  buffer += 2;
  m_size += 2;

  m_class = *reinterpret_cast<uint16_t *>(buffer);
  buffer += 2;
  m_size += 2;

  m_ttl = *reinterpret_cast<uint32_t *>(buffer);
  buffer += 4;
  m_size += 4;

  m_rdLength = *reinterpret_cast<uint16_t *>(buffer);
  buffer += 2;
  m_size += 2;

  m_rdata = reinterpret_cast<char *>(buffer);
  buffer += ntohs(m_rdLength);
  m_size += ntohs(m_rdLength);
}

// Implements stream operators for serializing:
// - Message
// - Header
// - Question
// - Resource Record
// Serializing a message iteratively calls the other stream operators to build
// the full message
namespace DNS {

// Message
std::ostream &operator<<(std::ostream &os, const DNS::Message &msg) {

  // From c.f. https://www.ietf.org/rfc/rfc1035
  // +---------------------+
  // |        Header       |
  // +---------------------+
  // |       Question      | the question for the name server
  // +---------------------+
  // |        Answer       | RRs answering the question
  // +---------------------+
  // |      Authority      | RRs pointing toward an authority
  // +---------------------+
  // |      Additional     | RRs holding additional information
  // +---------------------+
  // Serialized in network order (big-endian)

  os << msg.m_hdr;
  for (const auto &iter : msg.m_questions) {
    os << iter;
  }
  for (const auto &iter : msg.m_answers) {
    os << iter;
  }
  return os;
}

// Header
std::ostream &operator<<(std::ostream &os, const DNS::Message::Header &hdr) {

  // From c.f. https://www.ietf.org/rfc/rfc1035
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |                      ID                       |
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |                    QDCOUNT                    |
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |                    ANCOUNT                    |
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |                    NSCOUNT                    |
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |                    ARCOUNT                    |
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // Serialized in network order (big-endian)

  os.write(reinterpret_cast<const char *>(&hdr), Default::HDR_SIZE);
  return os;
}

// Question
std::ostream &operator<<(std::ostream &os, const DNS::Message::Question &q) {
  // From c.f. https://www.ietf.org/rfc/rfc1035
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |                                               |
  // /                     QNAME                     /
  // /                                               /
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |                     QTYPE                     |
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |                     QCLASS                    |
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // Serialized in network order (big-endian)

  for (const auto &iter : q.m_qname) {
    os << static_cast<uint8_t>(iter.size()) << iter;
  }
  // Add 0-length octet to mark end of NAME
  os << static_cast<uint8_t>(0);
  os.write(reinterpret_cast<const char *>(&q.m_qtype), 2);
  os.write(reinterpret_cast<const char *>(&q.m_qclass), 2);
  return os;
}

// ResourceRecord
std::ostream &operator<<(std::ostream &os,
                         const DNS::Message::ResourceRecord &rr) {
  // From c.f. https://www.ietf.org/rfc/rfc1035
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |                                               |
  // /                                               /
  // /                      NAME                     /
  // |                                               |
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |                      TYPE                     |
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |                     CLASS                     |
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |                      TTL                      |
  // |                                               |
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |                   RDLENGTH                    |
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
  // /                     RDATA                     /
  // /                                               /
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // Serialized in network order (big-endian)

  for (const auto &iter : rr.m_name) {
    os << static_cast<uint8_t>(iter.size()) << iter;
  }
  // Add 0-length octet to mark end of NAME
  os << static_cast<uint8_t>(0);
  os.write(reinterpret_cast<const char *>(&rr.m_type), 2);
  os.write(reinterpret_cast<const char *>(&rr.m_class), 2);
  os.write(reinterpret_cast<const char *>(&rr.m_ttl), 4);
  os.write(reinterpret_cast<const char *>(&rr.m_rdLength), 2);
  os.write(reinterpret_cast<const char *>(rr.m_rdata), ntohs(rr.m_rdLength));
  return os;
}
} // namespace DNS