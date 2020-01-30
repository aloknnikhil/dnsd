#include "dnsd.hh"
#include "message.hh"
#include <cstdlib>
#include <ctime>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <vector>

namespace DNS {
DNS::Message *query(struct in_addr server,
                    std::vector<std::string> &domainLabels, uint16_t qtype,
                    uint16_t qclass) {

  // Generate query headers
  DNS::Message query;
  query.m_hdr.m_qdcount = htons(1);

  srand(time(nullptr));
  query.m_hdr.m_id = static_cast<uint16_t>(rand());

  // Add a question
  DNS::Message::Question q;
  q.m_qclass = htons(qtype);
  q.m_qtype = htons(qclass);
  q.m_qname = domainLabels;
  query.m_questions.push_back(q);

  std::ostringstream queryBuf;
  queryBuf << query;

  // Dial UDP connection
  int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockFD == -1) {
    std::stringstream message;
    message << "What: " << std::strerror(errno) << " - Context: socket(UDP)";
    throw std::runtime_error(message.str());
  }

  int n = sendto(sockFD, queryBuf.str().c_str(), queryBuf.tellp(), MSG_WAITALL,
                 reinterpret_cast<sockaddr *>(&server), sizeof(server));

  if (n < queryBuf.tellp()) {
    std::stringstream message;
    message << "What: " << std::strerror(errno) << " - Context: sendto()";
    throw std::runtime_error(message.str());
  }
  unsigned char buf[DNS::Default::BUFFER_SIZE];
  socklen_t serverLen = sizeof(server);
  n = recvfrom(sockFD, buf, DNS::Default::BUFFER_SIZE, 0,
               reinterpret_cast<sockaddr *>(&server), &serverLen);
  if (n < 0) {
    std::stringstream message;
    message << "What: " << std::strerror(errno) << " - Context: recvfrom()";
    throw std::runtime_error(message.str());
  }

  return new DNS::Message(buf, n);
}
} // namespace DNS