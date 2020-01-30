#include "catch.hh"
#include "dnsd.hh"
#include "message.hh"
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <netinet/in.h>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <vector>

namespace DNS {
DNS::Message *query(struct sockaddr_in server,
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
  // TODO: The question m_size is not updated here
  query.m_questions.push_back(q);

  std::ostringstream queryBuf;
  queryBuf << query;

  // Dial UDP connection
  int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockFD < 0) {
    std::stringstream message;
    message << "[CLIENT] What: " << std::strerror(errno)
            << " - Context: socket(UDP)";
    throw std::runtime_error(message.str());
  }

  // Set socket receive timeout
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  if (setsockopt(sockFD, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    std::stringstream message;
    message << "[CLIENT] What: " << std::strerror(errno)
            << " - Context: setsockopt(SO_RCVTIMEO)";
    throw std::runtime_error(message.str());
  }

  socklen_t serverLen = sizeof(server);
  bool done = false;
  int n = 0;
  auto buf = new unsigned char[DNS::Default::BUFFER_SIZE];
  while (!done) {
    n = sendto(sockFD, queryBuf.str().c_str(), queryBuf.tellp(), 0,
               reinterpret_cast<sockaddr *>(&server), serverLen);
    if (n < queryBuf.tellp()) {
      std::stringstream message;
      message << "[CLIENT] What: " << std::strerror(errno)
              << " - Context: sendto()";
      throw std::runtime_error(message.str());
    }
    n = recvfrom(sockFD, buf, DNS::Default::BUFFER_SIZE, 0,
                 reinterpret_cast<sockaddr *>(&server), &serverLen);

    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      std::stringstream message;
      message << "[CLIENT] What: " << std::strerror(errno)
              << " - Context: recvfrom()";
      throw std::runtime_error(message.str());
    }
    done = true;
  }

  auto msg = new DNS::Message(buf, n);
  return msg;
}
} // namespace DNS