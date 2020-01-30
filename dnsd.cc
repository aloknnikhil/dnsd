#include "dnsd.hh"
#include "message.hh"
#include <arpa/inet.h>
#include <cstring>
#include <exception>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <utility>

// Constructs a spoofing daemon that spoofs A-record DNS lookup requests with
// the given IP address for ANY class queries
// Note: This daemon only supports IPv4
// Note: This daemon only implements a subset of the standard in RFC1035
DNS::Daemon::Daemon(std::string spoof) {

  // Validate IP address
  m_spoofIP = {0};
  auto ret = inet_pton(AF_INET, spoof.c_str(), &m_spoofIP);
  if (ret <= 0) {
    std::stringstream message;
    if (ret == 0) {
      message << "Address: " << spoof << " - Not in Presentation Format";
    } else {
      message << "What: " << std::strerror(errno) << " - Context: inet_pton("
              << spoof << ")";
    }
    throw std::runtime_error(message.str());
  }
}

DNS::Daemon::~Daemon() {
  // Do nothing for now
}

// Start the daemon to receive DNS messages over UDP.
// Blocking call.
void DNS::Daemon::run(bool block) {
  // Open a UDP socket
  auto sockFD = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockFD == -1) {
    std::stringstream message;
    message << "What: " << std::strerror(errno) << " - Context: socket(UDP)";
    throw std::runtime_error(message.str());
  }

  // Bind to UDP port (default: 53; address: 0.0.0.0)
  const sockaddr_in srvAddr{
      .sin_family = AF_INET,
      .sin_port = htons(DNS::Default::PORT),
      .sin_addr.s_addr = htonl(DNS::Default::ADDRESS),
  };
  if (bind(sockFD, reinterpret_cast<const sockaddr *>(&srvAddr),
           sizeof(srvAddr)) < 0) {
    std::stringstream message;
    message << "What: " << std::strerror(errno) << " - Context: bind()";
    throw std::runtime_error(message.str());
  }

  // Defining a maximum DNS packet size as described in the RFC:
  // c.f. https://www.ietf.org/rfc/rfc1035
  unsigned char buf[DNS::Default::BUFFER_SIZE];

  // Cache client address to reply back
  while (!m_complete) {
    sockaddr_in clientAddr{};
    socklen_t clientLen = sizeof(clientAddr);
    int flags = 0;
    if (!block) {
      flags = MSG_DONTWAIT;
    }
    int n = recvfrom(sockFD, buf, DNS::Default::BUFFER_SIZE, flags,
                     reinterpret_cast<sockaddr *>(&clientAddr), &clientLen);
    if (n < 0) {
      if (!block && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        continue;
      }
      std::stringstream message;
      message << "What: " << std::strerror(errno) << " - Context: recvfrom()";
      std::cerr << message.str() << std::endl;
    }

    // Parse DNS query
    try {
      DNS::Message msg(buf, n);

      // Copy DNS query to reply
      // The reply needs identical fields for ID, QDCOUNT, Question fields
      DNS::Message reply = msg;
      // Set message type to Response
      reply.m_hdr.m_qr = 1;
      // We are not a domain authority
      reply.m_hdr.m_aa = 0;
      // We don't support recursive lookup
      reply.m_hdr.m_ra = 0;
      // Set answer count = question count
      reply.m_hdr.m_ancount = reply.m_hdr.m_qdcount;
      // No Authority records
      reply.m_hdr.m_nscount = 0;
      // No Additional records
      reply.m_hdr.m_arcount = 0;

      // Generate a Resource Record for every answer with the spoofed IP
      for (int i = 0; i < htons(reply.m_hdr.m_qdcount); i++) {
        DNS::Message::ResourceRecord rr;
        // Copy domain labels
        rr.m_name = reply.m_questions[i].m_qname;
        // Set type to A record
        rr.m_type = htons(1);
        // Set class to IN (Internet)
        rr.m_class = htons(1);
        // Set TTL to 180 seconds
        rr.m_ttl = htonl(180);
        // Set RD length to 4 bytes (binary container for IPv4)
        rr.m_rdLength = htons(4);
        // Set RD data to the spoofed IPv4
        rr.m_rdata = reinterpret_cast<char *>(&m_spoofIP.s_addr);
        // Non-RFC field for calculating data offset
        rr.m_size = reply.m_questions[i].m_size + 4 + 2 + ntohs(rr.m_rdLength);
        reply.m_answers.push_back(rr);
      }

      // Mark response code with no errors
      reply.m_hdr.m_rcode = 0;

      // Serialize reply message from the stream
      std::ostringstream replybuffer;
      replybuffer << reply;

      // Send reply to client
      n = sendto(sockFD, replybuffer.str().c_str(), replybuffer.tellp(), 0,
                 reinterpret_cast<sockaddr *>(&clientAddr), clientLen);
      if (n < replybuffer.tellp()) {
        std::stringstream message;
        message << "What: " << std::strerror(errno) << " - Context: sendto()";
        std::cerr << message.str() << std::endl;
      }
    } catch (std::exception &e) {
      std::cerr << "Failed to parse DNS request: " << e.what()
                << " Ignoring request" << std::endl;
    }
  }
}