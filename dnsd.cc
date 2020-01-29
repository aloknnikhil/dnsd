#include "dnsd.hh"
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <utility>

DNS::Daemon::Daemon(std::string spoof) {

  // Validate IP address
  auto inetIP = new struct in_addr();
  auto ret = inet_pton(AF_INET, spoof.c_str(), inetIP);
  if (ret <= 0) {
    std::stringstream message;
    if (ret == 0) {
      message << "Address: " << spoof << " - Not in Presentation Format";
    } else {
      message << "What: " << std::strerror(errno) << " Context: inet_pton("
              << spoof << ")";
    }
    throw std::runtime_error(message.str());
  }
  m_spoofIP = spoof;
}

DNS::Daemon::~Daemon() {
  // Do nothing for now
}

void DNS::Daemon::run() {
  // Open a UDP socket
  auto sockFD = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockFD == -1) {
    std::stringstream message;
    message << "What: " << std::strerror(errno) << "Context: socket(UDP)";
    throw std::runtime_error(message.str());
  }

  // Bind to UDP port (default: 53; address: 0.0.0.0)
}