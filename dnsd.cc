#include "dnsd.hh"
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <utility>

DNS::Daemon::Daemon(std::vector<std::string> records) {
  for (const auto &record : records) {
    std::stringstream iss(record);
    std::string aRecord;
    // Parse A record
    std::getline(iss, aRecord, '/');
    if (aRecord.empty()) {
      std::stringstream message;
      message << "Invalid entry: " << record << std::endl;
      throw std::runtime_error(message.str());
    }

    // Parse IP address
    std::string ip;
    std::getline(iss, ip, '/');
    if (ip.empty()) {
      std::stringstream message;
      message << "Invalid entry: " << record << std::endl;
      throw std::runtime_error(message.str());
    }
    // Validate IP address
    auto inetIP = new struct in_addr();
    auto ret = inet_pton(AF_INET, ip.c_str(), inetIP);
    if (ret <= 0) {
      std::stringstream message;
      if (ret == 0) {
        message << "Address: " << ip << " - Not in Presentation Format"
                << std::endl;
      } else {
        message << "What: " << std::strerror(errno) << " Context: inet_pton("
                << ip << ")" << std::endl;
      }
      throw std::runtime_error(message.str());
    }

    if (m_cache.find(aRecord) != m_cache.end()) {
      std::cerr << "WARN: Duplicate A Record - IP mapping for " << aRecord
                << std::endl;
    }
    m_cache[aRecord] = inetIP;
  }
}

DNS::Daemon::~Daemon() {
  // Do nothing for now
  for (const auto &iter : m_cache) {
    std::cout << "Entry: " << iter.first << " = " << inet_ntoa(*iter.second)
              << std::endl;
  }
}

void DNS::Daemon::run() {
  // Open a UDP socket
  auto sockFD = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockFD == -1) {
    std::stringstream message;
    message << "What: " << std::strerror(errno) << "Context: socket(UDP)"
            << std::endl;
    throw std::runtime_error(message.str());
  }

  // Bind to UDP port (default: 53; address: 0.0.0.0)
}