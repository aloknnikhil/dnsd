#include <iterator>
#include <netinet/in.h>
#include <sstream>
#include <string>
#define CATCH_CONFIG_MAIN

#include "catch.hh"
#include "client.h"
#include <iostream>
#include <pthread.h>
#include <stdexcept>
#include <vector>

TEST_CASE("DNS daemon should be initialized with a valid IPv4 address") {
  SECTION("Test with 0.0.0.0") {
    std::string address("0.0.0.0");
    REQUIRE_NOTHROW(DNS::Daemon(address));
  }

  SECTION("Test with 255.255.255.255") {
    std::string address("255.255.255.255");
    REQUIRE_NOTHROW(DNS::Daemon(address));
  }

  SECTION("Test with 2.3.5.8") {
    std::string address("2.3.5.8");
    REQUIRE_NOTHROW(DNS::Daemon(address));
  }
}

TEST_CASE("DNS daemon should NOT be initialized with an empty IPv4 address") {
  REQUIRE_THROWS_MATCHES(
      DNS::Daemon(""), std::runtime_error,
      Catch::Matchers::Message("Address:  - Not in Presentation Format"));
}

TEST_CASE("DNS daemon should NOT be initialized with an invalid IPv4 address") {

  SECTION("Invalid IPv4 octet range") {
    std::string address("44.33.13.1111");
    REQUIRE_THROWS_MATCHES(
        DNS::Daemon(address), std::runtime_error,
        Catch::Matchers::Message(
            "Address: 44.33.13.1111 - Not in Presentation Format"));
  }

  SECTION("Incomplete IPv4 octets") {
    std::string address("44.33.13");
    REQUIRE_THROWS_MATCHES(
        DNS::Daemon(address), std::runtime_error,
        Catch::Matchers::Message(
            "Address: 44.33.13 - Not in Presentation Format"));
  }

  SECTION("Incomplete IPv4 octets with a separator") {
    std::string address("44.33.13.");
    REQUIRE_THROWS_MATCHES(
        DNS::Daemon(address), std::runtime_error,
        Catch::Matchers::Message(
            "Address: 44.33.13. - Not in Presentation Format"));
  }

  SECTION("Alpha-numeric IPv4 octets") {
    std::string address("A.ff.22.9");
    REQUIRE_THROWS_MATCHES(
        DNS::Daemon(address), std::runtime_error,
        Catch::Matchers::Message(
            "Address: A.ff.22.9 - Not in Presentation Format"));
  }

  SECTION("Alpha-numeric IPv4 octets with Emojis") {
    std::string address("🕺.🎒.👂🏼.🐼");
    REQUIRE_THROWS_MATCHES(
        DNS::Daemon(address), std::runtime_error,
        Catch::Matchers::Message(
            "Address: 🕺.🎒.👂🏼.🐼 - Not in Presentation Format"));
  }
}

void *daemonRunner(void *arg) {
  DNS::Daemon *daemon = reinterpret_cast<DNS::Daemon *>(arg);
  daemon->run(false);
  return nullptr;
}

TEST_CASE("DNS daemon responds to a simple lookup request") {
  std::string address("9.9.9.9");
  DNS::Daemon daemon(address);

  // Using pthreads over std::thread due to incompatibility with Catch2
  pthread_t thread_id;
  pthread_create(&thread_id, nullptr, daemonRunner, &daemon);

  // Send a DNS query
  std::vector<std::string> domainLabels;
  domainLabels.push_back("www");
  domainLabels.push_back("meter");
  domainLabels.push_back("com");

  sockaddr_in srvAddr{
      .sin_family = AF_INET,
      .sin_port = htons(DNS::Default::PORT),
      .sin_addr.s_addr = htonl(DNS::Default::ADDRESS),
  };

  auto reply = DNS::query(srvAddr.sin_addr, domainLabels, 1, 1);
  daemon.stop();
  pthread_join(thread_id, nullptr);

  std::stringstream debug;
  debug << reply;

  std::cout << debug.str() << std::endl;
}