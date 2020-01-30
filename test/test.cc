#include <cstring>
#include <iterator>
#include <netinet/in.h>
#include <sstream>
#include <string>
#define CATCH_CONFIG_MAIN

#include <catch.hh>
#include <client.hh>
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

  SECTION("Negative IPv4 octets") {
    std::string address("-1.-4.-44.22");
    REQUIRE_THROWS_MATCHES(
        DNS::Daemon(address), std::runtime_error,
        Catch::Matchers::Message(
            "Address: -1.-4.-44.22 - Not in Presentation Format"));
  }
}

void *daemonRunner(void *arg) {
  DNS::Daemon *daemon = reinterpret_cast<DNS::Daemon *>(arg);
  daemon->run(false);
  return nullptr;
}

DNS::Message *queryDaemon(std::string address,
                          std::vector<std::string> domainLabels) {

  DNS::Daemon daemon(address);
  // Using pthreads over std::thread due to incompatibility with Catch2
  pthread_t thread_id;
  pthread_create(&thread_id, nullptr, daemonRunner, &daemon);

  // Send a DNS query
  sockaddr_in srvAddr{
      .sin_family = AF_INET,
      .sin_port = htons(DNS::Default::PORT),
      .sin_addr.s_addr = htonl(DNS::Default::ADDRESS),
  };

  auto reply = DNS::query(srvAddr, domainLabels, 1, 1);
  daemon.stop();
  pthread_join(thread_id, nullptr);
  return reply;
}

TEST_CASE("DNS daemon responds to lookup requests") {
  SECTION("Simple domain name") {
    std::string address("9.9.9.9");
    in_addr addressNet;
    auto ret = inet_pton(AF_INET, address.c_str(), &addressNet);
    REQUIRE(ret == 1);

    std::vector<std::string> domainLabels;
    domainLabels.push_back("www");
    domainLabels.push_back("meter");
    domainLabels.push_back("com");

    auto reply = queryDaemon(address, domainLabels);
    // Verify success
    CHECK(reply->m_hdr.m_qr == 1);
    CHECK(reply->m_hdr.m_rcode == 0);

    // Verify domain labels
    CHECK(reply->m_questions.size() == 1);
    CHECK(reply->m_answers.size() == 1);
    CHECK(reply->m_questions[0].m_qname == domainLabels);
    CHECK(reply->m_answers[0].m_name == domainLabels);

    // Verify A-record matches our spoof argument
    CHECK(ntohs(reply->m_answers[0].m_rdLength) == 4);
    // Parse answer section IP
    in_addr parsed = {
        .s_addr = *reinterpret_cast<uint32_t *>(reply->m_answers[0].m_rdata),
    };
    CHECK(parsed.s_addr == addressNet.s_addr);
  }

  SECTION("Longest domain name") {
    std::string address("9.9.9.9");
    in_addr addressNet;
    auto ret = inet_pton(AF_INET, address.c_str(), &addressNet);
    REQUIRE(ret == 1);

    std::vector<std::string> domainLabels;
    domainLabels.push_back(
        "141592653589793238462643383279502884197169399375105820974941192");
    domainLabels.push_back(
        "141592653589793238462643383279502884197169399375105820974941192");
    domainLabels.push_back(
        "141592653589793238462643383279502884197169399375105820974941192");
    domainLabels.push_back(
        "1415926535897932384626433832795028841971693993751058209749411");

    auto reply = queryDaemon(address, domainLabels);
    // Verify success
    CHECK(reply->m_hdr.m_qr == 1);
    CHECK(reply->m_hdr.m_rcode == 0);

    // Verify domain labels
    CHECK(reply->m_questions.size() == 1);
    CHECK(reply->m_answers.size() == 1);
    CHECK(reply->m_questions[0].m_qname == domainLabels);
    CHECK(reply->m_answers[0].m_name == domainLabels);

    // Verify A-record matches our spoof argument
    CHECK(ntohs(reply->m_answers[0].m_rdLength) == 4);
    // Parse answer section IP
    in_addr parsed = {
        .s_addr = *reinterpret_cast<uint32_t *>(reply->m_answers[0].m_rdata),
    };
    CHECK(parsed.s_addr == addressNet.s_addr);
  }

  SECTION("Domain names with more than 3 labels") {
    std::string address("9.9.9.9");
    in_addr addressNet;
    auto ret = inet_pton(AF_INET, address.c_str(), &addressNet);
    REQUIRE(ret == 1);

    std::vector<std::string> domainLabels;
    domainLabels.push_back(
        "14159265358979323846264338327950288419716939937510582097494119");
    domainLabels.push_back(
        "14159265358979323846264338327950288419716939937510582097494119");
    domainLabels.push_back(
        "14159265358979323846264338327950288419716939937510582097494119");
    domainLabels.push_back("14159265358979323846264338327950288419");

    auto reply = queryDaemon(address, domainLabels);
    // Verify success
    CHECK(reply->m_hdr.m_qr == 1);
    CHECK(reply->m_hdr.m_rcode == 0);

    // Verify domain labels
    CHECK(reply->m_questions.size() == 1);
    CHECK(reply->m_answers.size() == 1);
    CHECK(reply->m_questions[0].m_qname == domainLabels);
    CHECK(reply->m_answers[0].m_name == domainLabels);

    // Verify A-record matches our spoof argument
    CHECK(ntohs(reply->m_answers[0].m_rdLength) == 4);
    // Parse answer section IP
    in_addr parsed = {
        .s_addr = *reinterpret_cast<uint32_t *>(reply->m_answers[0].m_rdata),
    };
    CHECK(parsed.s_addr == addressNet.s_addr);
  }

  SECTION("0-length QNAME") {
    std::string address("9.9.9.9");
    in_addr addressNet;
    auto ret = inet_pton(AF_INET, address.c_str(), &addressNet);
    REQUIRE(ret == 1);

    std::vector<std::string> domainLabels;

    auto reply = queryDaemon(address, domainLabels);
    // Verify success
    CHECK(reply->m_hdr.m_qr == 1);
    CHECK(reply->m_hdr.m_rcode == 0);

    // Verify domain labels
    CHECK(reply->m_questions.size() == 1);
    CHECK(reply->m_answers.size() == 1);
    CHECK(reply->m_questions[0].m_qname == domainLabels);
    CHECK(reply->m_answers[0].m_name == domainLabels);

    // Verify A-record matches our spoof argument
    CHECK(ntohs(reply->m_answers[0].m_rdLength) == 4);
    // Parse answer section IP
    in_addr parsed = {
        .s_addr = *reinterpret_cast<uint32_t *>(reply->m_answers[0].m_rdata),
    };
    CHECK(parsed.s_addr == addressNet.s_addr);
  }
}

TEST_CASE("Test for invalid message octet lengths") {
  SECTION("QNAME size exceeds 254") {
    std::vector<std::string> domainLabels;
    domainLabels.push_back(
        "141592653589793238462643383279502884197169399375105820974941192");
    domainLabels.push_back(
        "141592653589793238462643383279502884197169399375105820974941192");
    domainLabels.push_back(
        "141592653589793238462643383279502884197169399375105820974941192");
    domainLabels.push_back(
        "14159265358979323846264338327950288419999332323232136346553236");

    sockaddr_in srvAddr{
        .sin_family = AF_INET,
        .sin_port = htons(DNS::Default::PORT),
        .sin_addr.s_addr = htonl(DNS::Default::ADDRESS),
    };

    REQUIRE_THROWS(DNS::query(srvAddr, domainLabels, 1, 1));
  }

  SECTION("0-length label") {
    std::vector<std::string> domainLabels;
    domainLabels.push_back("");

    sockaddr_in srvAddr{
        .sin_family = AF_INET,
        .sin_port = htons(DNS::Default::PORT),
        .sin_addr.s_addr = htonl(DNS::Default::ADDRESS),
    };

    REQUIRE_THROWS(DNS::query(srvAddr, domainLabels, 1, 1));
  }
}