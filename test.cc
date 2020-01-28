#include <stdexcept>
#include <vector>
#define CATCH_CONFIG_MAIN
#include "catch.hh"
#include "dnsd.hh"

TEST_CASE("DNS daemon should be initialized with a single record") {
  std::vector<std::string> records;
  records.push_back("foo.com/44.33.13.11");

  REQUIRE_NOTHROW(DNS::Daemon(records));
}

TEST_CASE("DNS daemon should NOT be initialized with empty record list") {
  std::vector<std::string> records;

  REQUIRE_THROWS_MATCHES(
      DNS::Daemon(records), std::runtime_error,
      Catch::Matchers::Message(
          "Cannot initialize daemon with empty record list"));
}