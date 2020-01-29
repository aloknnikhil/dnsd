#include <stdexcept>
#include <vector>
#define CATCH_CONFIG_MAIN
#include "catch.hh"
#include "dnsd.hh"

TEST_CASE("DNS daemon should be initialized with a valid IP") {
  std::string address("44.33.13.11");

  REQUIRE_NOTHROW(address);
}

TEST_CASE("DNS daemon should NOT be initialized with an empty IP") {
  REQUIRE_THROWS_MATCHES(
      DNS::Daemon(""), std::runtime_error,
      Catch::Matchers::Message("Address:  - Not in Presentation Format"));
}