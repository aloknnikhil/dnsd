#include "CLI11.hh"
#include "dnsd.hh"
#include <iostream>
#include <thread>

int main(int argc, char **argv) {
  // Declare a new CLI app for help/usage context generation
  CLI::App app("DNS daemon");

  // Accept the spoof IP
  std::string address;
  app.add_option("-a,--address", address, "IP address to spoof with")
      ->required();

  // Parse input arguments
  CLI11_PARSE(app, argc, argv);

  // Start Daemon (inits resolver and starts server)
  DNS::Daemon daemon(address);
  auto serve = [&]() { daemon.run(true); };
  auto serveThread = std::thread(serve);

  // Wait for the daemon to finish
  serveThread.join();
  return 0;
} // main()