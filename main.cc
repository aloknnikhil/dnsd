#include "CLI11.hh"
#include "dnsd.hh"
#include <iostream>
#include <thread>

int main(int argc, char **argv) {
  // Declare a new CLI app for help/usage context generation
  CLI::App app("DNS daemon");

  // Accept a list of DNS resolver entries that map A records to IP addresses
  std::vector<std::string> entries;
  app.add_option(
         "-e,--entries", entries,
         "List of DNS A record entries formatted as: <A Record>/IP Address")
      ->required();

  // Parse input arguments
  CLI11_PARSE(app, argc, argv);

  // Start Daemon (inits resolver and starts server)
  DNS::Daemon daemon(entries);
  auto serve = [&]() { daemon.run(); };
  auto serveThread = std::thread(serve);
  serveThread.join();
  return 0;
} // main()