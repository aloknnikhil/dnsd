#include "CLI11.hh"
#include <iostream>

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

  for (auto &iter : entries) {
    std::cout << "Entry: " << iter << std::endl;
  }

  return 0;
}