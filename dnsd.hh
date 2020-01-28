#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace DNS {
namespace Default {
static const uint16_t PORT = 53;
static const uint32_t ADDRESS = 0;
} // namespace Default

class Daemon {
public:
  // Accepts a list of records (formatted as A Record/IP address) and returns an
  // instance of a daemon
  Daemon(std::vector<std::string> records);

  // Blocking call to run the daemon and bind to port 53 (DNS Spec)
  void run();

  // Hint to stop the daemon
  // In the current implementation, the daemon will continue running until the
  // next request comes in
  void stop();
  ~Daemon();

private:
  std::unordered_map<std::string, struct in_addr *> m_cache;
  bool m_complete = false;
}; // class Daemon
} // namespace DNS