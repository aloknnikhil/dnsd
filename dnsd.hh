#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace DNS {
namespace Default {
static const uint16_t PORT = 53;
static const uint32_t ADDRESS = INADDR_ANY;
static const uint32_t BACKLOG = 5;
// c.f. https://www.ietf.org/rfc/rfc1035 -
// Max UDP Payload size for classic DNS for IPv4
static const uint16_t BUFFER_SIZE = 512;
} // namespace Default

class Daemon {
public:
  // Accepts a list of records (formatted as A Record/IP address) and returns an
  // instance of a daemon
  Daemon(std::string spoof);

  // Blocking call to run the daemon and bind to port 53 (DNS Spec)
  void run();

  // Hint to stop the daemon
  // In the current implementation, the daemon will continue running until the
  // next request comes in
  void stop() { m_complete = true; }
  ~Daemon();

private:
  struct in_addr m_spoofIP;
  bool m_complete = false;
}; // class Daemon
} // namespace DNS