class QString;
class QHostAddress;

void start_service(const QString &host, const QString &port, const QString &secret);
bool protect(int socket);
int configure(int mtu,
              const QString &address,
              int address_mask,
              const QString &route,
              int route_mask,
              const QString &dns_server,
              const QString &search_domain,
              const QHostAddress &server);
