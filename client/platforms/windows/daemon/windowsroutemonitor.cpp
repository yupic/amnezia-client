/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "windowsroutemonitor.h"

#include <QByteArray>
#include <QScopeGuard>

#include "leakdetector.h"
#include "logger.h"

namespace {
Logger logger("WindowsRouteMonitor");

using RouteLookup = QHash<QByteArray, QList<MIB_IPFORWARD_ROW2*>>;
};  // namespace

// Attempt to mark routing entries that we create with a relatively
// high metric. This ensures that we can skip over routes of our own
// creation when processing route changes, and ensures that we give
// way to other routing entries.
constexpr const ULONG EXCLUSION_ROUTE_METRIC = 0x5e72;

static ULONG maxPrefixLength(ADDRESS_FAMILY family) {
  if (family == AF_INET) {
    return 32;
  }
  if (family == AF_INET6) {
    return 128;
  }
  return 0;
}

static QByteArray routeLookupKey(const IP_ADDRESS_PREFIX* prefix,
                                 ULONG prefixLength) {
  QByteArray key;
  prefixLength =
      qMin(prefixLength, maxPrefixLength(prefix->Prefix.si_family));
  key.reserve(18);
  key.append(static_cast<char>(prefix->Prefix.si_family));
  key.append(static_cast<char>(prefixLength));

  QByteArray address;
  if (prefix->Prefix.si_family == AF_INET) {
    address = QByteArray(reinterpret_cast<const char*>(
                             &prefix->Prefix.Ipv4.sin_addr),
                         sizeof(prefix->Prefix.Ipv4.sin_addr));
  } else if (prefix->Prefix.si_family == AF_INET6) {
    address = QByteArray(reinterpret_cast<const char*>(
                             &prefix->Prefix.Ipv6.sin6_addr),
                         sizeof(prefix->Prefix.Ipv6.sin6_addr));
  } else {
    return key;
  }

  const int fullBytes = prefixLength / 8;
  const int partialBits = prefixLength % 8;
  if (fullBytes < address.size()) {
    if (partialBits != 0) {
      uchar value = static_cast<uchar>(address[fullBytes]);
      value &= static_cast<uchar>(0xff << (8 - partialBits));
      address[fullBytes] = static_cast<char>(value);
      for (int i = fullBytes + 1; i < address.size(); ++i) {
        address[i] = 0;
      }
    } else {
      for (int i = fullBytes; i < address.size(); ++i) {
        address[i] = 0;
      }
    }
  }

  key.append(address);
  return key;
}

static RouteLookup buildRouteLookup(PMIB_IPFORWARD_TABLE2 table,
                                    quint64 vpnLuid) {
  RouteLookup lookup;
  for (ULONG i = 0; i < table->NumEntries; ++i) {
    MIB_IPFORWARD_ROW2* row = &table->Table[i];
    if (row->InterfaceLuid.Value == vpnLuid) {
      continue;
    }
    if ((row->Protocol == MIB_IPPROTO_NETMGMT) &&
        (row->Metric == EXCLUSION_ROUTE_METRIC)) {
      continue;
    }

    lookup[routeLookupKey(&row->DestinationPrefix,
                          row->DestinationPrefix.PrefixLength)]
        .append(row);
  }
  return lookup;
}

static ULONG routeMetricFor(const MIB_IPFORWARD_ROW2* row,
                            const QMap<quint64, ULONG>& interfaceMetricsIpv4,
                            const QMap<quint64, ULONG>& interfaceMetricsIpv6) {
  ULONG routeMetric = row->Metric;
  if (row->DestinationPrefix.Prefix.si_family == AF_INET6) {
    if (!interfaceMetricsIpv6.contains(row->InterfaceLuid.Value)) {
      return ULONG_MAX;
    }
    routeMetric += interfaceMetricsIpv6[row->InterfaceLuid.Value];
  } else if (row->DestinationPrefix.Prefix.si_family == AF_INET) {
    if (!interfaceMetricsIpv4.contains(row->InterfaceLuid.Value)) {
      return ULONG_MAX;
    }
    routeMetric += interfaceMetricsIpv4[row->InterfaceLuid.Value];
  } else {
    return ULONG_MAX;
  }

  if (routeMetric < row->Metric) {
    return ULONG_MAX;
  }
  return routeMetric;
}

static void updateExclusionRouteFromLookup(
    MIB_IPFORWARD_ROW2* data, const RouteLookup& lookup,
    const QMap<quint64, ULONG>& interfaceMetricsIpv4,
    const QMap<quint64, ULONG>& interfaceMetricsIpv6) {
  SOCKADDR_INET nexthop = {};
  quint64 bestLuid = 0;
  int bestMatch = -1;
  ULONG bestMetric = ULONG_MAX;

  nexthop.si_family = data->DestinationPrefix.Prefix.si_family;
  const int startPrefixLength = static_cast<int>(
      qMin(data->DestinationPrefix.PrefixLength,
           maxPrefixLength(data->DestinationPrefix.Prefix.si_family)));
  for (int prefixLength = startPrefixLength; prefixLength >= 0;
       --prefixLength) {
    const QList<MIB_IPFORWARD_ROW2*> candidates =
        lookup.value(routeLookupKey(&data->DestinationPrefix, prefixLength));
    if (candidates.isEmpty()) {
      continue;
    }

    for (MIB_IPFORWARD_ROW2* row : candidates) {
      const ULONG routeMetric =
          routeMetricFor(row, interfaceMetricsIpv4, interfaceMetricsIpv6);
      if (routeMetric == ULONG_MAX) {
        continue;
      }
      if ((bestMatch == prefixLength) && (routeMetric >= bestMetric)) {
        continue;
      }

      memcpy(&nexthop, &row->NextHop, sizeof(SOCKADDR_INET));
      bestMatch = prefixLength;
      bestMetric = routeMetric;
      if (prefixLength == data->DestinationPrefix.PrefixLength) {
        bestLuid = 0;  // Don't write if there is already an exact match.
      } else {
        bestLuid = row->InterfaceLuid.Value;
      }
    }

    if (bestMatch == prefixLength) {
      break;
    }
  }

  if (data->InterfaceLuid.Value == bestLuid &&
      memcmp(&nexthop, &data->NextHop, sizeof(SOCKADDR_INET)) == 0) {
    return;
  }

  if (data->InterfaceLuid.Value != 0) {
    DWORD result = DeleteIpForwardEntry2(data);
    if ((result != NO_ERROR) && (result != ERROR_NOT_FOUND)) {
      logger.error() << "Failed to delete route:" << result;
    }
  }

  data->InterfaceLuid.Value = bestLuid;
  memcpy(&data->NextHop, &nexthop, sizeof(SOCKADDR_INET));
  if (data->InterfaceLuid.Value != 0) {
    DWORD result = CreateIpForwardEntry2(data);
    if (result != NO_ERROR) {
      logger.error() << "Failed to update route:" << result;
    }
  }
}

// Called by the kernel on route changes - perform some basic filtering and
// invoke the routeChanged slot to do the real work.
static void routeChangeCallback(PVOID context, PMIB_IPFORWARD_ROW2 row,
                                MIB_NOTIFICATION_TYPE type) {
  WindowsRouteMonitor* monitor = (WindowsRouteMonitor*)context;
  Q_UNUSED(type);

  // Ignore route changes that we created.
  if ((row->Protocol == MIB_IPPROTO_NETMGMT) &&
      (row->Metric == EXCLUSION_ROUTE_METRIC)) {
    return;
  }
  if (monitor->getLuid() == row->InterfaceLuid.Value) {
    return;
  }

  monitor->notifyRouteChanged();
}

// Perform prefix matching comparison on IP addresses in host order.
static int prefixcmp(const void* a, const void* b, size_t bits) {
  size_t bytes = bits / 8;
  if (bytes > 0) {
    int diff = memcmp(a, b, bytes);
    if (diff != 0) {
      return diff;
    }
  }

  if (bits % 8) {
    quint8 avalue = *((const quint8*)a + bytes) >> (8 - bits % 8);
    quint8 bvalue = *((const quint8*)b + bytes) >> (8 - bits % 8);
    return avalue - bvalue;
  }

  return 0;
}

WindowsRouteMonitor::WindowsRouteMonitor(quint64 luid, QObject* parent)
    : QObject(parent), m_luid(luid) {
  MZ_COUNT_CTOR(WindowsRouteMonitor);
  logger.debug() << "WindowsRouteMonitor created.";

  NotifyRouteChange2(AF_INET, routeChangeCallback, this, FALSE, &m_routeHandle);
}

WindowsRouteMonitor::~WindowsRouteMonitor() {
  MZ_COUNT_DTOR(WindowsRouteMonitor);
  CancelMibChangeNotify2(m_routeHandle);

  flushRouteTable(m_exclusionRoutes);
  flushRouteTable(m_clonedRoutes);
  logger.debug() << "WindowsRouteMonitor destroyed.";
}

void WindowsRouteMonitor::updateInterfaceMetrics(int family) {
  PMIB_IPINTERFACE_TABLE table;
  DWORD result = GetIpInterfaceTable(family, &table);
  if (result != NO_ERROR) {
    logger.warning() << "Failed to retrive interface table." << result;
    return;
  }
  auto guard = qScopeGuard([&] { FreeMibTable(table); });

  // Flush the list of interfaces that are valid for routing.
  if ((family == AF_INET) || (family == AF_UNSPEC)) {
    m_interfaceMetricsIpv4.clear();
  }
  if ((family == AF_INET6) || (family == AF_UNSPEC)) {
    m_interfaceMetricsIpv6.clear();
  }

  // Rebuild the list of interfaces that are valid for routing.
  for (ULONG i = 0; i < table->NumEntries; i++) {
    MIB_IPINTERFACE_ROW* row = &table->Table[i];
    if (row->InterfaceLuid.Value == m_luid) {
      continue;
    }
    if (!row->Connected) {
      continue;
    }

    if (row->Family == AF_INET) {
      logger.debug() << "Interface" << row->InterfaceIndex
                     << "is valid for IPv4 routing";
      m_interfaceMetricsIpv4[row->InterfaceLuid.Value] = row->Metric;
    }
    if (row->Family == AF_INET6) {
      logger.debug() << "Interface" << row->InterfaceIndex
                     << "is valid for IPv6 routing";
      m_interfaceMetricsIpv6[row->InterfaceLuid.Value] = row->Metric;
    }
  }
}

// static
bool WindowsRouteMonitor::routeContainsDest(const IP_ADDRESS_PREFIX* route,
                                            const IP_ADDRESS_PREFIX* dest) {
  if (route->Prefix.si_family != dest->Prefix.si_family) {
    return false;
  }
  if (route->PrefixLength > dest->PrefixLength) {
    return false;
  }
  if (route->Prefix.si_family == AF_INET) {
    return prefixcmp(&route->Prefix.Ipv4.sin_addr, &dest->Prefix.Ipv4.sin_addr,
                     route->PrefixLength) == 0;
  } else if (route->Prefix.si_family == AF_INET6) {
    return prefixcmp(&route->Prefix.Ipv6.sin6_addr,
                     &dest->Prefix.Ipv6.sin6_addr, route->PrefixLength) == 0;
  } else {
    return false;
  }
}

// static
QHostAddress WindowsRouteMonitor::prefixToAddress(
    const IP_ADDRESS_PREFIX* dest) {
  if (dest->Prefix.si_family == AF_INET6) {
    return QHostAddress(dest->Prefix.Ipv6.sin6_addr.s6_addr);
  } else if (dest->Prefix.si_family == AF_INET) {
    quint32 addr = htonl(dest->Prefix.Ipv4.sin_addr.s_addr);
    return QHostAddress(addr);
  } else {
    return QHostAddress();
  }
}

bool WindowsRouteMonitor::isRouteExcluded(const IP_ADDRESS_PREFIX* dest) const {
  auto i = m_exclusionRoutes.constBegin();
  while (i != m_exclusionRoutes.constEnd()) {
    const MIB_IPFORWARD_ROW2* row = i.value();
    if (routeContainsDest(&row->DestinationPrefix, dest)) {
      return true;
    }
    i++;
  }
  return false;
}

void WindowsRouteMonitor::updateExclusionRoutes(void* ptable) {
  PMIB_IPFORWARD_TABLE2 table = reinterpret_cast<PMIB_IPFORWARD_TABLE2>(ptable);
  const RouteLookup lookup = buildRouteLookup(table, m_luid);
  for (MIB_IPFORWARD_ROW2* data : m_exclusionRoutes) {
    updateExclusionRouteFromLookup(data, lookup, m_interfaceMetricsIpv4,
                                   m_interfaceMetricsIpv6);
  }
}

void WindowsRouteMonitor::updateCapturedRoutes(int family) {
  if (!m_defaultRouteCapture) {
    return;
  }

  PMIB_IPFORWARD_TABLE2 table;
  DWORD error = GetIpForwardTable2(family, &table);
  if (error == NO_ERROR) {
    updateCapturedRoutes(family, table);
    FreeMibTable(table);
  }
}

void WindowsRouteMonitor::updateCapturedRoutes(int family, void* ptable) {
  PMIB_IPFORWARD_TABLE2 table = reinterpret_cast<PMIB_IPFORWARD_TABLE2>(ptable);
  if (!m_defaultRouteCapture) {
    return;
  }

  for (ULONG i = 0; i < table->NumEntries; i++) {
    MIB_IPFORWARD_ROW2* row = &table->Table[i];
    // Ignore routes into the VPN interface.
    if (row->InterfaceLuid.Value == m_luid) {
      continue;
    }
    // Ignore the default route
    if (row->DestinationPrefix.PrefixLength == 0) {
      continue;
    }
    // Ignore routes of our own creation.
    if ((row->Protocol == MIB_IPPROTO_NETMGMT) &&
        (row->Metric == EXCLUSION_ROUTE_METRIC)) {
      continue;
    }
    // Ignore routes which should be excluded.
    if (isRouteExcluded(&row->DestinationPrefix)) {
      continue;
    }
    QHostAddress destination = prefixToAddress(&row->DestinationPrefix);
    if (destination.isLoopback() || destination.isBroadcast() ||
        destination.isLinkLocal() || destination.isMulticast()) {
      continue;
    }

    // If we get here, this route should be cloned.
    IPAddress prefix(destination, row->DestinationPrefix.PrefixLength);
    MIB_IPFORWARD_ROW2* data = m_clonedRoutes.value(prefix, nullptr);
    if (data != nullptr) {
      // Count the number of matching entries in the main table.
      data->Age++;
      continue;
    }
    logger.debug() << "Capturing route to" << prefix.toString();

    // Clone the route and direct it into the VPN tunnel.
    data = new MIB_IPFORWARD_ROW2;
    InitializeIpForwardEntry(data);
    data->InterfaceLuid.Value = m_luid;
    data->DestinationPrefix = row->DestinationPrefix;
    data->NextHop.si_family = data->DestinationPrefix.Prefix.si_family;

    // Set the rest of the flags for a static route.
    data->ValidLifetime = 0xffffffff;
    data->PreferredLifetime = 0xffffffff;
    data->Metric = 0;
    data->Protocol = MIB_IPPROTO_NETMGMT;
    data->Loopback = false;
    data->AutoconfigureAddress = false;
    data->Publish = false;
    data->Immortal = false;
    data->Age = 0;

    // Route this traffic into the VPN tunnel.
    DWORD result = CreateIpForwardEntry2(data);
    if (result != NO_ERROR) {
      logger.error() << "Failed to update route:" << result;
      delete data;
    } else {
      m_clonedRoutes.insert(prefix, data);
      data->Age++;
    }
  }

  // Finally scan for any routes which were removed from the table. We do this
  // by reusing the age field to count the number of matching entries in the
  // main table.
  auto i = m_clonedRoutes.begin();
  while (i != m_clonedRoutes.end()) {
    MIB_IPFORWARD_ROW2* data = i.value();
    if (data->Age > 0) {
      // Entry is in use, don't delete it.
      data->Age = 0;
      i++;
      continue;
    }
    if ((family != AF_UNSPEC) &&
        (data->DestinationPrefix.Prefix.si_family != family)) {
      // We are not processing updates to this address family.
      i++;
      continue;
    }

    logger.debug() << "Removing route capture for" << i.key().toString();

    // Otherwise, this route is no longer in use.
    DWORD result = DeleteIpForwardEntry2(data);
    if ((result != NO_ERROR) && (result != ERROR_NOT_FOUND)) {
      logger.error() << "Failed to delete route:" << result;
    }
    delete data;
    i = m_clonedRoutes.erase(i);
  }
}

MIB_IPFORWARD_ROW2* WindowsRouteMonitor::createExclusionRouteData(
    const IPAddress& prefix) const {
  MIB_IPFORWARD_ROW2* data = new MIB_IPFORWARD_ROW2;
  InitializeIpForwardEntry(data);
  if (prefix.address().protocol() == QAbstractSocket::IPv6Protocol) {
    Q_IPV6ADDR buf = prefix.address().toIPv6Address();

    memcpy(&data->DestinationPrefix.Prefix.Ipv6.sin6_addr, &buf, sizeof(buf));
    data->DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    data->DestinationPrefix.PrefixLength = prefix.prefixLength();
  } else {
    quint32 buf = prefix.address().toIPv4Address();

    data->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = htonl(buf);
    data->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    data->DestinationPrefix.PrefixLength = prefix.prefixLength();
  }
  data->NextHop.si_family = data->DestinationPrefix.Prefix.si_family;

  // Set the rest of the flags for a static route.
  data->ValidLifetime = 0xffffffff;
  data->PreferredLifetime = 0xffffffff;
  data->Metric = EXCLUSION_ROUTE_METRIC;
  data->Protocol = MIB_IPPROTO_NETMGMT;
  data->Loopback = false;
  data->AutoconfigureAddress = false;
  data->Publish = false;
  data->Immortal = false;
  data->Age = 0;
  return data;
}

bool WindowsRouteMonitor::addExclusionRoute(const IPAddress& prefix) {
  QList<IPAddress> prefixes;
  prefixes.append(prefix);
  return addExclusionRoutes(prefixes);
}

bool WindowsRouteMonitor::addExclusionRoutes(const QList<IPAddress>& prefixes) {
  if (prefixes.isEmpty()) {
    return true;
  }

  logger.info() << "Adding exclusion routes batch:" << prefixes.size();
  bool success = true;
  QHash<IPAddress, MIB_IPFORWARD_ROW2*> pendingRoutes;
  for (const IPAddress& prefix : prefixes) {
    logger.debug() << "Adding exclusion route for" << prefix.toString();

    QHostAddress addr = prefix.address();
    if (addr.isLoopback() || addr.isBroadcast() || addr.isLinkLocal() ||
        addr.isMulticast()) {
      continue;
    }

    if (m_exclusionRoutes.contains(prefix) || pendingRoutes.contains(prefix)) {
      logger.warning() << "Exclusion route already exists";
      success = false;
      continue;
    }

    pendingRoutes[prefix] = createExclusionRouteData(prefix);
  }

  if (pendingRoutes.isEmpty()) {
    return success;
  }

  PMIB_IPFORWARD_TABLE2 table;
  DWORD result = GetIpForwardTable2(AF_UNSPEC, &table);
  if (result != NO_ERROR) {
    logger.error() << "Failed to fetch routing table:" << result;
    for (MIB_IPFORWARD_ROW2* data : pendingRoutes) {
      delete data;
    }
    return false;
  }

  m_bulkRouteUpdate.store(true);
  auto bulkGuard = qScopeGuard([&] {
    FreeMibTable(table);
    m_bulkRouteUpdate.store(false);
    if (m_routeChangePending.exchange(false)) {
      notifyRouteChanged();
    }
  });

  for (auto i = pendingRoutes.constBegin(); i != pendingRoutes.constEnd(); ++i) {
    m_exclusionRoutes[i.key()] = i.value();
  }

  updateInterfaceMetrics(AF_UNSPEC);
  updateCapturedRoutes(AF_UNSPEC, table);
  updateExclusionRoutes(table);

  return success;
}

bool WindowsRouteMonitor::deleteExclusionRoute(const IPAddress& prefix) {
  logger.debug() << "Deleting exclusion route for"
                 << prefix.address().toString();

  MIB_IPFORWARD_ROW2* data = m_exclusionRoutes.take(prefix);
  if (data == nullptr) {
    return true;
  }

  DWORD result = DeleteIpForwardEntry2(data);
  if ((result != ERROR_NOT_FOUND) && (result != NO_ERROR)) {
    logger.error() << "Failed to delete route to"
                   << prefix.toString()
                   << "result:" << result;
  }

  // Captured routes might have changed.
  updateCapturedRoutes(data->DestinationPrefix.Prefix.si_family);

  delete data;
  return true;
}

void WindowsRouteMonitor::flushRouteTable(
    QHash<IPAddress, MIB_IPFORWARD_ROW2*>& table) {
  for (auto i = table.begin(); i != table.end(); i++) {
    MIB_IPFORWARD_ROW2* data = i.value();
    DWORD result = DeleteIpForwardEntry2(data);
    if ((result != ERROR_NOT_FOUND) && (result != NO_ERROR)) {
      logger.error() << "Failed to delete route to"
                     << i.key().toString()
                     << "result:" << result;
    }
    delete data;
  }
  table.clear();
}

void WindowsRouteMonitor::setDetaultRouteCapture(bool enable) {
  m_defaultRouteCapture = enable;

  // Flush any captured routes when disabling the feature.
  if (!m_defaultRouteCapture) {
    flushRouteTable(m_clonedRoutes);
    return;
  }
}

void WindowsRouteMonitor::notifyRouteChanged() {
  if (m_bulkRouteUpdate.load()) {
    m_routeChangePending.store(true);
    return;
  }

  bool expected = false;
  if (!m_routeChangeQueued.compare_exchange_strong(expected, true)) {
    m_routeChangePending.store(true);
    return;
  }

  QMetaObject::invokeMethod(this, "routeChanged", Qt::QueuedConnection);
}

void WindowsRouteMonitor::routeChanged() {
  logger.debug() << "Routes changed";
  m_routeChangePending.store(false);
  auto guard = qScopeGuard([&] {
    m_routeChangeQueued.store(false);
    if (m_routeChangePending.exchange(false)) {
      notifyRouteChanged();
    }
  });

  PMIB_IPFORWARD_TABLE2 table;
  DWORD result = GetIpForwardTable2(AF_UNSPEC, &table);
  if (result != NO_ERROR) {
    logger.error() << "Failed to fetch routing table:" << result;
    return;
  }

  updateInterfaceMetrics(AF_UNSPEC);
  updateCapturedRoutes(AF_UNSPEC, table);
  updateExclusionRoutes(table);

  FreeMibTable(table);
}
