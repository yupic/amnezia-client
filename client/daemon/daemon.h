/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef DAEMON_H
#define DAEMON_H

#include <QDateTime>
#include <QTimer>

#include "daemon/daemonerrors.h"
#include "daemonerrors.h"
#include "dnsutils.h"
#include "interfaceconfig.h"
#include "iputils.h"
#include "wireguardutils.h"

class Daemon : public QObject {
  Q_OBJECT

 public:
  enum Op {
    Up,
    Down,
  };

  explicit Daemon(QObject* parent);
  ~Daemon();

  static Daemon* instance();

  static bool parseConfig(const QJsonObject& obj, InterfaceConfig& config);

  virtual bool activate(const InterfaceConfig& config);
  virtual bool deactivate(bool emitSignals = true);
  virtual QJsonObject getStatus();

  // Callback before any Activating measure is done
  virtual void prepareActivation(const InterfaceConfig& config, int inetAdapterIndex = 0) {
      Q_UNUSED(config)  };
  virtual void activateSplitTunnel(const InterfaceConfig& config, int vpnAdapterIndex = 0) {
      Q_UNUSED(config)  };

  QString logs();
  void cleanLogs();

  bool activateStaging(const InterfaceConfig& config);
  bool discardStaging();
  bool promoteStagingToActive(const InterfaceConfig& newConfig);

 signals:
  void connected(const QString& pubkey);
  /**
   * Can be fired if a call to activate() was unsucessfull
   * and connected systems should rollback
   */
  void activationFailure();
  void disconnected();
  void backendFailure(DaemonError reason = DaemonError::ERROR_FATAL);
  void stagingConnected(const QString& pubkey);
  void stagingFailed();

 private:
  bool maybeUpdateResolvers(const InterfaceConfig& config);
  bool addExclusionRoute(const IPAddress& address);
  bool delExclusionRoute(const IPAddress& address);
  void checkStagingHandshake();
  QTimer m_stagingHandshakeTimer;
  QTimer m_stagingTimeoutTimer;
  InterfaceConfig m_stagingConfig;

 protected:
  virtual bool run(Op op, const InterfaceConfig& config) {
    Q_UNUSED(op);
    Q_UNUSED(config);
    return true;
  }
  virtual WireguardUtils* wgutils() const = 0;
  virtual WireguardUtils* createWgUtils() = 0;
  virtual void replaceActiveWgUtils(WireguardUtils* newUtils) = 0;

  WireguardUtils* m_stagingWgutils = nullptr;
  virtual bool supportIPUtils() const { return false; }
  virtual IPUtils* iputils() { return nullptr; }
  virtual DnsUtils* dnsutils() { return nullptr; }

  static bool parseStringList(const QJsonObject& obj, const QString& name,
                              QStringList& list);

  void checkHandshake();

  class ConnectionState {
   public:
    ConnectionState(){};
    ConnectionState(const InterfaceConfig& config) { m_config = config; }
    QDateTime m_date;
    InterfaceConfig m_config;
  };
  QMap<InterfaceConfig::HopType, ConnectionState> m_connections;
  QHash<IPAddress, int> m_excludedAddrSet;
  QTimer m_handshakeTimer;
};

#endif  // DAEMON_H
