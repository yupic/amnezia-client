/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "daemonlocalserverconnection.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLocalSocket>

#include "daemon.h"
#include "leakdetector.h"
#include "logger.h"

namespace {
Logger logger("DaemonLocalServerConnection");
}

DaemonLocalServerConnection::DaemonLocalServerConnection(QObject* parent,
                                                         QLocalSocket* socket)
    : QObject(parent) {
  MZ_COUNT_CTOR(DaemonLocalServerConnection);

  logger.debug() << "Connection created";

  Q_ASSERT(socket);
  m_socket = socket;

  connect(m_socket, &QLocalSocket::readyRead, this,
          &DaemonLocalServerConnection::readData);

  Daemon* daemon = Daemon::instance();
  connect(daemon, &Daemon::tunnelConnected,
          this, &DaemonLocalServerConnection::onTunnelConnected);
  connect(daemon, &Daemon::tunnelHandshakeFailed,
          this, &DaemonLocalServerConnection::onTunnelHandshakeFailed);
  connect(daemon, &Daemon::disconnected, this,
          &DaemonLocalServerConnection::disconnected);
  connect(daemon, &Daemon::backendFailure, this,
          &DaemonLocalServerConnection::backendFailure);
}

DaemonLocalServerConnection::~DaemonLocalServerConnection() {
  MZ_COUNT_DTOR(DaemonLocalServerConnection);

  logger.debug() << "Connection released";
}

void DaemonLocalServerConnection::readData() {
  logger.debug() << "Read Data";

  Q_ASSERT(m_socket);

  while (true) {
    int pos = m_buffer.indexOf("\n");
    if (pos == -1) {
      QByteArray input = m_socket->readAll();
      if (input.isEmpty()) {
        break;
      }
      m_buffer.append(input);
      continue;
    }

    QByteArray line = m_buffer.left(pos);
    m_buffer.remove(0, pos + 1);

    QByteArray command(line);
    command = command.trimmed();

    if (command.isEmpty()) {
      continue;
    }

    parseCommand(command);
  }
}

void DaemonLocalServerConnection::parseCommand(const QByteArray& data) {
  QJsonDocument json = QJsonDocument::fromJson(data);
  if (!json.isObject()) {
    logger.error() << "Invalid input";
    return;
  }

  QJsonObject obj = json.object();
  QJsonValue typeValue = obj.value("type");
  if (!typeValue.isString()) {
    logger.warning() << "No type command. Ignoring request.";
    return;
  }
  QString type = typeValue.toString();

  logger.debug() << "Command received:" << type;

  // It is expected that sometimes the client will request backend logs
  // before the first authentication. In these cases we just return empty
  // logs.
  if (type == "logs") {
    QJsonObject obj;
    obj.insert("type", "logs");
    obj.insert("logs", "");
    write(obj);
    return;
  }

  if (type == "activate") {
    InterfaceConfig config;
    if (!Daemon::parseConfig(obj, config)) {
      logger.error() << "Invalid configuration";
      disconnected();
      return;
    }
    m_responseStyle[config.m_ifname] = ResponseStyle::LegacyActive;
    if (!Daemon::instance()->activate(config.m_ifname, config) ||
        !Daemon::instance()->setPrimary(config.m_ifname, config)) {
      logger.error() << "Failed to activate the interface";
      Daemon::instance()->deactivateTunnel(config.m_ifname);
      m_responseStyle.remove(config.m_ifname);
      disconnected();
    }
    return;
  }

  if (type == "deactivate") {
    m_responseStyle.clear();
    Daemon::instance()->deactivate(true);
    return;
  }

  if (type == "activateStaging") {
    InterfaceConfig config;
    if (!Daemon::parseConfig(obj, config)) {
      logger.error() << "activateStaging: invalid configuration";
      return;
    }
    m_responseStyle[config.m_ifname] = ResponseStyle::LegacyStaging;
    if (!Daemon::instance()->activate(config.m_ifname, config)) {
      logger.error() << "activateStaging: failed";
      Daemon::instance()->deactivateTunnel(config.m_ifname);
      m_responseStyle.remove(config.m_ifname);
      QJsonObject reply;
      reply.insert("type", "stagingFailed");
      write(reply);
    }
    return;
  }

  if (type == "discardStaging") {
    QString stagingIfname;
    for (auto it = m_responseStyle.constBegin(); it != m_responseStyle.constEnd(); ++it) {
      if (it.value() == ResponseStyle::LegacyStaging) {
        stagingIfname = it.key();
        break;
      }
    }
    if (!stagingIfname.isEmpty()) {
      Daemon::instance()->deactivateTunnel(stagingIfname);
      m_responseStyle.remove(stagingIfname);
    }
    return;
  }

  if (type == "promoteStagingToActive") {
    InterfaceConfig config;
    if (!Daemon::parseConfig(obj, config)) {
      logger.error() << "promoteStagingToActive: invalid configuration";
      return;
    }
    // TODO: Order is broken here, new tunnel should be set primary before deactivating the old one.
    const QString oldPrimary = Daemon::instance()->primaryIfname();
    if (!oldPrimary.isEmpty() && oldPrimary != config.m_ifname) {
      Daemon::instance()->deactivateTunnel(oldPrimary);
      m_responseStyle.remove(oldPrimary);
    }
    if (!Daemon::instance()->setPrimary(config.m_ifname, config)) {
      logger.error() << "promoteStagingToActive failed";
      Daemon::instance()->deactivateTunnel(config.m_ifname);
    }
    return;
  }

  if (type == "setPrimary") {
    InterfaceConfig config;
    if (!Daemon::parseConfig(obj, config)) {
      logger.error() << "setPrimary: invalid configuration";
      return;
    }
    if (!Daemon::instance()->setPrimary(config.m_ifname, config)) {
      logger.error() << "setPrimary failed";
      Daemon::instance()->deactivateTunnel(config.m_ifname);
    }
    return;
  }

  if (type == "status") {
    QJsonObject obj = Daemon::instance()->getStatus();
    obj.insert("type", "status");
    write(obj);
    return;
  }

  if (type == "logs") {
    QJsonObject obj;
    obj.insert("type", "logs");
    obj.insert("logs", Daemon::instance()->logs().replace("\n", "|"));
    write(obj);
    return;
  }

  if (type == "cleanlogs") {
    Daemon::instance()->cleanLogs();
    return;
  }

  logger.warning() << "Invalid command:" << type;
}

void DaemonLocalServerConnection::onTunnelConnected(const QString& ifname,
                                                    const QString& pubkey) {
  const ResponseStyle style =
      m_responseStyle.value(ifname, ResponseStyle::LegacyActive);
  m_responseStyle.remove(ifname);

  QJsonObject obj;
  obj.insert("type", style == ResponseStyle::LegacyStaging ? "stagingConnected"
                                                           : "connected");
  obj.insert("ifname", ifname);
  obj.insert("pubkey", pubkey);
  write(obj);
}

void DaemonLocalServerConnection::onTunnelHandshakeFailed(const QString& ifname) {
  const ResponseStyle style =
      m_responseStyle.value(ifname, ResponseStyle::LegacyActive);
  m_responseStyle.remove(ifname);

  QJsonObject obj;
  obj.insert("type", style == ResponseStyle::LegacyStaging ? "stagingFailed"
                                                           : "disconnected");
  obj.insert("ifname", ifname);
  write(obj);
}

void DaemonLocalServerConnection::disconnected() {
  QJsonObject obj;
  obj.insert("type", "disconnected");
  write(obj);
}

void DaemonLocalServerConnection::backendFailure(DaemonError err) {
  QJsonObject obj;
  obj.insert("type", "backendFailure");
  obj.insert("errorCode", static_cast<int>(err));
  write(obj);
}

void DaemonLocalServerConnection::write(const QJsonObject& obj) {
  m_socket->write(QJsonDocument(obj).toJson(QJsonDocument::Compact));
  m_socket->write("\n");
}
