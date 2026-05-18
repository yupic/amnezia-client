#include "xrayProtocol.h"

#include "core/models/protocols/xrayProtocolConfig.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/ipcClient.h"
#include "core/utils/networkUtilities.h"
#include "core/utils/serialization/serialization.h"
#include "ipc.h"

#include <QCryptographicHash>
#include <QJsonDocument>
#include <QTimer>
#include <QJsonObject>
#include <QNetworkInterface>
#include <QtCore/qlogging.h>
#include <QtCore/qobjectdefs.h>
#include <QtCore/qprocess.h>

#include <exception>

#ifdef Q_OS_MACOS
static const QString tunName = "utun22";
#else
static const QString tunName = "tun2";
#endif

XrayProtocol::XrayProtocol(const QJsonObject &configuration, QObject *parent) : VpnProtocol(configuration, parent)
{
    m_vpnGateway = amnezia::protocols::xray::defaultLocalAddr;
    m_vpnLocalAddress = amnezia::protocols::xray::defaultLocalAddr;
    m_routeGateway = NetworkUtilities::getGatewayAndIface().first;

    m_routeMode = static_cast<amnezia::RouteMode>(configuration.value(amnezia::configKey::splitTunnelType).toInt());
    m_remoteAddress = NetworkUtilities::getIPAddress(m_rawConfig.value(amnezia::configKey::hostName).toString());

    const QString primaryDns = configuration.value(amnezia::configKey::dns1).toString();
    m_dnsServers.push_back(QHostAddress(primaryDns));
    if (primaryDns != amnezia::protocols::dns::amneziaDnsIp) {
        const QString secondaryDns = configuration.value(amnezia::configKey::dns2).toString();
        m_dnsServers.push_back(QHostAddress(secondaryDns));
    }

    QJsonObject xrayConfiguration = configuration.value(ProtocolUtils::key_proto_config_data(Proto::Xray)).toObject();
    if (xrayConfiguration.isEmpty()) {
        xrayConfiguration = configuration.value(ProtocolUtils::key_proto_config_data(Proto::SSXray)).toObject();
    }

    if (xrayConfiguration.isEmpty()) {
        qWarning() << "Xray config wrapper is empty";
        m_xrayConfig = {};
    }

    m_xrayConfig = QJsonDocument::fromJson(xrayConfiguration.value(amnezia::configKey::config).toString().toUtf8()).object();
    if (m_xrayConfig.isEmpty()) {
        qWarning() << "Xray config string is not a valid JSON object";
        m_xrayConfig = {};
    }
}

XrayProtocol::~XrayProtocol()
{
    qDebug() << "XrayProtocol::~XrayProtocol()";
    XrayProtocol::stop();
}

ErrorCode XrayProtocol::start()
{
    resetStopGuard();

    qDebug() << "VPN connect [VLESS]: start requested, remote" << m_remoteAddress
             << "route mode" << static_cast<int>(m_routeMode);

    // Inject SOCKS5 auth into the inbound before starting xray.
    // Re-uses existing credentials if the config already has them (e.g. imported config).
    amnezia::serialization::inbounds::InboundCredentials creds;
    try {
        qDebug() << "VPN connect [VLESS]: preparing local SOCKS inbound";
        creds = amnezia::serialization::inbounds::EnsureInboundAuth(m_xrayConfig);
    } catch (const std::exception &e) {
        qCritical() << "VPN connect [VLESS]: failed to prepare local SOCKS inbound:" << e.what();
        return ErrorCode::InternalError;
    }
    m_socksUser = creds.username;
    m_socksPassword = creds.password;
    m_socksPort = creds.port;
    qDebug() << "VPN connect [VLESS]: local SOCKS inbound prepared on 127.0.0.1:" << m_socksPort;

    QString xrayConfigStr = QJsonDocument(m_xrayConfig).toJson(QJsonDocument::Compact);
    if (xrayConfigStr.isEmpty()) {
        qCritical() << "Xray config is empty";
        return ErrorCode::XrayExecutableCrashed;
    }

    xrayConfigStr = amnezia::sanitizeNativeConfig(xrayConfigStr);

    return IpcClient::withInterface(
            [&](QSharedPointer<IpcInterfaceReplica> iface) {
                qDebug() << "VPN connect [VLESS]: starting Xray core";
                auto xrayStart = iface->xrayStartOwned(xrayConfigStr);
                if (!xrayStart.waitForFinished() || xrayStart.returnValue() == 0) {
                    qCritical() << "VPN connect [VLESS]: failed to start Xray core";
                    return ErrorCode::XrayExecutableCrashed;
                }
                m_xrayToken = xrayStart.returnValue();
                qDebug() << "VPN connect [VLESS]: Xray core started";
                return startTun2Socks();
            },
            []() {
                qCritical() << "VPN connect [VLESS]: failed to connect to Amnezia service over IPC";
                return ErrorCode::AmneziaServiceConnectionFailed;
            });
}

void XrayProtocol::stop()
{
    if (guardStop()) {
        return;
    }

    qDebug() << "XrayProtocol::stop()";

    IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> iface) {
        auto disableKillSwitch = iface->disableKillSwitch();
        if (!disableKillSwitch.waitForFinished() || !disableKillSwitch.returnValue())
            qWarning() << "Failed to disable killswitch";

        auto StartRoutingIpv6 = iface->StartRoutingIpv6();
        if (!StartRoutingIpv6.waitForFinished() || !StartRoutingIpv6.returnValue())
            qWarning() << "Failed to start routing ipv6";

        auto restoreResolvers = iface->restoreResolvers();
        if (!restoreResolvers.waitForFinished() || !restoreResolvers.returnValue())
            qWarning() << "Failed to restore resolvers";

        auto deleteTun = iface->deleteTun(tunName);
        if (!deleteTun.waitForFinished() || !deleteTun.returnValue())
            qWarning() << "Failed to delete tun";

        auto xrayStop = iface->xrayStopOwned(m_xrayToken);
        if (!xrayStop.waitForFinished() || !xrayStop.returnValue())
            qWarning() << "Failed to stop xray";
        m_xrayToken = 0;
    });

    if (m_tun2socksProcess) {
        m_tun2socksProcess->blockSignals(true);

#ifndef Q_OS_WIN
        m_tun2socksProcess->terminate();
        auto waitForFinished = m_tun2socksProcess->waitForFinished(1000);
        if (!waitForFinished.waitForFinished() || !waitForFinished.returnValue()) {
            qWarning() << "Failed to terminate tun2socks. Killing the process...";
            m_tun2socksProcess->kill();
        }
#else
        // terminate does not do anything useful on Windows
        // so just kill the process
        m_tun2socksProcess->kill();
#endif

        m_tun2socksProcess->close();
        m_tun2socksProcess.reset();
    }

    setConnectionState(Vpn::ConnectionState::Disconnected);
}

ErrorCode XrayProtocol::startTun2Socks()
{
    qDebug() << "VPN connect [VLESS]: creating privileged tun2socks process";
    m_tun2socksProcess = IpcClient::CreatePrivilegedProcess();
    if (!m_tun2socksProcess || !m_tun2socksProcess->waitForSource()) {
        qCritical() << "VPN connect [VLESS]: failed to create privileged tun2socks process";
        return ErrorCode::AmneziaServiceConnectionFailed;
    }

    const QString proxyUrl = QString("socks5://%1:%2@127.0.0.1:%3").arg(m_socksUser, m_socksPassword, QString::number(m_socksPort));

    m_tun2socksProcess->setProgram(PermittedProcess::Tun2Socks);
    m_tun2socksProcess->setArguments({ "-device", QString("tun://%1").arg(tunName), "-proxy", proxyUrl });
    qDebug() << "VPN connect [VLESS]: starting tun2socks for" << tunName
             << "through local SOCKS port" << m_socksPort;

    connect(
            m_tun2socksProcess.data(), &IpcProcessInterfaceReplica::readyReadStandardError, this, 
            [this]() {
                auto readAllStandardError = m_tun2socksProcess->readAllStandardError();
                if (!readAllStandardError.waitForFinished()) {
                    qWarning() << "VPN connect [VLESS]: failed to read output from tun2socks";
                    return;
                }

                const QString line = readAllStandardError.returnValue();

                if (!line.contains("[TCP]") && !line.contains("[UDP]"))
                    qDebug() << "[tun2socks]:" << line;

                if (line.contains("[STACK] tun://") && line.contains("<-> socks5://")) {
                    disconnect(m_tun2socksProcess.data(), &IpcProcessInterfaceReplica::readyReadStandardOutput, this, nullptr);

                    qDebug() << "VPN connect [VLESS]: tun2socks network stack is ready";
                    if (ErrorCode res = setupRouting(); res != ErrorCode::NoError) {
                        qCritical() << "VPN connect [VLESS]: routing setup failed with error" << res;
                        stop();
                        setLastError(res);
                    } else {
                        qDebug() << "VPN connect [VLESS]: connection established, notifying client";
                        setConnectionState(Vpn::ConnectionState::Connected);
                    }
                }
            },
            Qt::QueuedConnection);

    connect(
            m_tun2socksProcess.data(), &IpcProcessInterfaceReplica::finished, this,
            [this](int exitCode, QProcess::ExitStatus exitStatus) {
                // Check stdout for "resource busy" — the TUN device was not yet released
                // by the previous tun2socks instance. Retry after a short delay.
                bool resourceBusy = false;
                if (m_tun2socksProcess) {
                    auto readOut = m_tun2socksProcess->readAllStandardOutput();
                    if (readOut.waitForFinished()) {
                        resourceBusy = readOut.returnValue().contains("resource busy");
                    }
                }

                if (resourceBusy && m_tun2socksRetryCount < maxTun2SocksRetries) {
                    m_tun2socksRetryCount++;
                    qWarning() << QString("Tun2socks: TUN resource busy, retrying (%1/%2) in %3ms...")
                                      .arg(m_tun2socksRetryCount)
                                      .arg(maxTun2SocksRetries)
                                      .arg(tun2socksRetryDelayMs);
                    QTimer::singleShot(tun2socksRetryDelayMs, this, [this]() {
                        if (ErrorCode err = startTun2Socks(); err != ErrorCode::NoError) {
                            stop();
                            setLastError(err);
                        }
                    });
                    return;
                }

                m_tun2socksRetryCount = 0;

                if (exitStatus == QProcess::ExitStatus::CrashExit) {
                    qCritical() << "VPN connect [VLESS]: tun2socks process crashed";
                } else {
                    qCritical() << QString("VPN connect [VLESS]: tun2socks process exited with %1 exit code").arg(exitCode);
                }
                stop();
                setLastError(ErrorCode::Tun2SockExecutableCrashed);
            },
            Qt::QueuedConnection);

    m_tun2socksProcess->start();
    return ErrorCode::NoError;
}

ErrorCode XrayProtocol::setupRouting()
{
    return IpcClient::withInterface(
            [this](QSharedPointer<IpcInterfaceReplica> iface) -> ErrorCode {
                qDebug() << "VPN connect [VLESS]: configuring TUN, DNS, routes and firewall";
#ifdef Q_OS_WIN
                const int inetAdapterIndex = NetworkUtilities::AdapterIndexTo(QHostAddress(m_remoteAddress));
                qDebug() << "VPN connect [VLESS]: internet adapter index for remote" << m_remoteAddress
                         << "is" << inetAdapterIndex;
#endif
                auto createTun = iface->createTun(tunName, amnezia::protocols::xray::defaultLocalAddr);
                if (!createTun.waitForFinished() || !createTun.returnValue()) {
                    qCritical() << "VPN connect [VLESS]: failed to create or assign IP address for TUN" << tunName;
                    return ErrorCode::InternalError;
                }
                qDebug() << "VPN connect [VLESS]: TUN interface configured" << tunName
                         << amnezia::protocols::xray::defaultLocalAddr;

                auto updateResolvers = iface->updateResolvers(tunName, m_dnsServers);
                if (!updateResolvers.waitForFinished() || !updateResolvers.returnValue()) {
                    qCritical() << "VPN connect [VLESS]: failed to set DNS resolvers for TUN" << tunName;
                    return ErrorCode::InternalError;
                }
                qDebug() << "VPN connect [VLESS]: DNS resolvers configured for TUN" << tunName;

#ifdef Q_OS_WIN
                int vpnAdapterIndex = -1;
                QList<QNetworkInterface> netInterfaces = QNetworkInterface::allInterfaces();
                for (auto &netInterface : netInterfaces) {
                    for (auto &address : netInterface.addressEntries()) {
                        if (m_vpnLocalAddress == address.ip().toString())
                            vpnAdapterIndex = netInterface.index();
                    }
                }
#else
                static const int vpnAdapterIndex = 0;
#endif
                const bool killSwitchEnabled = QVariant(m_rawConfig.value(configKey::killSwitchOption).toString()).toBool();
                if (killSwitchEnabled) {
                    qDebug() << "VPN connect [VLESS]: enabling kill switch";
                    if (vpnAdapterIndex != -1) {
                        QJsonObject config = m_rawConfig;
                        config.insert("vpnServer", m_remoteAddress);

                        auto enableKillSwitch = IpcClient::Interface()->enableKillSwitch(config, vpnAdapterIndex);
                        if (!enableKillSwitch.waitForFinished() || !enableKillSwitch.returnValue()) {
                            qCritical() << "VPN connect [VLESS]: failed to enable kill switch";
                            return ErrorCode::InternalError;
                        }
                        qDebug() << "VPN connect [VLESS]: kill switch enabled";
                    } else
                        qWarning() << "VPN connect [VLESS]: failed to get VPN adapter index, kill switch disabled";
                }

                if (m_routeMode == amnezia::RouteMode::VpnAllSites) {
                    static const QStringList subnets = { "1.0.0.0/8",  "2.0.0.0/7",  "4.0.0.0/6",  "8.0.0.0/5",
                                                         "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1" };

                    qDebug() << "VPN connect [VLESS]: adding default IPv4 routes through TUN";
                    auto routeAddList = iface->routeAddList(m_vpnGateway, subnets);
                    const bool routesFinished = routeAddList.waitForFinished();
                    const int routesAdded = routesFinished ? routeAddList.returnValue() : -1;
                    if (!routesFinished || routesAdded != subnets.count()) {
                        qCritical() << "VPN connect [VLESS]: failed to set routes for TUN, added"
                                    << routesAdded << "of" << subnets.count();
                        return ErrorCode::InternalError;
                    }
                    qDebug() << "VPN connect [VLESS]: default IPv4 routes added through TUN";
                }

                auto StopRoutingIpv6 = iface->StopRoutingIpv6();
                if (!StopRoutingIpv6.waitForFinished() || !StopRoutingIpv6.returnValue()) {
                    qCritical() << "VPN connect [VLESS]: failed to disable IPv6 routing";
                    return ErrorCode::InternalError;
                }
                qDebug() << "VPN connect [VLESS]: IPv6 routing disabled";

#ifdef Q_OS_WIN
                if (inetAdapterIndex != -1 && vpnAdapterIndex != -1) {
                    QJsonObject config = m_rawConfig;
                    config.insert("inetAdapterIndex", inetAdapterIndex);
                    config.insert("vpnAdapterIndex", vpnAdapterIndex);
                    config.insert("vpnGateway", m_vpnGateway);
                    config.insert("vpnServer", m_remoteAddress);

                    auto enablePeerTraffic = iface->enablePeerTraffic(config);
                    if (!enablePeerTraffic.waitForFinished() || !enablePeerTraffic.returnValue()) {
                        qCritical() << "VPN connect [VLESS]: failed to enable peer traffic rules";
                        return ErrorCode::InternalError;
                    }
                    qDebug() << "VPN connect [VLESS]: peer traffic rules enabled";
                } else
                    qWarning() << "VPN connect [VLESS]: failed to get adapter indexes, split tunneling disabled";
#endif
                qDebug() << "VPN connect [VLESS]: routing setup completed";
                return ErrorCode::NoError;
            },
            []() {
                qCritical() << "VPN connect [VLESS]: failed to connect to Amnezia service while setting routes";
                return ErrorCode::AmneziaServiceConnectionFailed;
            });
}
