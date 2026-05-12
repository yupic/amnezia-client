#include "vpnConnection.h"

#include <QDebug>
#include <QEventLoop>
#include <QFile>
#include <QHostInfo>
#include <QJsonObject>
#include <QObject>
#include <QSharedPointer>
#include <QString>
#include <QStringList>
#include <QTimer>

#include <core/configurators/openVpnConfigurator.h>
#include <core/configurators/wireguardConfigurator.h>

#ifdef AMNEZIA_DESKTOP
    #include "core/utils/ipcClient.h"
    #include <core/protocols/wireGuardProtocol.h>
#endif

#ifdef Q_OS_ANDROID
    #include "platforms/android/android_controller.h"
    #include <QThread>

#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include "platforms/ios/ios_controller.h"
#endif

#include "core/utils/networkUtilities.h"
#include "daemon/wireguardutils.h"

using namespace ProtocolUtils;

VpnConnection::VpnConnection(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository, QObject *parent)
    : QObject(parent), m_serversRepository(serversRepository), m_appSettingsRepository(appSettingsRepository), m_checkTimer(this), m_trafficGuard(new VpnTrafficGuard(appSettingsRepository, this))
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    m_checkTimer.setInterval(1000);
    connect(IosController::Instance(), &IosController::connectionStateChanged, this, &VpnConnection::setConnectionState);
    connect(IosController::Instance(), &IosController::bytesChanged, this, &VpnConnection::onBytesChanged);
#endif
}

VpnConnection::~VpnConnection()
{
}

void VpnConnection::onBytesChanged(quint64 receivedBytes, quint64 sentBytes)
{
    emit bytesChanged(receivedBytes, sentBytes);
}

void VpnConnection::onKillSwitchModeChanged(bool enabled)
{
#ifdef AMNEZIA_DESKTOP
    IpcClient::withInterface([enabled](QSharedPointer<IpcInterfaceReplica> iface){
        QRemoteObjectPendingReply<bool> reply = iface->refreshKillSwitch(enabled);
        if (reply.waitForFinished() && reply.returnValue())
            qDebug() << "VpnConnection::onKillSwitchModeChanged: Killswitch refreshed";
        else
            qWarning() << "VpnConnection::onKillSwitchModeChanged: Failed to execute remote refreshKillSwitch call";
    });
#endif
}

void VpnConnection::onConnectionStateChanged(Vpn::ConnectionState state)
{
#ifdef AMNEZIA_DESKTOP
    switch (state) {
        case Vpn::ConnectionState::Connected: {
            m_trafficGuard->setupRoutes(m_active->config(), m_vpnProtocol, m_active->remoteAddress());
        } break;
        default:
            break;
    }
#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    if (state == Vpn::ConnectionState::Connected ||
        state == Vpn::ConnectionState::Connecting ||
        state == Vpn::ConnectionState::Reconnecting) {
        m_checkTimer.start();
    } else {
        m_checkTimer.stop();
    }
#endif
}

void VpnConnection::setRepositories(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository)
{
    m_serversRepository = serversRepository;
    m_appSettingsRepository = appSettingsRepository;
    m_trafficGuard.reset(new VpnTrafficGuard(appSettingsRepository, this));
}

QSharedPointer<VpnProtocol> VpnConnection::vpnProtocol() const
{
    return m_vpnProtocol;
}

void VpnConnection::disconnectSlots()
{
    if (m_vpnProtocol) {
        m_vpnProtocol->disconnect();
    }
}

ErrorCode VpnConnection::lastError() const
{
#ifdef Q_OS_ANDROID
    return ErrorCode::AndroidError;
#endif

    if (m_vpnProtocol.isNull()) {
        return ErrorCode::InternalError;
    }

    return m_vpnProtocol.data()->lastError();
}

Vpn::ConnectionState VpnConnection::connectionState() const
{
    return m_connectionState;
}

void VpnConnection::connectToVpn(int serverIndex, DockerContainer container, const QJsonObject &vpnConfiguration)
{
    if (!m_appSettingsRepository || !m_serversRepository) {
        qCritical() << "VpnConnection::connectToVpn: repositories not initialized";
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }

    qDebug() << QString("Trying to connect to VPN, server index is %1, container is %2, route mode is")
                        .arg(serverIndex)
                        .arg(ContainerUtils::containerToString(container))
             << m_appSettingsRepository->routeMode();

    const QString resolvedRemote =
        NetworkUtilities::getIPAddress(vpnConfiguration.value(configKey::hostName).toString());

#ifdef AMNEZIA_DESKTOP
    if (m_vpnProtocol != nullptr
            && m_connectionState == Vpn::ConnectionState::Connected
            && VpnProtocol::isWireGuardBased(container)
            && m_active && VpnProtocol::isWireGuardBased(m_active->container())) {
        if (!m_trafficGuard->allowEndpoint(resolvedRemote)) {
            setConnectionState(Vpn::ConnectionState::Error);
            emit vpnProtocolError(ErrorCode::AmneziaServiceConnectionFailed);
            return;
        }
        startStagingSwitch(container, vpnConfiguration);
        return;
    }

    if (!m_trafficGuard->allowEndpoint(resolvedRemote)) {
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(ErrorCode::AmneziaServiceConnectionFailed);
        return;
    }
#endif
    setConnectionState(Vpn::ConnectionState::Connecting);

    QJsonObject config = vpnConfiguration;

#ifdef AMNEZIA_DESKTOP
    if (m_vpnProtocol) {
        disconnect(m_vpnProtocol.data(), &VpnProtocol::protocolError, this, &VpnConnection::vpnProtocolError);
        m_trafficGuard->teardown();
        m_vpnProtocol->stop();
        m_vpnProtocol.reset();
    }
    appendKillSwitchConfig(config);
#endif

    appendSplitTunnelingConfig(config);

    delete m_active;
    m_active = new TunnelSession(config, container, WG_INTERFACE, resolvedRemote, this);

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    m_vpnProtocol.reset(VpnProtocol::factory(container, m_active->config()));
    if (!m_vpnProtocol) {
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }
    m_vpnProtocol->prepare();
    m_trafficGuard->setConfig(m_active->config());
#elif defined Q_OS_ANDROID
    androidVpnProtocol = createDefaultAndroidVpnProtocol();
    createAndroidConnections();

    m_vpnProtocol.reset(androidVpnProtocol);
#elif defined Q_OS_IOS || defined(MACOS_NE)
    Proto proto = ContainerUtils::defaultProtocol(container);
    IosController::Instance()->connectVpn(proto, m_active->config());
    connect(&m_checkTimer, &QTimer::timeout, IosController::Instance(), &IosController::checkStatus);
    return;
#endif

    createProtocolConnections();

    if (ErrorCode err = m_vpnProtocol->start(); err != ErrorCode::NoError) {
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(err);
    }
}

void VpnConnection::createProtocolConnections()
{
    connect(m_vpnProtocol.data(), &VpnProtocol::protocolError, this, &VpnConnection::vpnProtocolError);
    connect(m_vpnProtocol.data(), &VpnProtocol::connectionStateChanged, this, &VpnConnection::setConnectionState);
    connect(m_vpnProtocol.data(), SIGNAL(bytesChanged(quint64, quint64)), this, SLOT(onBytesChanged(quint64, quint64)));
    connect(m_vpnProtocol.data(), &VpnProtocol::tunnelAddressesUpdated, m_trafficGuard.data(), &VpnTrafficGuard::applyFirewall);

#ifdef AMNEZIA_DESKTOP
    IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> rep) {
        connect(rep.data(), &IpcInterfaceReplica::networkChanged, this, &VpnConnection::reconnectToVpn, Qt::QueuedConnection);
        connect(rep.data(), &IpcInterfaceReplica::wakeup, this, &VpnConnection::reconnectToVpn, Qt::QueuedConnection);
    });
#endif
}

void VpnConnection::appendKillSwitchConfig(QJsonObject &config)
{
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::appendKillSwitchConfig: repositories not initialized";
        return;
    }

    config.insert(configKey::killSwitchOption, QVariant(m_appSettingsRepository->isKillSwitchEnabled()).toString());
    config.insert(configKey::allowedDnsServers, QVariant(m_appSettingsRepository->getAllowedDnsServers()).toJsonValue());
}

void VpnConnection::appendSplitTunnelingConfig(QJsonObject &config)
{
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::appendSplitTunnelingConfig: repositories not initialized";
        return;
    }

    bool allowSiteBasedSplitTunneling = true;

    // this block is for old native configs and for old self-hosted configs
    auto protocolName = config.value(configKey::vpnProto).toString();
    if (protocolName == ProtocolUtils::protoToString(Proto::Awg) || protocolName == ProtocolUtils::protoToString(Proto::WireGuard)) {
        allowSiteBasedSplitTunneling = false;
        auto configData = config.value(protocolName + "_config_data").toObject();
        if (configData.value(configKey::allowedIps).isString()) {
            QJsonArray allowedIpsJsonArray = QJsonArray::fromStringList(configData.value(configKey::allowedIps).toString().split(", "));
            configData.insert(configKey::allowedIps, allowedIpsJsonArray);
            config.insert(protocolName + "_config_data", configData);
        } else if (configData.value(configKey::allowedIps).isUndefined()) {
            auto nativeConfig = configData.value(configKey::config).toString();
            auto nativeConfigLines = nativeConfig.split("\n");
            for (auto &line : nativeConfigLines) {
                if (line.contains("AllowedIPs")) {
                    auto allowedIpsString = line.split(" = ");
                    if (allowedIpsString.size() < 1) {
                        break;
                    }
                    QJsonArray allowedIpsJsonArray = QJsonArray::fromStringList(allowedIpsString.at(1).split(", "));
                    configData.insert(configKey::allowedIps, allowedIpsJsonArray);
                    config.insert(protocolName + "_config_data", configData);
                    break;
                }
            }
        }

        if (configData.value(configKey::persistentKeepAlive).isUndefined()) {
            auto nativeConfig = configData.value(configKey::config).toString();
            auto nativeConfigLines = nativeConfig.split("\n");
            for (auto &line : nativeConfigLines) {
                if (line.contains("PersistentKeepalive")) {
                    auto persistentKeepaliveString = line.split(" = ");
                    if (persistentKeepaliveString.size() < 1) {
                        break;
                    }
                    configData.insert(configKey::persistentKeepAlive, persistentKeepaliveString.at(1));
                    config.insert(protocolName + "_config_data", configData);
                    break;
                }
            }
        }

        QJsonArray allowedIpsJsonArray = configData.value(configKey::allowedIps).toArray();
        if (allowedIpsJsonArray.contains("0.0.0.0/0") && allowedIpsJsonArray.contains("::/0")) {
            allowSiteBasedSplitTunneling = true;
        }
    }

    amnezia::RouteMode routeMode = amnezia::RouteMode::VpnAllSites;
    QJsonArray sitesJsonArray;
    if (m_appSettingsRepository->isSitesSplitTunnelingEnabled()) {
        routeMode = m_appSettingsRepository->routeMode();

        if (allowSiteBasedSplitTunneling) {
            QStringList sites;
            const QVariantMap &m = m_appSettingsRepository->vpnSites(routeMode);
            for (auto i = m.constBegin(); i != m.constEnd(); ++i) {
                if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
                    sites.append(i.key());
                } else if (NetworkUtilities::checkIpSubnetFormat(i.value().toString())) {
                    sites.append(i.value().toString());
                }
            }
            sites.removeDuplicates();
            for (const auto &site : sites) {
                sitesJsonArray.append(site);
            }

            if (sitesJsonArray.isEmpty()) {
                routeMode = amnezia::RouteMode::VpnAllSites;
            } else if (routeMode == amnezia::RouteMode::VpnOnlyForwardSites) {
                // Allow traffic to Amnezia DNS
                sitesJsonArray.append(config.value(configKey::dns1).toString());
                sitesJsonArray.append(config.value(configKey::dns2).toString());
            }
        }
    }

    config.insert(configKey::splitTunnelType, routeMode);
    config.insert(configKey::splitTunnelSites, sitesJsonArray);

    amnezia::AppsRouteMode appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
    QJsonArray appsJsonArray;
    if (m_appSettingsRepository->isAppsSplitTunnelingEnabled()) {
        appsRouteMode = m_appSettingsRepository->appsRouteMode();

        auto apps = m_appSettingsRepository->vpnApps(appsRouteMode);
        for (const auto &app : apps) {
            appsJsonArray.append(app.appPath.isEmpty() ? app.packageName : app.appPath);
        }

        if (appsJsonArray.isEmpty()) {
            appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
        }
    }

    config.insert(configKey::appSplitTunnelType, appsRouteMode);
    config.insert(configKey::splitTunnelApps, appsJsonArray);

    qDebug() << QString("Site split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isSitesSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(routeMode);
    qDebug() << QString("App split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isAppsSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(appsRouteMode);
}

#ifdef Q_OS_ANDROID
void VpnConnection::restoreConnection()
{
    createAndroidConnections();

    m_vpnProtocol.reset(androidVpnProtocol);

    createProtocolConnections();
}

void VpnConnection::createAndroidConnections()
{
    androidVpnProtocol = createDefaultAndroidVpnProtocol();

    connect(AndroidController::instance(), &AndroidController::connectionStateChanged, androidVpnProtocol,
            &AndroidVpnProtocol::setConnectionState);
    connect(AndroidController::instance(), &AndroidController::statisticsUpdated, androidVpnProtocol, &AndroidVpnProtocol::setBytesChanged);
}

AndroidVpnProtocol *VpnConnection::createDefaultAndroidVpnProtocol()
{
    return new AndroidVpnProtocol(m_active->config());
}
#endif

QString VpnConnection::bytesPerSecToText(quint64 bytes)
{
    double mbps = bytes * 8 / 1e6;
    return QString("%1 %2").arg(QString::number(mbps, 'f', 2)).arg(tr("Mbps")); // Mbit/s
}

void VpnConnection::reconnectToVpn() {
    if (m_vpnProtocol.isNull())
        return;

    if (m_connectionState != Vpn::ConnectionState::Connected) {
        qWarning() << QString("Reconnect triggered on %1 during inappropriate state: %2; ignoring slot")
                              .arg(QMetaEnum::fromType<Vpn::ConnectionState>().valueToKey(m_connectionState));
        return;
    }

    qDebug() << "Reconnect triggered. Reconnecting to the server";

    setConnectionState(Vpn::ConnectionState::Reconnecting);

    m_vpnProtocol->stop();
    if (ErrorCode err = m_vpnProtocol->start(); err != ErrorCode::NoError) {
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(err);
    }
}

void VpnConnection::disconnectFromVpn()
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    // iOS/macOS NE use IosController directly; m_vpnProtocol is not set there.
    IosController::Instance()->disconnectVpn();
    disconnect(&m_checkTimer, &QTimer::timeout, IosController::Instance(), &IosController::checkStatus);
#endif

    if (m_vpnProtocol.isNull()) {
        setConnectionState(Vpn::ConnectionState::Disconnected);
        return;
    }

    setConnectionState(Vpn::ConnectionState::Disconnecting);

#ifdef Q_OS_ANDROID
    auto *const connection = new QMetaObject::Connection;
    *connection = connect(AndroidController::instance(), &AndroidController::vpnStateChanged, this,
                          [this, connection](AndroidController::ConnectionState state) {
                              if (state == AndroidController::ConnectionState::DISCONNECTED) {
                                  setConnectionState(Vpn::ConnectionState::Disconnected);
                                  disconnect(*connection);
                                  delete connection;
                              }
                          });
#endif
#ifdef AMNEZIA_DESKTOP
    m_trafficGuard->teardown();
#endif
    m_vpnProtocol->stop();

    delete m_active;
    m_active = nullptr;
    delete m_staging;
    m_staging = nullptr;

#if !defined(Q_OS_ANDROID) && !defined(AMNEZIA_DESKTOP)
    m_vpnProtocol->deleteLater();
#endif

    m_vpnProtocol = nullptr;
}

void VpnConnection::setConnectionState(Vpn::ConnectionState state) {
    onConnectionStateChanged(state);

    if (state == Vpn::Disconnected && m_connectionState == Vpn::Reconnecting)
        return;

    m_connectionState = state;
    emit connectionStateChanged(state);
}

void VpnConnection::startStagingSwitch(DockerContainer container,
                                        const QJsonObject &vpnConfiguration)
{
    disconnect(m_vpnProtocol.data(), &VpnProtocol::tunnelAddressesUpdated,
               m_trafficGuard.data(), &VpnTrafficGuard::applyFirewall);
    disconnect(m_vpnProtocol.data(), &VpnProtocol::connectionStateChanged,
               this, &VpnConnection::setConnectionState);

    const QString newRemoteAddress =
        NetworkUtilities::getIPAddress(vpnConfiguration.value(configKey::hostName).toString());

    const QString stagingIfname = (m_active->tunName() == QString(WG_INTERFACE))
        ? QString(WG_STAGING_INTERFACE)
        : QString(WG_INTERFACE);

    QJsonObject config = vpnConfiguration;
#ifdef AMNEZIA_DESKTOP
    appendKillSwitchConfig(config);
#endif
    appendSplitTunnelingConfig(config);

    m_staging = new TunnelSession(config, container,
                                   stagingIfname, newRemoteAddress, this);

    connect(m_staging, &TunnelSession::handshakeConfirmed,
            this, &VpnConnection::onStagingHandshakeConfirmed,
            static_cast<Qt::ConnectionType>(Qt::QueuedConnection | Qt::UniqueConnection));
    connect(m_staging, &TunnelSession::failed,
            this, &VpnConnection::onStagingFailed,
            static_cast<Qt::ConnectionType>(Qt::QueuedConnection | Qt::UniqueConnection));

    connect(m_vpnProtocol.data(), &VpnProtocol::stagingConnected,
            m_staging, &TunnelSession::confirmHandshake, Qt::UniqueConnection);
    connect(m_vpnProtocol.data(), &VpnProtocol::stagingFailed,
            m_staging, &TunnelSession::markFailed, Qt::UniqueConnection);

    setConnectionState(Vpn::ConnectionState::Switching);

    m_vpnProtocol->activateStaging(m_staging->config(), stagingIfname);
}

void VpnConnection::onStagingHandshakeConfirmed(const QString &pubkey)
{
    Q_UNUSED(pubkey);
    Q_ASSERT(m_staging);

    m_vpnProtocol->promoteStagingToActive(m_staging->config(), m_staging->tunName());

    m_trafficGuard->revokeEndpoint(m_active->remoteAddress());

    disconnect(m_vpnProtocol.data(), &VpnProtocol::protocolError,
               this, &VpnConnection::vpnProtocolError);
    m_vpnProtocol->abandon();
    m_vpnProtocol.reset();

    delete m_active;
    m_active = m_staging;
    m_staging = nullptr;

    m_vpnProtocol.reset(VpnProtocol::factory(m_active->container(), m_active->config()));
    if (!m_vpnProtocol) {
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }
    m_vpnProtocol->prepare();
    m_vpnProtocol->assumeConnected();
    m_trafficGuard->setConfig(m_active->config());

    setConnectionState(Vpn::ConnectionState::Connected);
    createProtocolConnections();

    const QString proto = m_active->config().value("protocol").toString();
    const QJsonObject vpnCfg = m_active->config().value(proto + "_config_data").toObject();
    m_trafficGuard->applyFirewall(m_active->remoteAddress(), vpnCfg.value(configKey::clientIp).toString());
}

void VpnConnection::onStagingFailed()
{
    Q_ASSERT(m_staging);

    m_vpnProtocol->discardStaging();

    m_trafficGuard->revokeEndpoint(m_staging->remoteAddress());

    disconnect(m_vpnProtocol.data(), &VpnProtocol::stagingConnected,
               m_staging, &TunnelSession::confirmHandshake);
    disconnect(m_vpnProtocol.data(), &VpnProtocol::stagingFailed,
               m_staging, &TunnelSession::markFailed);

    delete m_staging;
    m_staging = nullptr;

    connect(m_vpnProtocol.data(), &VpnProtocol::connectionStateChanged,
            this, &VpnConnection::setConnectionState, Qt::UniqueConnection);
    connect(m_vpnProtocol.data(), &VpnProtocol::tunnelAddressesUpdated,
            m_trafficGuard.data(), &VpnTrafficGuard::applyFirewall, Qt::UniqueConnection);

    setConnectionState(Vpn::ConnectionState::Connected);
    emit serverSwitchFailed();
}
