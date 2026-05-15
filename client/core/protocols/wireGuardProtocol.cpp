#include <QCoreApplication>
#include <QFileInfo>
#include <QProcess>
#include <QTcpSocket>
#include <QThread>

#include "wireGuardProtocol.h"
#include "core/utils/networkUtilities.h"
#include "daemon/wireguardutils.h"

#include "mozilla/localsocketcontroller.h"

WireguardProtocol::WireguardProtocol(const QJsonObject &configuration, QObject *parent)
    : VpnProtocol(configuration, parent)
{
    const QString ifname = configuration.value("ifname").toString(WG_INTERFACE);
    m_impl.reset(new LocalSocketController(ifname));
    connect(m_impl.get(), &ControllerImpl::connected, this,
            [this](const QString& ifname, const QString &pubkey,
                   const QDateTime &connectionTimestamp) {
                Q_UNUSED(ifname)
                setConnectionState(Vpn::ConnectionState::Connected);
            });
    connect(m_impl.get(), &ControllerImpl::statusUpdated, this,
            [this](const QString& serverIpv4Gateway,
                   const QString& deviceIpv4Address, uint64_t txBytes,
                   uint64_t rxBytes) {
                const QString previousGateway = m_vpnGateway;
                const QString previousLocal = m_vpnLocalAddress;

                if (!serverIpv4Gateway.isEmpty()) {
                    m_vpnGateway = serverIpv4Gateway;
                }
                if (!deviceIpv4Address.isEmpty()) {
                    m_vpnLocalAddress = deviceIpv4Address;
                }

                if ((!m_vpnGateway.isEmpty() && m_vpnGateway != previousGateway) ||
                    (!m_vpnLocalAddress.isEmpty() && m_vpnLocalAddress != previousLocal)) {
                        if (m_connectionState == Vpn::ConnectionState::Connected) {
                            emit tunnelAddressesUpdated(m_vpnGateway, m_vpnLocalAddress);
                        }
                    }
            });

    connect(m_impl.get(), &ControllerImpl::disconnected, this,
            [this](const QString& ifname) {
                Q_UNUSED(ifname)
                setConnectionState(Vpn::ConnectionState::Disconnected);
            });
    connect(m_impl.get(), &ControllerImpl::stagingConnected, this,
            [this](const QString& ifname, const QString& pubkey) {
                Q_UNUSED(ifname)
                emit stagingConnected(pubkey);
            });
    connect(m_impl.get(), &ControllerImpl::stagingFailed, this,
            [this](const QString& ifname) {
                Q_UNUSED(ifname)
                emit stagingFailed();
            });
    m_impl->initialize(nullptr, nullptr);
}

WireguardProtocol::~WireguardProtocol()
{
    WireguardProtocol::stop();
    QThread::msleep(200);
}

void WireguardProtocol::stop()
{
    stopMzImpl();
    return;
}

ErrorCode WireguardProtocol::startMzImpl()
{
    QString protocolName = m_rawConfig.value("protocol").toString();
    QJsonObject vpnConfigData = m_rawConfig.value(protocolName + "_config_data").toObject();
    vpnConfigData[configKey::hostName] = NetworkUtilities::getIPAddress(vpnConfigData.value(configKey::hostName).toString());
    m_rawConfig.insert(protocolName + "_config_data", vpnConfigData);
    m_rawConfig[configKey::hostName] = NetworkUtilities::getIPAddress(m_rawConfig[configKey::hostName].toString());

    m_impl->activate(m_rawConfig);
    return ErrorCode::NoError;
}

ErrorCode WireguardProtocol::stopMzImpl()
{
    if (m_abandoned) return ErrorCode::NoError;
    m_impl->deactivate();
    return ErrorCode::NoError;
}

void WireguardProtocol::activateStaging(const QJsonObject& config, const QString& stagingIfname)
{
    m_impl->activateStaging(config, stagingIfname);
}

void WireguardProtocol::discardStaging()
{
    m_impl->discardStaging();
}

void WireguardProtocol::promoteStagingToActive(const QJsonObject& config, const QString& stagingIfname)
{
    m_impl->promoteStagingToActive(config, stagingIfname);
}

void WireguardProtocol::abandon()
{
    m_abandoned = true;
}

void WireguardProtocol::assumeConnected()
{
    setConnectionState(Vpn::ConnectionState::Connected);
}

ErrorCode WireguardProtocol::start()
{
    return startMzImpl();
}
