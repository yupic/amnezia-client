#include "tunnelSession.h"

TunnelSession::TunnelSession(const QJsonObject& config,
                              amnezia::DockerContainer container,
                              const QString& tunName,
                              const QString& remoteAddress,
                              QObject* parent)
    : QObject(parent)
    , m_config(config)
    , m_container(container)
    , m_tunName(tunName)
    , m_remoteAddress(remoteAddress)
{}

void TunnelSession::confirmHandshake(const QString& pubkey) {
    emit handshakeConfirmed(pubkey);
}

void TunnelSession::markFailed() {
    emit failed();
}
