#include "tunnel.h"

#include <QTimer>

#include "daemon/interfaceconfig.h"

Tunnel::Tunnel(QString ifname,
               amnezia::DockerContainer container,
               QJsonObject config,
               QString remoteAddress,
               QObject* parent)
    : QObject(parent),
      m_ifname(std::move(ifname)),
      m_remoteAddress(std::move(remoteAddress)),
      m_container(container),
      m_config(std::move(config)) {}

Tunnel::~Tunnel() = default;

void Tunnel::prepare() {
    if (m_state != State::Idle && m_state != State::Failed) {
        return;
    }

    setState(State::Preparing);

    m_protocol.reset(VpnProtocol::factory(m_container, m_config));
    if (!m_protocol) {
        setState(State::Failed);
        emit failed(amnezia::ErrorCode::InternalError);
        return;
    }

    connect(m_protocol.data(), &VpnProtocol::connectionStateChanged,
            this, &Tunnel::onProtocolStateChanged);
    connect(m_protocol.data(), &VpnProtocol::bytesChanged,
            this, &Tunnel::bytesChanged);
    connect(m_protocol.data(), &VpnProtocol::tunnelAddressesUpdated,
            this, &Tunnel::addressesUpdated);

    startActivationDeadline(ACTIVATION_TIMEOUT_MSEC);

    const amnezia::ErrorCode err = m_protocol->start();
    if (err != amnezia::ErrorCode::NoError) {
        cancelActivationDeadline();
        setState(State::Failed);
        emit failed(err);
    }
}

void Tunnel::commit() {
    if (m_state != State::Prepared) {
        return;
    }
    setState(State::Committing);
    setState(State::Active);
    emit activated();
}

void Tunnel::deactivate() {
    if (m_state == State::Gone || m_state == State::Idle) {
        return;
    }
    cancelActivationDeadline();
    setState(State::TearingDown);
    if (m_protocol) {
        m_protocol->stop();
    }
    setState(State::Gone);
}

void Tunnel::setState(State next) {
    if (m_state == next) {
        return;
    }
    m_state = next;
    emit stateChanged(m_state);
}

void Tunnel::startActivationDeadline(int msec) {
    if (!m_deadline) {
        m_deadline = new QTimer(this);
        m_deadline->setSingleShot(true);
        connect(m_deadline, &QTimer::timeout, this, [this]() {
            if (m_state != State::Preparing) {
                return;
            }
            setState(State::Failed);
            emit failed(amnezia::ErrorCode::InternalError);
        });
    }
    m_deadline->start(msec);
}

void Tunnel::cancelActivationDeadline() {
    if (m_deadline) {
        m_deadline->stop();
    }
}

void Tunnel::onProtocolStateChanged(Vpn::ConnectionState state) {
    if (m_state == State::Preparing && state == Vpn::ConnectionState::Connected) {
        cancelActivationDeadline();
        setState(State::Prepared);
        emit prepared();
        return;
    }
    if (m_state == State::Preparing && state == Vpn::ConnectionState::Error) {
        cancelActivationDeadline();
        setState(State::Failed);
        emit failed(m_protocol ? m_protocol->lastError() : amnezia::ErrorCode::InternalError);
    }
}
