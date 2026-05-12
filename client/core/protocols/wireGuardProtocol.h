#ifndef WIREGUARDPROTOCOL_H
#define WIREGUARDPROTOCOL_H

#include <QObject>
#include <QProcess>
#include <QString>
#include <QTemporaryFile>
#include <QTimer>

#include "vpnProtocol.h"

#include "mozilla/controllerimpl.h"

class WireguardProtocol : public VpnProtocol
{
    Q_OBJECT

public:
    explicit WireguardProtocol(const QJsonObject& configuration, QObject* parent = nullptr);
    virtual ~WireguardProtocol() override;

    ErrorCode start() override;
    void stop() override;

    void activateStaging(const QJsonObject& config, const QString& stagingIfname) override;
    void discardStaging() override;
    void promoteStagingToActive(const QJsonObject& config, const QString& stagingIfname) override;
    void abandon() override;
    void assumeConnected() override;

    ErrorCode startMzImpl();
    ErrorCode stopMzImpl();

private:
    bool m_abandoned = false;

    QScopedPointer<ControllerImpl> m_impl;
};

#endif // WIREGUARDPROTOCOL_H
