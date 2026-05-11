#ifndef TUNNELSESSION_H
#define TUNNELSESSION_H

#include <QObject>
#include <QJsonObject>
#include "core/utils/containerEnum.h"

class TunnelSession : public QObject {
    Q_OBJECT

public:
    explicit TunnelSession(const QJsonObject& config,
                           amnezia::DockerContainer container,
                           const QString& tunName,
                           const QString& remoteAddress,
                           QObject* parent = nullptr);

    const QString& tunName() const       { return m_tunName; }
    const QString& remoteAddress() const { return m_remoteAddress; }
    amnezia::DockerContainer container() const { return m_container; }
    const QJsonObject& config() const    { return m_config; }

public slots:
    void confirmHandshake(const QString& pubkey);
    void markFailed();

signals:
    void handshakeConfirmed(const QString& pubkey);
    void failed();

private:
    QString m_tunName;
    QString m_remoteAddress;
    amnezia::DockerContainer m_container;
    QJsonObject m_config;
};

#endif // TUNNELSESSION_H
