/*
 * Copyright (c) 2009 Steve Gribble (gribble [at] cs.washington.edu) and
 *                    Mark Liversedge (liversedge@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>

#include "TLSServerController.h"

#include <cmath>

#include "QtWebSockets/QWebSocketServer"
#include <QtWebSockets/QWebSocket>
#include <QtCore/QByteArray>
#include <QtNetwork/QSslError>
//#include "QtWebSockets/QWebSocketServer"
//#include "QtWebSockets/QWebSocket"
#include <QtCore/QDebug>
#include <QtCore/QFile>
#include <QtNetwork/QSslCertificate>
#include <QtNetwork/QSslKey>
#include <QTime>
TLSServerController::TLSServerController(TrainSidebar *parent,
                                                 DeviceConfiguration *dc)
  : RealtimeController(parent, dc), parent(parent)
{
    m_pWebSocketServer = 0;
    if (dc != NULL)
    {
        port = dc->portSpec.toUInt();
    }
    else
    {
        port = 41320;
    }
}

TLSServerController::~TLSServerController()
{
    if (m_pWebSocketServer != NULL)
    {
        m_pWebSocketServer->close();
    }
    qDeleteAll(m_clients.begin(), m_clients.end());
}

void TLSServerController::onNewConnection()
{
    QWebSocket *pSocket = m_pWebSocketServer->nextPendingConnection();

    qDebug() << "Client connected:" << pSocket->peerName() << pSocket->origin();

    connect(pSocket, &QWebSocket::textMessageReceived, this, &TLSServerController::processTextMessage);
    connect(pSocket, &QWebSocket::binaryMessageReceived,
            this, &TLSServerController::processBinaryMessage);
    connect(pSocket, &QWebSocket::disconnected, this, &TLSServerController::socketDisconnected);
    //connect(pSocket, &QWebSocket::pong, this, &SslEchoServer::processPong);

    m_clients << pSocket;
}
//! [onNewConnection]

//! [processTextMessage]
void TLSServerController::processTextMessage(QString message)
{
    QWebSocket *pClient = qobject_cast<QWebSocket *>(sender());
    if (pClient)
    {
        QString valueFromMessage;
        if (message.left(4) == QStringLiteral("bpm:"))
        {
            valueFromMessage = message.replace(QStringLiteral("bpm:"),QStringLiteral(""));
            telemetry.setHr(valueFromMessage.toFloat());
        }

        if (message.left(4) == QStringLiteral("cad:"))
        {
            valueFromMessage = message.replace(QStringLiteral("cad:"),QStringLiteral(""));
            telemetry.setCadence(valueFromMessage.toDouble());
        }

        if (message.left(4) == QStringLiteral("rpm:"))
        {
            valueFromMessage = message.replace(QStringLiteral("rpm:"),QStringLiteral(""));
            telemetry.setWheelRpm(valueFromMessage.toDouble());
        }

        if (message.left(4) == QStringLiteral("pow:"))
        {
            valueFromMessage = message.replace(QStringLiteral("pow:"),QStringLiteral(""));
            telemetry.setWatts(valueFromMessage.toDouble());
        }
        QTime qtime = QTime::currentTime();
        qDebug() << qtime.toString() << " | " << "Message from client: " << message;
        //pClient->sendTextMessage(message);
    }
}
//! [processTextMessage]

//! [processBinaryMessage]
void TLSServerController::processBinaryMessage(QByteArray message)
{
    QWebSocket *pClient = qobject_cast<QWebSocket *>(sender());
    if (pClient)
    {
        pClient->sendBinaryMessage(message);
    }
}
//! [processBinaryMessage]

//! [socketDisconnected]
void TLSServerController::socketDisconnected()
{
    qDebug() << "Client disconnected";
    QWebSocket *pClient = qobject_cast<QWebSocket *>(sender());
    if (pClient)
    {
        m_clients.removeAll(pClient);
        pClient->deleteLater();
    }
}

void TLSServerController::onSslErrors(const QList<QSslError> &errors)
{
    for (int i = 0; i < errors.length();i++)
     {
        qDebug() << "SSL error: " << errors.at(i).errorString();
    }

    qDebug() << "Ssl errors occurred";
}
//! [socketDisconnected]

int TLSServerController::start() {

    QList<QSslCertificate> caCertificates;

  if (m_pWebSocketServer) {
      m_pWebSocketServer->close();
      qDeleteAll(m_clients.begin(), m_clients.end());
  }
  // set up the server
  m_pWebSocketServer = new QWebSocketServer(QStringLiteral("SSL Server"),
                                            QWebSocketServer::SecureMode,
                                            this);
  QSslConfiguration sslConfiguration;
  QFile certFile(QStringLiteral("/home/peter/tls/lt2.crt"));
  QFile keyFile(QStringLiteral("/home/peter/tls/lt2.key"));
  QFile caCertFile(QStringLiteral("/home/peter/tls/ca.crt"));
  certFile.open(QIODevice::ReadOnly);
  keyFile.open(QIODevice::ReadOnly);
  caCertFile.open((QIODevice::ReadOnly));
  QSslCertificate caCertificate(&caCertFile,QSsl::Pem);
  QSslCertificate certificate(&certFile, QSsl::Pem);
  QSslKey sslKey(&keyFile, QSsl::Rsa, QSsl::Pem);
  certFile.close();
  keyFile.close();
  caCertFile.close();
  caCertificates.append(caCertificate);
  sslConfiguration.setCaCertificates(caCertificates);
  sslConfiguration.setPeerVerifyMode(QSslSocket::AutoVerifyPeer);
  sslConfiguration.setLocalCertificate(certificate);
  sslConfiguration.setPrivateKey(sslKey);
  sslConfiguration.setProtocol(QSsl::TlsV1SslV3);
  m_pWebSocketServer->setSslConfiguration(sslConfiguration);

  if (m_pWebSocketServer->listen(QHostAddress::Any, port))
  {
      qDebug() << "SSL Server listening on port" << port;
      connect(m_pWebSocketServer, &QWebSocketServer::newConnection,
              this, &TLSServerController::onNewConnection);
      connect(m_pWebSocketServer, &QWebSocketServer::sslErrors,
              this, &TLSServerController::onSslErrors);
  }

  return 0;
}

int TLSServerController::stop() {
    if (m_pWebSocketServer) {
        m_pWebSocketServer->close();
        qDeleteAll(m_clients.begin(), m_clients.end());
    }
  return 0;
}

int TLSServerController::pause() {
  return 0;
}

int TLSServerController::restart() {
  return 0;
}

bool TLSServerController::find() {
    return true;
}

void TLSServerController::getRealtimeData(RealtimeData &rtData) {

    rtData = telemetry;
    processRealtimeData(rtData);
}

void TLSServerController::pushRealtimeData(RealtimeData &) {
}
