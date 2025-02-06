/*
    Copyright (C) 2016-2025 zafaco GmbH

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
    as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "tcphandler.h"

using namespace std;

int mSocket;
sockaddr_in6 *mClient;
bool mTlsSocket;

vector<string> allowedProtocols;
unsigned long long tcpTimeout;
string sClientIp;

bool rttRunning;
bool downloadRunning;
bool uploadRunning;

int downloadFrameSize;
long long downloadRandomDataSize;

int rttRequests;
unsigned long long rttRequestTimeout;
long rttRequestWait;
unsigned long long rttTimeout;
int rttPayloadSize;
string rttPayload;
string rttPayloadTimestamp;
string rttPayloadDelimiter;
bool rttStart;
unsigned long long rttPingSendTime;
unsigned long long rttPongReceiveTime;
unsigned long long rttPongAllegedReceiveTime;
vector<long long> rttVector;

double rttAvg;
double rttMed;
double rttMin;
double rttMax;
int rttRequestsSend;
int rttReplies;
int rttErrors;
int rttMissing;
int rttPacketsize;
double rttStdDevPop;

long long uploadBytesReceived;
long long uploadBytesReceivedLast;
long long uploadHeaderReceived;
long long uploadTLSRecordsReceived;

bool showShutdown;
bool showStopped;
bool showRttStart;

string certDir;

bool connectionIsValidWebSocket;
bool connectionIsValidHttp;

string tlsVersionNegotiated;
string tls12CipherSuitesConfigured;
string tls13CipherSuitesConfigured;
string tlsCipherSuiteNegotiated;
int tlsOverhead;

CTcpHandler::CTcpHandler()
{
}

CTcpHandler::~CTcpHandler()
{
}

CTcpHandler::CTcpHandler(int nSocket, string nClientIp, bool nTlsSocket, sockaddr_in6 *pClient)
{
    mClient = pClient;
    mSocket = nSocket;
    mTlsSocket = nTlsSocket;

    if (::CONFIG["tcp_timeout"].int_value() != 0)
    {
        tcpTimeout = ::CONFIG["tcp_timeout"].int_value();
    }
    else
    {
        tcpTimeout = 25;
    }

    allowedProtocols.push_back("ip");
    allowedProtocols.push_back("rtt");
    allowedProtocols.push_back("download");
    allowedProtocols.push_back("upload");

    sClientIp = nClientIp;

    rttRunning = false;
    downloadRunning = false;
    uploadRunning = false;

    downloadRandomDataSize = 1123457;

    rttRequests = 10 + 1;
    rttRequestTimeout = 1000;
    rttRequestWait = 500;
    rttTimeout = (rttRequests * (rttRequestTimeout + rttRequestWait)) * 1.3;
    rttPayloadDelimiter = ";";
    rttPayloadSize = 64;
    rttStart = false;
    rttPingSendTime = 0;
    rttPongReceiveTime = 0;
    rttPongAllegedReceiveTime = 0;
    rttVector.clear();

    uploadBytesReceived = 0;
    uploadBytesReceivedLast = 0;
    uploadHeaderReceived = 0;
    uploadTLSRecordsReceived = 0;

    showShutdown = false;
    showStopped = true;
    showRttStart = true;

    certDir = "/var/opt/ias-server/certs/";

    connectionIsValidWebSocket = false;
    connectionIsValidHttp = false;

    tls12CipherSuitesConfigured = "";
    if (::CONFIG["tls"]["cipher_suites_1_2"].string_value().compare("") != 0)
    {
        tls12CipherSuitesConfigured = ::CONFIG["tls"]["cipher_suites_1_2"].string_value();
    }
    tls13CipherSuitesConfigured = "";
    if (::CONFIG["tls"]["cipher_suites_1_3"].string_value().compare("") != 0)
    {
        tls13CipherSuitesConfigured = ::CONFIG["tls"]["cipher_suites_1_3"].string_value();
    }
    tlsOverhead = 0;
}

int CTcpHandler::handle_tcp()
{
    TRC_DEBUG("TCP handler: started");

    noPollCtx *ctx = nopoll_ctx_new();
    if (!ctx)
    {
        TRC_ERR("TCP handler: noPoll context initialization failed");
        return 1;
    }

    if (::DEBUG_NOPOLL)
    {
        nopoll_log_enable(ctx, nopoll_true);
        nopoll_log_set_handler(ctx, nopoll_logging_handler, NULL);
    }

    nopoll_ctx_set_ssl_context_creator(ctx, websocket_ssl_context_handler, NULL);

    noPollConn *conn = nopoll_listener_from_socket(ctx, (NOPOLL_SOCKET)mSocket, mTlsSocket);

    if (!nopoll_conn_is_ok(conn))
    {
        TRC_ERR("TCP handler: noPoll connection initialization failed");
        return 1;
    }

    if (mTlsSocket)
    {
        TRC_INFO("TCP handler: TLS secured connection requested");

        DIR *dir;
        struct dirent *ent;

        if ((dir = opendir(certDir.c_str())) != NULL)
        {
            while ((ent = readdir(dir)) != NULL)
            {
                string dirName = ent->d_name;
                string certFile;
                string keyFile;

                if (!dirName.compare(".") == 0 && !dirName.compare("..") == 0)
                {
                    certFile = certDir + dirName + "/" + dirName + ".crt";
                    keyFile = certDir + dirName + "/" + dirName + ".key";

                    if (nopoll_ctx_set_certificate(ctx, dirName.c_str(), certFile.c_str(), keyFile.c_str(), NULL))
                    {
                        TRC_DEBUG("TCP handler: noPoll context TLS certificate set for: " + dirName);
                    }
                    else
                    {
                        TRC_CRIT("TCP handler: error: noPoll context TLS certificate set failed for: " + dirName);
                        return 0;
                    }
                }
            }
            closedir(dir);
        }
        else
        {
            TRC_CRIT("TCP handler: error: failed to open TLS certificate Directory: " + certDir);
            return 0;
        }

        if (nopoll_conn_is_tls_on(conn))
        {
            TRC_DEBUG("TCP handler: noPoll listener TLS enabled");
        }
        else
        {
            TRC_CRIT("TCP handler: error: noPoll listener TLS not enabled");
            return 0;
        }

        nopoll_ctx_set_post_ssl_check(ctx, websocket_post_ssl_handler, NULL);

        nopoll_conn_accept_complete(ctx, conn, conn, (NOPOLL_SOCKET)mSocket, nopoll_true);
    }

    nopoll_ctx_set_on_open(ctx, websocket_open_handler, NULL);
    nopoll_ctx_set_on_ready(ctx, websocket_ready_handler, NULL);
    nopoll_ctx_set_on_reject(ctx, websocket_reject_handler, NULL);
    nopoll_ctx_set_on_msg(ctx, websocket_message_handler, NULL);

    nopoll_loop_wait(ctx, 0);

    nopoll_ctx_unref(ctx);
    nopoll_cleanup_library();

    if (showStopped)
    {
        TRC_DEBUG("TCP handler: stopped");
    }

    return 0;
}

int CTcpHandler::websocket_open_handler(noPollCtx *ctx, noPollConn *conn, noPollPtr user_data)
{
    TRC_DEBUG("WebSocket handler: open");

    downloadFrameSize = 32764;

    nopoll_conn_set_on_close(conn, websocket_close_handler, NULL);
    nopoll_conn_set_sock_block(nopoll_conn_socket(conn), nopoll_true);

    string sProtocol = string(nopoll_conn_get_requested_protocol(conn));
    CTool::replaceStringInPlace(sProtocol,
                                " ", "");

    vector<string> requestestedProtocols;
    string delimiter = ",";
    CTool::tokenize(sProtocol, requestestedProtocols, delimiter);

    bool protocolAllowed = false;

    string acceptedProtocol;

    for (vector<string>::iterator itRequestedProtocols = requestestedProtocols.begin(); itRequestedProtocols != requestestedProtocols.end(); ++itRequestedProtocols)
    {
        for (vector<string>::iterator itAllowedProtocols = allowedProtocols.begin(); itAllowedProtocols != allowedProtocols.end(); ++itAllowedProtocols)
        {
            string requestedProtocol = *itRequestedProtocols;
            if (requestedProtocol.compare(*itAllowedProtocols) == 0)
            {
                if (requestedProtocol.compare("ip") == 0 || requestedProtocol.compare("rtt") == 0 || requestedProtocol.compare("download") == 0 || requestedProtocol.compare("upload") == 0)
                {
                    acceptedProtocol = requestedProtocol;
                    protocolAllowed = true;
                }
            }
        }
    }

    if (protocolAllowed)
    {
        connectionIsValidWebSocket = true;

        nopoll_conn_set_accepted_protocol(conn, acceptedProtocol.c_str());

        TRC_DEBUG("WebSocket handler: requested protocol: \"" + acceptedProtocol + "\" is allowed");
    }
    else if (!protocolAllowed)
    {
        TRC_ERR("WebSocket handler: requested protocol: \"" + sProtocol + "\" is not allowed");

        char response[] = HTTP_FORBIDDEN;
        int responseSize = strlen(response);

        nopoll_conn_default_send(conn, response, responseSize);

        return 0;
    }

    return 1;
}

int CTcpHandler::websocket_ready_handler(noPollCtx *ctx, noPollConn *conn, noPollPtr user_data)
{
    TRC_DEBUG("WebSocket handler: ready for IP: " + sClientIp + " on Port: " +
              string(nopoll_conn_port(conn)));

    string sProtocol = string(nopoll_conn_get_accepted_protocol(conn));

    if (sProtocol.compare("ip") == 0)
    {
        int on = 1;
        setsockopt(mSocket, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on));
        thread ipThread(ip, ctx, conn);
        ipThread.detach();
    }

    if (sProtocol.compare("rtt") == 0)
    {
        int on = 1;
        setsockopt(mSocket, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on));
        thread rttThread(roundTripTime, ctx, conn);
        rttThread.detach();
    }

    if (sProtocol.compare("download") == 0)
    {
        thread downloadThread(download, ctx, conn);
        downloadThread.detach();
    }

    if (sProtocol.compare("upload") == 0)
    {
        int on = 1;
        setsockopt(mSocket, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on));
        thread uploadThread(upload, ctx, conn);
        uploadThread.detach();
    }

    return 1;
}

int CTcpHandler::websocket_reject_handler(noPollCtx *ctx, noPollConn *conn, noPollPtr user_data)
{

    struct http_header *http_header_values_struct;
    http_header_values_struct = nopoll_conn_get_http_header(conn);

    Json::object http_header_values;
    while (http_header_values_struct)
    {
        struct http_header *node = http_header_values_struct;
        http_header_values[node->key] = node->value;
        http_header_values_struct = http_header_values_struct->next;
    }

    if (http_header_values["request_url"].string_value().compare(HTTP_DATA) == 0 || http_header_values["request_url"].string_value().compare(HTTP_IP) == 0)
    {
        TRC_INFO("WebSocket handler: valid HTTP " + http_header_values["http_method"].string_value() + " request received, falling back to HTTP");

        return handle_http(http_header_values, ctx, conn, user_data);
    }
    else
    {
        TRC_ERR("WebSocket handler: invalid HTTP " + http_header_values["http_method"].string_value() + " request received, closing connection");

        char response[] = HTTP_BAD_REQUEST;
        int responseSize = strlen(response);

        nopoll_conn_default_send(conn, response, responseSize);
        nopoll_loop_stop(ctx);
    }

    return 0;
}

int CTcpHandler::handle_http(
    Json::object http_header_values, noPollCtx *ctx, noPollConn *conn, noPollPtr user_data)
{
    TRC_DEBUG("HTTP handler: requested protocol:    \"HTTP " + http_header_values["http_method"].string_value() + " " + http_header_values["request_url"].string_value() + "\"");

    connectionIsValidHttp = true;
    nopoll_conn_set_http_on(conn, true);

    TRC_DEBUG("HTTP handler: ready for IP: " + sClientIp + " on Port: " + string(nopoll_conn_port(conn)));

    string response = "";

    if (http_header_values["http_method"].string_value().compare("GET") == 0)
    {
        response += "HTTP/1.1 200 OK\r\n";
        response += "Accept-Ranges: bytes\r\n";
        if (http_header_values["Origin"].string_value().compare("") != 0)
        {
            response += "Access-Control-Allow-Origin: " + http_header_values["Origin"].string_value() + "\r\n";
        }
        response += "Access-Control-Allow-Credentials: true\r\n";
        response += "Content-Language: en\r\n";
        response += "Content-Type: application/octet-stream\r\n";
        response += "Cache-Control: max-age=0, no-cache, no-store\r\n";
        response += "Pragma: no-cache\r\n";
        response += "X-Rack-Cache: miss\r\n";
        response += "Connection: keep-alive\r\n\r\n";

        nopoll_conn_default_send(conn, const_cast<char *>(response.c_str()), response.size());

        if (http_header_values["request_url"].string_value().compare(HTTP_DATA) == 0)
        {
            thread downloadThread(download, ctx, conn);
            downloadThread.detach();
        }
        else if (http_header_values["request_url"].string_value().compare(HTTP_IP) == 0)
        {
            thread ipThread(ip, ctx, conn);
            ipThread.detach();
        }
    }
    else if (http_header_values["http_method"].string_value().compare("POST") == 0)
    {
        response += "HTTP/1.1 100 Continue\r\n";
        response += "Content-Length: 1024000000\r\n";
        response += "Content-Type: application/octet-stream\r\n";
        response += "Connection: keep-alive\r\n\r\n";

        nopoll_conn_default_send(conn, const_cast<char *>(response.c_str()), response.size());

        thread uploadThread(upload, ctx, conn);
        uploadThread.detach();
    }
    else
    {
        TRC_ERR("HTTP handler: requested protocol: \"HTTP " + http_header_values["http_method"].string_value() + " " + http_header_values["request_url"].string_value() + "\" is not allowed");

        char response[] = HTTP_FORBIDDEN;
        int responseSize = strlen(response);

        nopoll_conn_default_send(conn, response, responseSize);

        return 0;
    }

    return 1;
}

void CTcpHandler::websocket_message_handler(noPollCtx *ctx, noPollConn *conn, noPollMsg *msg, noPollPtr user_data)
{
    if (uploadRunning)
    {
        uploadBytesReceived += nopoll_msg_get_payload_size(msg);

        if (nopoll_msg_opcode(msg) != 0)
        {
            uploadHeaderReceived++;
        }

        return;
    }

    if (nopoll_msg_opcode(msg) == NOPOLL_PONG_FRAME && rttRunning)
    {
        rttPongAllegedReceiveTime = CTool::get_timestamp();

        string rttPayloadReceivedString = (const char *)nopoll_msg_get_payload(msg);

        size_t rttPayloadReceivedPos;
        if ((rttPayloadReceivedPos = rttPayloadReceivedString.find(rttPayloadDelimiter)) != string::npos)
        {
            TRC_DEBUG("WebSocket handler: rtt PONG received");

            string rttPayloadReceivedTimestamp = rttPayloadReceivedString.substr(0, rttPayloadReceivedPos);

            if (rttPayloadReceivedTimestamp.compare(rttPayloadTimestamp) == 0)
            {
                rttPongReceiveTime = rttPongAllegedReceiveTime;
                return;
            }
            else
            {
                TRC_DEBUG("WebSocket handler: rtt PING/PONG mismatch, discarding PONG");
            }
        }

        return;
    }

    if (rttRunning && !rttStart)
    {
        string error;
        Json rttParameters = Json::parse((const char *)nopoll_msg_get_payload(msg), error);

        if (rttParameters["cmd"].string_value().compare("rttStart") == 0)
        {
            if (rttParameters["rttRequests"].int_value()) rttRequests = rttParameters["rttRequests"].int_value() + 1;
            if (rttParameters["rttRequestTimeout"].int_value()) rttRequestTimeout = rttParameters["rttRequestTimeout"].int_value();
            if (rttParameters["rttRequestWait"].int_value()) rttRequestWait = rttParameters["rttRequestWait"].int_value();
            if (rttParameters["rttTimeout"].int_value()) rttTimeout = rttParameters["rttTimeout"].int_value();
            if (rttParameters["rttPayloadSize"].int_value())
            {
                if (rttParameters["rttPayloadSize"].int_value() > 6)
                {
                    rttPayloadSize = rttParameters["rttPayloadSize"].int_value();
                }
            }

            rttStart = true;
        }
    }

    if (!uploadRunning)
    {
        TRC_DEBUG("WebSocket handler: Message received");

        return;
    }
}

void CTcpHandler::websocket_close_handler(noPollCtx *ctx, noPollConn *conn, noPollPtr user_data)
{
    TRC_DEBUG("WebSocket handler: close");

    rttRunning = false;
    downloadRunning = false;
    uploadRunning = false;

    nopoll_conn_flush_writes(conn, 2000, 0);

    nopoll_loop_stop(ctx);
}

nopoll_bool CTcpHandler::websocket_post_ssl_handler(noPollCtx *ctx, noPollConn *conn, noPollPtr SSL_CTX_REF, noPollPtr SSL_REF, noPollPtr user_data)
{
    tlsVersionNegotiated = SSL_get_version((SSL *)SSL_REF);
    tlsCipherSuiteNegotiated = SSL_CIPHER_get_name(SSL_get_current_cipher((SSL *)SSL_REF));

    if (tlsCipherSuiteNegotiated == "TLS_AES_128_GCM_SHA256" || tlsCipherSuiteNegotiated == "TLS_AES_256_GCM_SHA384" || tlsCipherSuiteNegotiated == "TLS_CHACHA20_POLY1305_SHA256")
    {
        tlsOverhead = 22;
    }

    else if (tlsCipherSuiteNegotiated == "ECDHE-RSA-AES128-GCM-SHA256" || tlsCipherSuiteNegotiated == "ECDHE-RSA-AES256-GCM-SHA384" || tlsCipherSuiteNegotiated == "AES128-GCM-SHA256" || tlsCipherSuiteNegotiated == "AES256-GCM-SHA384")
    {
        tlsOverhead = 29;
    }

    TRC_DEBUG("TCP handler: TLS handshake: completed using " + tlsVersionNegotiated + ", cipher suite " + tlsCipherSuiteNegotiated + ", tls overhead: " + to_string(tlsOverhead));

    return nopoll_true;
}

noPollPtr CTcpHandler::websocket_ssl_context_handler(noPollCtx *ctx, noPollConn *conn, noPollConnOpts *opts, nopoll_bool is_client, noPollPtr user_data)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());

    TRC_DEBUG("TCP handler: TLS handshake: starting");

    if (!tls12CipherSuitesConfigured.empty())
    {
        TRC_DEBUG("TCP handler: TLS handshake: enforcing tls 1.2 cipher suites " + tls12CipherSuitesConfigured);
        if (SSL_CTX_set_cipher_list(ssl_ctx, tls12CipherSuitesConfigured.c_str()) != 1)
        {
            TRC_DEBUG("TCP handler: TLS handshake: tls 1.2 cipher suites could not be enforced, using default");
        }
    }
    else
    {
        TRC_DEBUG("TCP handler: TLS handshake: enforcing no tls 1.2 cipher suites");
    }

    if (!tls13CipherSuitesConfigured.empty())
    {
        TRC_DEBUG("TCP handler: TLS handshake: enforcing tls 1.3 cipher suites " + tls13CipherSuitesConfigured);
        if (SSL_CTX_set_ciphersuites(ssl_ctx, tls13CipherSuitesConfigured.c_str()) != 1)
        {
            TRC_DEBUG("TCP handler: TLS handshake: tls 1.3 cipher suites could not be enforced, using default");
        }
    }
    else
    {
        TRC_DEBUG("TCP handler: TLS handshake: enforcing no tls 1.3 cipher suites");
    }

    SSL_CTX_set_msg_callback(ssl_ctx, ssl_ctx_message_handler);

    return ssl_ctx;
}

void CTcpHandler::ssl_ctx_message_handler(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
    if (uploadRunning && write_p == 0 && content_type == SSL3_RT_HEADER)
    {
        uploadTLSRecordsReceived++;
    }
}

void CTcpHandler::tcp_timeout_handler(noPollCtx *ctx, noPollConn *conn)
{
    TRC_ERR("TCP handler: Timeout reached");

    TRC_DEBUG("TCP handler: stopped");

    nopoll_loop_stop(ctx);

    if (showShutdown) TRC_DEBUG("Socket: Connection Shutdown for Client IP: " + sClientIp);
}

void CTcpHandler::nopoll_logging_handler(noPollCtx *ctx, noPollDebugLevel level, const char *log_msg, noPollPtr user_data)
{
    if (level == NOPOLL_LEVEL_DEBUG && ::DEBUG_NOPOLL)
    {
        TRC_DEBUG("NoPoll: " + string(log_msg));
    }

    if (level == NOPOLL_LEVEL_WARNING && ::DEBUG_NOPOLL_WARNING)
    {
        TRC_ERR("NoPoll: " + string(log_msg));
    }

    if (level == NOPOLL_LEVEL_CRITICAL && ::DEBUG_NOPOLL_CRITICAL)
    {
        TRC_CRIT("NoPoll: " + string(log_msg));
    }

    return;
}

int CTcpHandler::ip(noPollCtx *ctx, noPollConn *conn)
{
    if (connectionIsValidHttp)
    {
        TRC_DEBUG("TCP handler: ip using HTTP");
    }
    else if (connectionIsValidWebSocket)
    {
        TRC_DEBUG("TCP handler: ip using WebSocket");
    }

    usleep(100000);

    Json::object ip_report_mutable = Json::object{
        {"cmd", "ip_report"},
        {"client", sClientIp}};

    if (mTlsSocket)
    {
        TRC_DEBUG("TCP handler: ip report: tls_version: " + tlsVersionNegotiated + " tls_cipher_suite: " + tlsCipherSuiteNegotiated + " tls_overhead: " + to_string(tlsOverhead));

        if (!tlsVersionNegotiated.empty())
        {
            ip_report_mutable["tls_version"] = tlsVersionNegotiated;
        }
        if (!tlsCipherSuiteNegotiated.empty())
        {
            ip_report_mutable["tls_cipher_suite"] = tlsCipherSuiteNegotiated;
        }
        if (tlsOverhead != 0)
        {
            ip_report_mutable["tls_overhead"] = to_string(tlsOverhead);
        }
    }

    if (connectionIsValidWebSocket)
    {
        ip_report_mutable["msg"] = "ok";
    }

    Json ip_report = ip_report_mutable;

    TRC_DEBUG("TCP handler: ip report: " + ip_report.dump());

    if (connectionIsValidHttp)
    {
        nopoll_conn_default_send(conn, const_cast<char *>(ip_report.dump().c_str()), ip_report.dump().size());
    }
    else if (connectionIsValidWebSocket)
    {
        nopoll_conn_send_text(conn, ip_report.dump().c_str(), ip_report.dump().length());
        nopoll_conn_flush_writes(conn, 2000, 0);
    }

    TRC_DEBUG("TCP handler: ip report send");

    usleep(6000 * 1000);
    nopoll_conn_close(conn);

    return 1;
}

int CTcpHandler::roundTripTime(noPollCtx *ctx, noPollConn *conn)
{
    TRC_DEBUG("WebSocket handler: Round Trip Time");

    rttRunning = true;

    unsigned long long startTime;
    unsigned long long runningTime;

    startTime = CTool::get_timestamp();

    do
    {
        runningTime = CTool::get_timestamp() - startTime;

        if (!rttStart)
        {
            usleep(100);
            if (((runningTime / 1000) > rttTimeout) || !rttRunning)
                break;
            else
                continue;
        }

        if (showRttStart)
        {
            showRttStart = false;
            TRC_DEBUG("WebSocket handler: Round Trip Time start");
        }

        char randomData[rttPayloadSize - 6];
        CTool::randomData(randomData, rttPayloadSize - 6);

        rttPayloadTimestamp = to_string(CTool::get_timestamp_usec());

        rttPayload = rttPayloadTimestamp + ";" + randomData;

        if (nopoll_conn_send_frame(conn, nopoll_true, nopoll_false, NOPOLL_PING_FRAME, rttPayloadSize, (noPollPtr)rttPayload.c_str(), 0) == -1)
        {
            rttErrors++;
            setRoundTripTimeKPIs();
            sendRoundTripTimeResponse(ctx, conn);
            rttPingSendTime = 0;
            rttPongReceiveTime = 0;
            rttPayloadTimestamp = "0";
            usleep(rttRequestWait * 1000);
            continue;
        }

        rttPingSendTime = CTool::get_timestamp();

        rttRequestsSend++;

        TRC_DEBUG("WebSocket handler: rtt PING send");

        while (rttPongReceiveTime == 0)
        {
            if (((CTool::get_timestamp() - rttPingSendTime) / 1000) > rttRequestTimeout)
            {
                TRC_DEBUG("WebSocket handler: Round Trip Time Request Timeout");
                if (rttRequestsSend != 1)
                {
                    rttMissing++;
                    setRoundTripTimeKPIs();
                    sendRoundTripTimeResponse(ctx, conn);
                }

                break;
            }
            usleep(300);
        }

        if (((CTool::get_timestamp() - rttPingSendTime) / 1000) > rttRequestTimeout)
        {
            rttPingSendTime = 0;
            rttPongReceiveTime = 0;
            rttPayloadTimestamp = "0";
            usleep(rttRequestWait * 2000);
            continue;
        }

        long long rtt = rttPongReceiveTime - rttPingSendTime;

        if (rttRequestsSend != 1)
        {
            rttVector.push_back(rtt);

            rttReplies++;
            setRoundTripTimeKPIs();
            sendRoundTripTimeResponse(ctx, conn);
        }

        rttPingSendTime = 0;
        rttPongReceiveTime = 0;

        usleep(rttRequestWait * 1000);

    } while (((runningTime / 1000) < rttTimeout) && rttRunning && rttRequestsSend < rttRequests);

    nopoll_conn_flush_writes(conn, 2000, 0);

    if (rttRequestsSend == rttRequests)
    {
        usleep(6000 * 1000);
        nopoll_conn_close(conn);
        return 1;
    }

    if (rttRunning && ((runningTime / 1000) >= rttTimeout))
    {
        showShutdown = true;
        showStopped = false;
        tcp_timeout_handler(ctx, conn);
    }

    return 1;
}

void CTcpHandler::setRoundTripTimeKPIs()
{
    long long rttSum = 0;
    long long rttSumSq = 0;

    for (long long rtt : rttVector)
    {

        rttSum += rtt;
        rttSumSq += rtt * rtt;
    }

    if (rttSum != 0 && rttReplies > 0)
    {
        rttAvg = (double)rttSum / (double)rttReplies;

        if ((rttVector.back() < rttMin) || rttMin == 0)
        {
            rttMin = rttVector.back();
        }
        if (rttVector.back() > rttMax)
        {
            rttMax = rttVector.back();
        }

        vector<long long> rttMedianVector = rttVector;
        sort(rttMedianVector.begin(), rttMedianVector.end());
        size_t length = rttMedianVector.size();

        if (length % 2 == 0)
        {
            rttMed = (rttMedianVector[length / 2 - 1] + rttMedianVector[length / 2]) / 2;
        }
        else
        {
            rttMed = rttMedianVector[length / 2];
        }

        double variancePopulation = (double)rttSumSq / (double)rttReplies - rttAvg * rttAvg;
        rttStdDevPop = sqrt(variancePopulation);
    }

    rttMissing = rttRequestsSend - 1 - rttReplies - rttErrors;
    rttPacketsize = rttPayloadSize;
}

void CTcpHandler::sendRoundTripTimeResponse(noPollCtx *ctx, noPollConn *conn)
{
    Json::array jRtts;
    int counter = 0;

    for (double rtt : rttVector)
    {
        Json jRtt = Json::object{
            {"rtt_ns", rtt},
            {"id", counter}};

        jRtts.push_back(jRtt);
        counter++;
    }

    if (((rttRequestsSend - 1) % 2 == 1) || (rttRequestsSend == rttRequests))
    {
        Json rttReport = Json::object{
            {"cmd", "rtt_report"},
            {"avg", rttAvg},
            {"med", rttMed},
            {"min", rttMin},
            {"max", rttMax},
            {"req", rttRequestsSend - 1},
            {"rep", rttReplies},
            {"err", rttErrors},
            {"mis", rttMissing},
            {"pSz", rttPacketsize},
            {"std_dev_pop", rttStdDevPop},
            {"rtts", jRtts}};

        nopoll_conn_send_text(conn, rttReport.dump().c_str(), rttReport.dump().length());

        TRC_DEBUG("WebSocket handler: rtt report send");
    }
}

int CTcpHandler::download(noPollCtx *ctx, noPollConn *conn)
{
    if (connectionIsValidHttp)
    {
        TRC_DEBUG("TCP handler: download using HTTP");
        downloadFrameSize = MAX_PACKET_SIZE;
    }
    else if (connectionIsValidWebSocket)
    {
        TRC_DEBUG("TCP handler: download using WebSocket, frame size: " + to_string(downloadFrameSize));
    }

    downloadRunning = true;

    vector<char> randomDataValues;
    randomDataValues.clear();
    randomDataValues.reserve(downloadRandomDataSize);
    CTool::randomData(randomDataValues, downloadRandomDataSize);

    unsigned long long index = 0;

    unsigned long long startTime = 0;
    unsigned long long runningTime = 0;

    int nResponse = 0;

    usleep(500000);

    startTime = CTool::get_timestamp_sec();

    char *firstChar = randomDataValues.data();

    do
    {
        if (index + downloadFrameSize > randomDataValues.size())
        {
            index += downloadFrameSize - randomDataValues.size();
        }

        if (connectionIsValidHttp)
        {
            nResponse = nopoll_conn_default_send(conn, firstChar + index, downloadFrameSize);
        }
        else if (connectionIsValidWebSocket)
        {
            nResponse = nopoll_conn_send_binary(conn, firstChar + index, downloadFrameSize);
        }

        index += downloadFrameSize;

        if (nResponse <= 0)
        {
            TRC_ERR("TCP handler: download send: " + to_string(nResponse));
            break;
        }

        runningTime = CTool::get_timestamp_sec() - startTime;

    } while (nResponse > 0 && runningTime < tcpTimeout && downloadRunning);

    if (connectionIsValidWebSocket)
    {
        nopoll_conn_flush_writes(conn, 2000, 0);
    }

    if (downloadRunning && runningTime >= tcpTimeout)
    {
        showShutdown = true;
        showStopped = false;
        tcp_timeout_handler(ctx, conn);
    }

    return 1;
}

int CTcpHandler::upload(noPollCtx *ctx, noPollConn *conn)
{
    if (connectionIsValidHttp)
    {
        TRC_DEBUG("TCP handler: upload using HTTP");
    }
    else if (connectionIsValidWebSocket)
    {
        TRC_DEBUG("TCP handler: upload using WebSocket");
    }

    string sResponse;

    uploadRunning = true;

    unsigned long long startTime = 0;
    unsigned long long endTime = CTool::get_timestamp();
    unsigned long long runningTime = 0;
    unsigned long long currentTime = endTime / 100000;

    currentTime = formatCurrentTime(endTime, currentTime);

    startTime = CTool::get_timestamp_sec();

    do
    {
        if ((endTime - (currentTime * 100000)) > 500000)
        {
            sResponse.clear();

            long long uploadBytesReceivedTmp =
                uploadBytesReceived + (uploadTLSRecordsReceived * tlsOverhead);
            long long uploadHeaderReceivedTmp = uploadHeaderReceived;

            uploadBytesReceived = 0;
            uploadHeaderReceived = 0;
            uploadTLSRecordsReceived = 0;

            string currentTimeString = CTool::toString(currentTime);
            currentTime = formatCurrentTime(endTime, currentTime);

            if (connectionIsValidHttp)
            {
                sResponse = "" + CTool::toString(uploadBytesReceivedTmp) + "," + CTool::toString(uploadBytesReceivedLast) + "," + CTool::toString(CTool::get_timestamp_sec()) + "," + currentTimeString + ";";

                uploadBytesReceivedLast = uploadBytesReceivedTmp;

                nopoll_conn_default_send(conn, const_cast<char *>(sResponse.c_str()), sResponse.size());
            }
            else if (connectionIsValidWebSocket)
            {
                Json ulReport = Json::object{
                    {"cmd", "ul_report"},
                    {"time", currentTimeString},
                    {"bRcv", CTool::toString(uploadBytesReceivedTmp)},
                    {"hRcv", CTool::toString(uploadHeaderReceivedTmp)},
                };

                nopoll_conn_send_text(conn, ulReport.dump().c_str(), ulReport.dump().length());
            }
        }

        usleep(100);

        endTime = CTool::get_timestamp();
        runningTime = CTool::get_timestamp_sec() - startTime;

    } while (runningTime < tcpTimeout && uploadRunning);

    if (connectionIsValidWebSocket)
    {
        nopoll_conn_flush_writes(conn, 2000, 0);
    }

    if (uploadRunning && runningTime >= tcpTimeout)
    {
        showShutdown = false;
        showStopped = false;
        tcp_timeout_handler(ctx, conn);
    }

    return 1;
}

unsigned long long CTcpHandler::formatCurrentTime(unsigned long long endTime, unsigned long long currentTime)
{
    currentTime = endTime / 100000;

    if ((currentTime % 10) < 5)
    {
        currentTime -= currentTime % 10;
    }
    else
    {
        currentTime = (currentTime - (currentTime % 10)) + 5;
    }

    return currentTime;
}

struct addrinfo *CTcpHandler::getIpsFromHostname(string sString, bool bReachable)
{
    int error = 0;

    struct addrinfo query, *ips;

    memset(&query, 0, sizeof query);
    query.ai_family = AF_UNSPEC;

    if (bReachable)
    {
        query.ai_flags = (AI_V4MAPPED | AI_ADDRCONFIG);
    }
    else
    {
        query.ai_flags = AI_ADDRCONFIG;
    }

    if ((error = getaddrinfo(sString.c_str(), NULL, &query, &ips)) != 0)
    {
        TRC_ERR("Could not Request DNS - DNS ERROR");
    }

    return ips;
}