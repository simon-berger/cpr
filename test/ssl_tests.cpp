#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include <cpr/cprtypes.h>
#include <cpr/filesystem.h>
#include <cpr/ssl_options.h>

#include "httpsServer.hpp"


using namespace cpr;

static HttpsServer* server;

std::string loadCertificateFromFile(const std::string certPath) {
    std::ifstream certFile(certPath);
    std::stringstream buffer;
    buffer << certFile.rdbuf();
    return buffer.str();
}

TEST(SslTests, HelloWorldTestSimpel) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    Url url{server->GetBaseUrl() + "/hello.html"};
    std::string baseDirPath = server->getBaseDirPath();
    SslOptions sslOpts = Ssl(ssl::CaPath{baseDirPath + "ca.cer"}, ssl::CertFile{baseDirPath + "client.cer"}, ssl::KeyFile{baseDirPath + "client.key"}, ssl::VerifyPeer{false}, ssl::PinnedPublicKey{baseDirPath + "server.pubkey"}, ssl::VerifyHost{false}, ssl::VerifyStatus{false});
    Response response = cpr::Get(url, sslOpts, Timeout{5000}, Verbose{});
    std::string expected_text = "Hello world!";
    EXPECT_EQ(expected_text, response.text);
    EXPECT_EQ(url, response.url);
    EXPECT_EQ(std::string{"text/html"}, response.header["content-type"]);
    EXPECT_EQ(200, response.status_code);
    EXPECT_EQ(ErrorCode::OK, response.error.code) << response.error.message;
}

TEST(SslTests, HelloWorldTestFull) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    Url url{server->GetBaseUrl() + "/hello.html"};
    std::string baseDirPath = server->getBaseDirPath();
    SslOptions sslOpts = Ssl(ssl::TLSv1{}, ssl::ALPN{false}, ssl::NPN{false}, ssl::CaPath{baseDirPath + "ca.cer"}, ssl::CertFile{baseDirPath + "client.cer"}, ssl::KeyFile{baseDirPath + "client.key"}, ssl::PinnedPublicKey{baseDirPath + "server.pubkey"}, ssl::VerifyPeer{false}, ssl::VerifyHost{false}, ssl::VerifyStatus{false});
    Response response = cpr::Get(url, sslOpts, Timeout{5000}, Verbose{});
    std::string expected_text = "Hello world!";
    EXPECT_EQ(expected_text, response.text);
    EXPECT_EQ(url, response.url);
    EXPECT_EQ(std::string{"text/html"}, response.header["content-type"]);
    EXPECT_EQ(200, response.status_code);
    EXPECT_EQ(ErrorCode::OK, response.error.code) << response.error.message;
}

TEST(SslTests, GetCertInfo) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    Url url{server->GetBaseUrl() + "/hello.html"};
    std::string baseDirPath = server->getBaseDirPath();
    SslOptions sslOpts = Ssl(ssl::CaPath{baseDirPath + "ca.cer"}, ssl::CertFile{baseDirPath + "client.cer"}, ssl::KeyFile{baseDirPath + "client.key"}, ssl::VerifyPeer{false}, ssl::VerifyHost{false}, ssl::VerifyStatus{false});
    Response response = cpr::Get(url, sslOpts, Timeout{5000}, Verbose{});
    std::string expected_text = "Hello world!";
    EXPECT_EQ(expected_text, response.text);
    EXPECT_EQ(url, response.url);
    EXPECT_EQ(std::string{"text/html"}, response.header["content-type"]);
    EXPECT_EQ(200, response.status_code);
    EXPECT_EQ(ErrorCode::OK, response.error.code) << response.error.message;

    std::vector<std::string> certInfo = response.GetCertInfo();
    EXPECT_EQ(certInfo.size(), 1);
    std::string expected_certInfo = "Subject:C = XX, L = Default City, O = Default Company Ltd";
    EXPECT_EQ(certInfo[0], expected_certInfo);
}

#if SUPPORT_CURLOPT_SSL_CTX_FUNCTION
TEST(SslTests, LoadCertFromBufferTestSimpel) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    Url url{server->GetBaseUrl() + "/hello.html"};
    std::string baseDirPath = server->getBaseDirPath();

    std::string certBuffer = loadCertificateFromFile(baseDirPath + "ca.cer");
    SslOptions sslOpts = Ssl(ssl::CaBuffer{std::move(certBuffer)}, ssl::CertFile{baseDirPath + "client.cer"}, ssl::KeyFile{baseDirPath + "client.key"}, ssl::VerifyPeer{false}, ssl::VerifyHost{false}, ssl::VerifyStatus{false});
    Response response = cpr::Get(url, sslOpts, Timeout{5000}, Verbose{});
    std::string expected_text = "Hello world!";
    EXPECT_EQ(expected_text, response.text);
    EXPECT_EQ(url, response.url);
    EXPECT_EQ(std::string{"text/html"}, response.header["content-type"]);
    EXPECT_EQ(200, response.status_code);
    EXPECT_EQ(ErrorCode::OK, response.error.code) << response.error.message;
}
#endif

fs::path getBasePath(const std::string& execPath) {
    return fs::path{execPath}.parent_path().make_preferred();
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    fs::path baseDirPath = getBasePath(argv[0]);
    fs::path serverCertPath = fs::path{baseDirPath}.append("server.cer");
    fs::path serverKeyPath = fs::path{baseDirPath}.append("server.key");
    server = new HttpsServer(std::move(baseDirPath), std::move(serverCertPath), std::move(serverKeyPath));
    ::testing::AddGlobalTestEnvironment(server);

    return RUN_ALL_TESTS();
}
