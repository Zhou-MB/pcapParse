#include <string>
#include <map>
#include <sstream>
#include <stdint.h>
#include <arpa/inet.h>

class HttpsParser{
private:
    std::map<std::string, std::string> https;
    std::string format_key(std::string &str);
    std::map<uint16_t, std::string> cipher_suites_table;
public:

    HttpsParser(const char *buf, int len);
    ~HttpsParser();
    void show();
    int RecordDecode(const char *msg);
    void Init_Cipher_Suites_Table();
    void HandshakeDecode(const char *msg);
    void ClientHelloDecode(const char *msg);
};

void HttpsParser::ClientHelloDecode(const char *msg){
    int offset=32;
    uint8_t *sessionLen=(uint8_t *)(msg+offset);
    offset+=(1+(*sessionLen));
    uint16_t *suitesLen=(uint16_t *)(msg+offset);
    offset+=2;
    Init_Cipher_Suites_Table();
    for(uint16_t i=0;i<ntohs(*suitesLen);i+=2){   //密码学套件，两个字节的ID
        uint16_t *suiteId=(uint16_t *)(msg+offset);
        offset+=2;
        //printf("suiteId:%x\n",*suiteId);
        printf("Cipher-Suite:%s\n", cipher_suites_table[ntohs(*suiteId)].c_str());
    }
    offset+=4; //跳过压缩方法与扩展长度
    uint16_t *extensionType=(uint16_t *)(msg+offset);
    offset+=2;
    if(*extensionType==0x0){
        offset+=5; //跳至server name length
        int16_t *serverLen=(int16_t *)(msg+offset);
        offset+=2;
        std::string serverName(msg+offset,*serverLen);
        https.insert(std::make_pair("Server-Name", serverName));
    }
    show();
}

void HttpsParser::HandshakeDecode(const char *msg){
    int offset=0;
    uint8_t *Hstype=(uint8_t *)(msg+offset);
    offset+=1;
    if (*Hstype == 0)
        https.insert(std::make_pair("Handshake-Type", "Hello-Request"));
    else if (*Hstype == 1)
        https.insert(std::make_pair("Handshake-Type", "Client-Hello"));
    else if (*Hstype == 2)
        https.insert(std::make_pair("Handshake-Type", "Server-Hello"));
    else if (*Hstype == 11)
        https.insert(std::make_pair("Handshake-Type", "Certificate"));
    else if (*Hstype == 12)
        https.insert(std::make_pair("Handshake-Type", "ServerKey-Exchange"));
    else if (*Hstype == 16)
        https.insert(std::make_pair("Handshake-Type", "ClientKey-Exchange"));
    else if (*Hstype == 20)
        https.insert(std::make_pair("Handshake-Type", "Finished"));
    
    uint32_t *le=(uint32_t *)(msg+offset);
    offset+=3;
    if (https.find("Handshake-Type") != https.end())
    {
        https.insert(std::make_pair("Length", std::to_string(ntohl(*le) >> 8)));
    }

    uint16_t *ver = (uint16_t *)(msg + offset);
    offset += 2;
    if (ntohs(*ver) == 0x0300)
        https.insert(std::make_pair("Version", "SSL 3.0"));
    else if (ntohs(*ver) == 0x0301)
        https.insert(std::make_pair("Version", "TLS 1.0"));
    else if (ntohs(*ver) == 0x0302)
        https.insert(std::make_pair("Version", "TLS 1.1"));
    else if (ntohs(*ver) == 0x0303)
        https.insert(std::make_pair("Version", "TLS 1.2"));

    show();

    if (*Hstype == 1){
        ClientHelloDecode(msg+offset);
    }
}

int HttpsParser::RecordDecode(const char *msg){
    int offset = 0;
    uint8_t *contType = (uint8_t *)(msg + offset);
    offset += 1;
    if (*contType == 20)
        https.insert(std::make_pair("Content-Type", "ChangeCipherSpec"));
    else if (*contType == 21)
        https.insert(std::make_pair("Content-Type", "Alert"));
    else if (*contType == 22)
        https.insert(std::make_pair("Content-Type", "Handshake"));
    else if (*contType == 23)
        https.insert(std::make_pair("Content-Type", "ApplicationData"));

    uint16_t *ver = (uint16_t *)(msg + offset);
    offset += 2;
    if (ntohs(*ver) == 0x0300)
        https.insert(std::make_pair("Version", "SSL 3.0"));
    else if (ntohs(*ver) == 0x0301)
        https.insert(std::make_pair("Version", "TLS 1.0"));
    else if (ntohs(*ver) == 0x0302)
        https.insert(std::make_pair("Version", "TLS 1.1"));
    else if (ntohs(*ver) == 0x0303)
        https.insert(std::make_pair("Version", "TLS 1.2"));

    uint16_t *le = (uint16_t *)(msg + offset);
    offset+=2;
    if (https.find("Content-Type") != https.end())
        https.insert(std::make_pair("Length", std::to_string(ntohs(*le))));

    show();

    if(*contType == 22){
        HandshakeDecode(msg+offset);
    }

    return offset+ntohs(*le);
}

HttpsParser::HttpsParser(const char *msg, int len)
{
    if (len > 0)
    {
        int offset = 0;
        while (offset < len)   //可能包含多个Record协议
        {
            printf("...\n");
            offset += RecordDecode(msg + offset);
        }
    }
}

HttpsParser::~HttpsParser(){}

void HttpsParser::show(){     
    for(auto it = https.cbegin(); it != https.cend(); ++it){
        printf("%s:%s\n",it->first.c_str(),it->second.c_str());
    }
    https.clear();
}

std::string HttpsParser::format_key(std::string &str){
    if(str[0] >= 'a' && str[0] <= 'z'){
        str[0] = str[0] + 'A' - 'a';
    }
    int position = 0;
    while((position = str.find("-", position)) != std::string::npos){
        if(str[position + 1] >= 'a' && str[position + 1] <= 'z'){
            str[position + 1] = str[position + 1] + 'A' - 'a';
        }
        position++;
    }
    return str;
}

void HttpsParser::Init_Cipher_Suites_Table() // TLS1.2
{
    cipher_suites_table.insert(std::make_pair(0xC02F, (std::string)"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));
    cipher_suites_table.insert(std::make_pair(0xC027, (std::string)"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"));
    cipher_suites_table.insert(std::make_pair(0xC013, (std::string)"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"));
    cipher_suites_table.insert(std::make_pair(0xC030, (std::string)"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"));
    cipher_suites_table.insert(std::make_pair(0xC028, (std::string)"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"));
    cipher_suites_table.insert(std::make_pair(0xC014, (std::string)"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"));
    cipher_suites_table.insert(std::make_pair(0xC061, (std::string)"TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"));
    cipher_suites_table.insert(std::make_pair(0xC060, (std::string)"TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"));
    cipher_suites_table.insert(std::make_pair(0xC077, (std::string)"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"));
    cipher_suites_table.insert(std::make_pair(0xC076, (std::string)"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"));
    cipher_suites_table.insert(std::make_pair(0x9D, (std::string)"TLS_RSA_WITH_AES_256_GCM_SHA384"));
    cipher_suites_table.insert(std::make_pair(0xC0A1, (std::string)"TLS_RSA_WITH_AES_256_CCM_8"));
    cipher_suites_table.insert(std::make_pair(0xC09D, (std::string)"TLS_RSA_WITH_AES_256_CCM"));
    cipher_suites_table.insert(std::make_pair(0xC051, (std::string)"TLS_RSA_WITH_ARIA_256_GCM_SHA384"));
    cipher_suites_table.insert(std::make_pair(0x9C, (std::string)"TLS_RSA_WITH_AES_128_GCM_SHA256"));
    cipher_suites_table.insert(std::make_pair(0xC0A0, (std::string)"TLS_RSA_WITH_AES_128_CCM_8"));
    cipher_suites_table.insert(std::make_pair(0xC02C, (std::string)"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"));
    cipher_suites_table.insert(std::make_pair(0xC09C, (std::string)"TLS_RSA_WITH_AES_128_CCM"));
    cipher_suites_table.insert(std::make_pair(0xC050, (std::string)"TLS_RSA_WITH_ARIA_128_GCM_SHA256"));
    cipher_suites_table.insert(std::make_pair(0x3D, (std::string)"TLS_RSA_WITH_AES_256_CBC_SHA256"));
    cipher_suites_table.insert(std::make_pair(0xC0, (std::string)"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"));
    cipher_suites_table.insert(std::make_pair(0x3C, (std::string)"TLS_RSA_WITH_AES_128_CBC_SHA256"));
    cipher_suites_table.insert(std::make_pair(0xBA, (std::string)"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"));
    cipher_suites_table.insert(std::make_pair(0x35, (std::string)"TLS_RSA_WITH_AES_256_CBC_SHA"));
    cipher_suites_table.insert(std::make_pair(0x84, (std::string)"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"));
    cipher_suites_table.insert(std::make_pair(0x2F, (std::string)"TLS_RSA_WITH_AES_128_CBC_SHA"));
    cipher_suites_table.insert(std::make_pair(0x96, (std::string)"TLS_RSA_WITH_SEED_CBC_SHA"));
    cipher_suites_table.insert(std::make_pair(0x41, (std::string)"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"));
    cipher_suites_table.insert(std::make_pair(0xCCA8, (std::string)"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"));
    cipher_suites_table.insert(std::make_pair(0xC02B, (std::string)"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"));
    cipher_suites_table.insert(std::make_pair(0xCCA9, (std::string)"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"));
    cipher_suites_table.insert(std::make_pair(0xC009, (std::string)"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"));
    cipher_suites_table.insert(std::make_pair(0xC00A, (std::string)"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"));
    cipher_suites_table.insert(std::make_pair(0xA, (std::string)"TLS_RSA_WITH_3DES_EDE_CBC_SHA"));
    cipher_suites_table.insert(std::make_pair(0xc023, (std::string)"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"));
    cipher_suites_table.insert(std::make_pair(0xc028, (std::string)"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"));
    cipher_suites_table.insert(std::make_pair(0xc024, (std::string)"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"));
    cipher_suites_table.insert(std::make_pair(0x1301, (std::string)"TLS_AES_128_GCM_SHA256"));
    cipher_suites_table.insert(std::make_pair(0x1302, (std::string)"TLS_AES_256_GCM_SHA384"));
    cipher_suites_table.insert(std::make_pair(0x1303, (std::string)"TLS_CHACHA20_POLY1305_SHA256"));
    cipher_suites_table.insert(std::make_pair(0x9F, (std::string)"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"));
    cipher_suites_table.insert(std::make_pair(0xCCAA, (std::string)"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"));
    cipher_suites_table.insert(std::make_pair(0x9E, (std::string)"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"));
    cipher_suites_table.insert(std::make_pair(0x6B, (std::string)"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"));
    cipher_suites_table.insert(std::make_pair(0x67, (std::string)"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"));
    cipher_suites_table.insert(std::make_pair(0x39, (std::string)"TLS_DHE_RSA_WITH_AES_256_CBC_SHA"));
    cipher_suites_table.insert(std::make_pair(0x33, (std::string)"TLS_DHE_RSA_WITH_AES_128_CBC_SHA"));
    cipher_suites_table.insert(std::make_pair(0xFF, (std::string)"TLS_EMPTY_RENEGOTIATION_INFO_SCSV"));
}