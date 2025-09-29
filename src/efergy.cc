
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <dirent.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <experimental/filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace std;

// Globals
static volatile int keepRunning = 1;

static time_t last_file_rotation = 0;
static ofstream current_file;

static const char * cert_pem = R"CERT(
-----BEGIN CERTIFICATE-----
MIIDcjCCAtugAwIBAgIJAJ3dmhrA7nxGMA0GCSqGSIb3DQEBBQUAMIGDMRIwEAYD
VQQKEwlzZW5zb3JuZXQxIzAhBgkqhkiG9w0BCQEWFG9wc0BoaWxkZWJyYW5kLmNv
LnVrMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAgTBkxvbmRvbjELMAkGA1UEBhMC
R0IxGTAXBgNVBAMUECouc2Vuc29ybmV0LmluZm8wHhcNMTUwMTE4MTI0MjQ2WhcN
MjUwMTE1MTI0MjQ2WjCBgzESMBAGA1UEChMJc2Vuc29ybmV0MSMwIQYJKoZIhvcN
AQkBFhRvcHNAaGlsZGVicmFuZC5jby51azEPMA0GA1UEBxMGTG9uZG9uMQ8wDQYD
VQQIEwZMb25kb24xCzAJBgNVBAYTAkdCMRkwFwYDVQQDFBAqLnNlbnNvcm5ldC5p
bmZvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6mhS7h3/EquMTVMYI5kWD
5QVFXWtTkcYl1L2OQT067HZODBfZFKB0S6DQtnjnNqP7L7C/HrStGPyxsnD7qdmy
G/8RQHjiCN1nsS8JT/GbegO/mQYtoF/FPjYKv3yfmp2a5yVNN12iIeVZTP3MSPpf
3CBuNPN87TPx2M73aPygoQIDAQABo4HrMIHoMAwGA1UdEwQFMAMBAf8wHQYDVR0O
BBYEFEKJGJNsCm2reUJPhRGhXUMPn9raMIG4BgNVHSMEgbAwga2AFEKJGJNsCm2r
eUJPhRGhXUMPn9raoYGJpIGGMIGDMRIwEAYDVQQKEwlzZW5zb3JuZXQxIzAhBgkq
hkiG9w0BCQEWFG9wc0BoaWxkZWJyYW5kLmNvLnVrMQ8wDQYDVQQHEwZMb25kb24x
DzANBgNVBAgTBkxvbmRvbjELMAkGA1UEBhMCR0IxGTAXBgNVBAMUECouc2Vuc29y
bmV0LmluZm+CCQCd3ZoawO58RjANBgkqhkiG9w0BAQUFAAOBgQCTzqN3G0WwjBi7
tVgqkkqx5XqXlmv+r83OtwswGYrF6kPLhTvVqxalY+Lsk1D4lztBmjmaP5aF6SRJ
XVV4tXbS0a35TEJSwpSfGxG01LMy2/y7cNN5fgHXpE1iStlTIdihIcuJrfyJePaU
sI1sbTCF+v6mmr82fR1mNilAhnRhnA==
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALqaFLuHf8Sq4xNU
xgjmRYPlBUVda1ORxiXUvY5BPTrsdk4MF9kUoHRLoNC2eOc2o/svsL8etK0Y/LGy
cPup2bIb/xFAeOII3WexLwlP8Zt6A7+ZBi2gX8U+Ngq/fJ+anZrnJU03XaIh5VlM
/cxI+l/cIG4083ztM/HYzvdo/KChAgMBAAECgYB0WSQ6NWdOGfsSD5aW7/VCIudh
c7k61zbEWdyDOVxTRCMT0OiBuyG8wXcZC91g1Snzsa2zzRJ8p4rPxWI7GJGaMrbw
xeIAM+bIXbGkCeQwhYPnvgt1v/5ZtCMf0JonsDTwqPirLeHysZU1TRtUo9Z/FRTm
1QY1Jt/vOV2lLbEIUQJBAOGW04qGfjC3+W9O1XcukaCgWGHf26J8ueRg/t9yr0LX
lFCd9SLb40NyIqBun2V2d/vs0NZ/V78vDs1AyyPhCq0CQQDTwcmeP5W07oFUrTCM
T4Zbvox1zy8YAR4RMuM+Pkxr0Sv1U30zut76quCbE5DBY8yJ51J0WvWhD0rLksr/
/8BFAkAhjQALQzNzZXlIj6352sg33oEmlVeiE/DFwZNGglUEmPFrCAMUWyWyuz/h
InK8cWEo67CnpirTuVj3N+K+hFLFAkEAmyuuKqA9e9AqRXqD0M2VjzUaiFnCEL0A
42l+y+Wq6nbk12jOnlGZg+YjoH+923jeMU+pREpDJDqofHSc/OrUYQJBALKskbIt
6CAcLUX/IM8ZDMgWyL8w1VhiqOCxBc0jYR8utlcAid5mzic5kNNo9YlCGKnP4Zii
RusjU8Aqz4jhTm4=
-----END PRIVATE KEY-----
)CERT";

string getOpenSSLError() {
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    string ret(buf, len);
    BIO_free(bio);
    return ret;
}

void intHandler(int dummy) {
    cerr << "CTRL-C requested" << endl;
    keepRunning = 0;
}

vector<string_view> split_string(const string_view str, const char delim = ',')
{
  vector<string_view> result;

  int indexCommaToLeftOfColumn = 0;
  int indexCommaToRightOfColumn = -1;
  for (int i = 0; i < static_cast<int>(str.size()); i++) {
    if (str[i] == delim) {
        indexCommaToLeftOfColumn = indexCommaToRightOfColumn;
        indexCommaToRightOfColumn = i;
        int index = indexCommaToLeftOfColumn + 1;
        int length = indexCommaToRightOfColumn - index;

        string_view column(str.data() + index, length);
        result.push_back(column);
    }
  }
  const string_view finalColumn(str.data() + indexCommaToRightOfColumn + 1,
                                str.size() - indexCommaToRightOfColumn - 1);
  result.push_back(finalColumn);
  return result;
}


int read_cert(SSL_CTX* ctx) {
  int error = 0;
  BIO *mem = BIO_new(BIO_s_mem());
  BIO_write(mem, cert_pem, strlen(cert_pem) + 1);

  X509 *x = PEM_read_bio_X509(mem, NULL, 0, NULL);
  if (x == NULL) {
    cerr << getOpenSSLError() << endl;
    error = 1;
  }
  EVP_PKEY* k = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
  if (k == NULL) {
    cerr << getOpenSSLError() << endl;
    error = 1;
  }
  if (!SSL_CTX_use_cert_and_key(ctx, x, k, NULL, 1)) {
    cerr << getOpenSSLError() << endl;
    error = 1;
  }

  BIO_free(mem);
  return error;
}

#include <algorithm>
#include <cctype>
#include <locale>

// Trim from the start (in place)
inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

// Trim from the end (in place)
inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

// Trim from both ends (in place)
inline void trim(std::string &s) {
    rtrim(s);
    ltrim(s);
}

// Trim from the start (copying)
inline std::string ltrim_copy(std::string s) {
    ltrim(s);
    return s;
}

// Trim from the end (copying)
inline std::string rtrim_copy(std::string s) {
    rtrim(s);
    return s;
}

// Trim from both ends (copying)
inline std::string trim_copy(std::string s) {
    trim(s);
    return s;
}

template <class T>
int sum_of_bytes(const T& data) {
  auto* vv = reinterpret_cast<const unsigned char*>(&data);
  int sum = 0;
  for (size_t i = 0; i < sizeof(data); ++i) {
    sum += int(vv[i]);
  }
  return sum;
}

template <class... Args>
int8_t checksum(Args... args) {
  int sum = (sum_of_bytes(args) + ...);
  return int8_t(sum % 256);
}

template <class T>
T read(istream& f) {
  T v = T(0);
  f.read(reinterpret_cast<char *>(&v), sizeof(T));
  return v;
}

int process_datalog(istream& f, ostream& o) {
  auto timestamp = read<uint32_t>(f);

  // 5 sensors, 3 bytes each
  int32_t sensors[5];
  for (int i = 0; i < 5;++i) {
    int32_t v = 0;
    f.read(reinterpret_cast<char *>(&v), 3);
    sensors[i] = v;
  }

  int count = 0;
  while (true) {
    count++;
    //if (f.fail()) {
    //  return -1;
    //}
    auto sensor_and_type = read<int8_t>(f);
    int8_t type = (sensor_and_type >> 5);           // 3 bits
    int8_t sensor = (sensor_and_type & 0x1F) >> 1;  // 4 bits
    int8_t leftover = (sensor_and_type & 0x01);     // 1 bit
    if (type == 1) {
      // Our regular EFCT sensor
      auto time_offset = ntohs(read<int16_t>(f));
      auto value = read<float>(f);
      auto cksum = read<int8_t>(f);
      auto c = checksum(sensor_and_type, time_offset, value);
      if (cksum != c) {
        cerr << "Checksum error at count " << count
             << ". Expected " << int(cksum) << ". Got " << int(c) << endl;
        return -1;
      }
      // Store in sensor, take leftover into account
      o << (timestamp + time_offset + 65537 * int(leftover)) << ","
        << sensors[sensor] << ","
        << value << endl;

    } else if (type == 3) {
      //cerr << (int)type << " " << (int)sensor  << endl;
      // A EFMS1 sensor. For some reason some EFCT sometimes send this out.
      auto time_offset = ntohs(read<int16_t>(f));
      auto m_value = read<float>(f);
      auto t_value = read<float>(f);
      auto l_value = read<float>(f);
      auto cksum = read<int8_t>(f);
      auto c = checksum(sensor_and_type, time_offset,
                        m_value, t_value, l_value);
      if (cksum != c) {
        cerr << "Checksum error at count " << count
             << ". Expected " << int(cksum) << ". Got " << int(c) << endl;
        return -1;
      }
    } else if (type == -1) {
      // This is end-of-file
      return 0;
    } else {
      // Don't know what to do with any other sensor type.
      cerr << "Unknown sensor type at count " << count << ": " << int(type) << endl;
      return -1;
    }
  }
  return 0;
}

void saveCall(const string& type,
              const string& path,
              time_t current_time,
              const map<string, string>& headers,
              const string& body) {
  std::stringstream filenameStream;
  filenameStream << "/tmp/efergy." << current_time << "." << type;
  string datafile = filenameStream.str();
  string scriptfile = filenameStream.str() + ".sh";
  cerr << "Saving call to " << scriptfile << endl;
  if (body != "") {
    ofstream f(datafile.c_str());
    f << body;
    f.close();
  }

  ofstream f(scriptfile.c_str());
  f << "LD_LIBRARY_PATH=/opt/openssl1/lib ./wget-1.21/src/wget \
        --no-check-certificate \
        --secure-protocol=SSLv3";
  for (const auto& p : headers) {
    f << " --header='" << p.first << ": " << p.second << "' ";
  }
  if (body != "") {
    f << " --post-file " << datafile;
  }
  f << "  https://51.89.234.206" << path;
  f.close();
}


int handle_request(int sockfd, SSL_CTX* ctx) {
  socklen_t len;
  struct sockaddr_storage addr;
  len = sizeof addr;

  int clientfd = accept(sockfd, (struct sockaddr*)&addr, &len);
  if (clientfd == -1) {
    cerr << "Error accepting connection: " << strerror(errno) << endl;
    return -1;
  }

  char ipstr[INET6_ADDRSTRLEN];
  struct sockaddr_in *s = (struct sockaddr_in *)&addr;
  int port = ntohs(s->sin_port);
  inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);

  time_t current_time = time(NULL);
  cerr << "Connection from " << ipstr << ":" << port
       << " on " << ctime(&current_time);

  //sleep(10);

  SSL* ssl = SSL_new(ctx);
  if (!ssl) {
    cerr << getOpenSSLError() << endl;
    close(clientfd);
    return -1;
  }
  if (SSL_set_fd(ssl, clientfd) == 0) {
    cerr << getOpenSSLError() << endl;
    close(clientfd);
    return -1;
  }

  if (SSL_accept(ssl) != 1) {
    cerr << getOpenSSLError() << endl;
    close(clientfd);
    return -1;
  }
  char buffer[1024] = {0};
  int b = SSL_read(ssl, buffer, 1023);
  if (b == 0) {
    cerr << getOpenSSLError() << endl;
    close(clientfd);
    return -1;
  }

  string request_line;
  map<string, string> headers;
  string body;
  int body_size = 0;

  stringstream stream(buffer);
  string line;
  while (getline(stream, line)) {
    if (line == "\r") {
      if (headers.count("Content-Length") != 0) {
        int size = atoi(headers["Content-Length"].c_str());
        body.resize(size);
        body_size = size;

        int remaining_bytes = size;
        while (remaining_bytes > 0) {
          //cerr << "Reading " << remaining_bytes << " more" << endl;
          int pos = size - remaining_bytes;
          int b = SSL_read(ssl, &body[pos], remaining_bytes);
          //cerr << "Read " << b << " bytes" << endl;
          remaining_bytes -= b;
        }
      }
      break;
    }
    trim(line);
    if (request_line == "") {
      request_line = line; //<method> <request-target> <protocol>
      continue;
    }
    //cerr << "|" << line << "----------|" << endl;
    size_t c = line.find(":");
    headers.insert(make_pair(trim_copy(line.substr(0, c)), trim_copy(line.substr(c+1))));
  }

  char response[1024] = {0};
  const char* metadata = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n";
  memcpy(response, metadata, strlen(metadata));

  if (request_line.find("/h3bulk", 0) != string::npos) {
    //saveCall("datalog", "/h3bulk", current_time, headers, body);

    std::stringstream datalog_stream;
    //datalog_stream.write(body.data(), sizeof(body));
    datalog_stream.write(body.data(), body_size);

    ofstream ofile("/var/lib/efergy/datalog");

    if (process_datalog(datalog_stream, ofile) == 0) {
      // here's where we copy the scratch file into a file to be forwared.
      std::stringstream filenameStream;
      filenameStream << "/var/lib/efergy/" << current_time << ".ts";
      //copy(std::filesystem::path("/var/lib/efergy/datalog"),
      //     std::filesystem::path("/tmp/datalog"),
      //     std::filesystem::copy_options::overwrite_existing);
      if (rename("/var/lib/efergy/datalog", filenameStream.str().c_str()) != 0) {
        if (errno != ENOENT) {
          // This is really an error we can't recover from. The best
          // approach is to abort the process, but that won't really
          // make the error go away.
          cerr << "Aborting: cannot move current file " << strerror(errno) << endl;
          abort();
        }
      }
    } else {
      cerr << "Failed processing datalog." << endl;
      saveCall("datalog", "/h3bulk", current_time, headers, body);
    }
    //if (headers["Content-Type"] == string("application/eh-datalog")) {
    //  // It is really always eh-datalog
    //  cerr << "Datalog" << endl;
    //}
    // reply is really an octet-stream
    const char* metadata = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: 3\r\n\r\n200";
    memcpy(response, metadata, strlen(metadata));
  } else if (request_line.find("/h3", 0) != string::npos) {
    //cerr << "h3 " << buffer << endl;
    if (headers["Content-Type"] == string("application/eh-ping")) {
      // eh-ping is a post
      //saveCall("ping", "/h3", current_time, headers, body);
    } else if (headers["Content-Type"] == string("application/eh-data")) {
      // All data is stored in 'body'
      stringstream stream(body.c_str());
      string line;
      bool has_data = false;
      while (getline(stream, line)) {
        if (line.size() == 0) continue;

        //cerr << "line: "<< line << endl;
        std::vector<string_view> v = split_string(line, '|');
        // Fields are: <SID>|1|<SensorType>|<Port>,<value to 2 decimal places>|XX
        //   Usually, SensorTYpe is EFCT, but sometimes I get EFMS1, for the same
        // sensor.
        if (v.size() < 5) {
          cerr << "line too short: "<< v.size() << endl;
          for (const auto& x : v) { cerr << x << endl; }
          continue;
        }
        if (v[2] != string("EFCT")) {
          //cerr << "not EFCT" << endl;
          continue;
        }
        const auto& sensor = v[0];
        std::vector<string_view> vv = split_string(v[3], ',');
        const auto& value = vv[1]; //string_view(*std::next(vv.begin()));

        time_t current_time = time(NULL);
        if (current_time - last_file_rotation > 30) {

          // close file
          if (current_file.is_open()) {
            current_file.close();
          }

          // rename file
          std::stringstream filenameStream;
          filenameStream << "/var/lib/efergy/" << current_time << ".ts";
          if (rename("/var/lib/efergy/current", filenameStream.str().c_str()) != 0) {
            if (errno != ENOENT) {
              // This is really an error we can't recover from. The best
              // approach is to abort the process, but that won't really
              // make the error go away.
              cerr << "Aborting: cannot move current file " << strerror(errno) << endl;
              abort();
            }
          }

          last_file_rotation = current_time;
        }
        if (!current_file.is_open()) {
          current_file.open("/var/lib/efergy/current", std::ios_base::app);
        }
        if (!current_file.is_open()) {
          cerr << "Cannot open current file: " << strerror(errno) << endl;
          abort();
        }

        current_file << current_time << "," << sensor << "," << value << endl;
        has_data = true;
      }
      if (!has_data) cerr << "Sensor data: >>" << body << "<<"<< endl;
      //cerr << "       data" << buffer2 << endl;
    } else {
      cerr << "type: " << headers["Content-Type"] << endl;
      cerr << buffer;
      cerr << "---------" << endl;
    }
  } else if (request_line.find("/check_key.html", 0) != string::npos) {
    // check_key seems to always succeed and return an empty document
    //auto vv = split_string(request_line, ' ');
    //saveCall("check_key", string(vv[1]), current_time, headers, body);
  } else {
    cerr << "Unknown efergy hub call: " << request_line << endl;
    auto vv = split_string(request_line, ' ');
    saveCall("unknown", string(vv[1]), current_time, headers, body);
  }

  if (SSL_write(ssl, response, 1024) <= 0) {
    cerr << getOpenSSLError() << endl;
    close(clientfd);
    return -1;
  }

  if (SSL_shutdown(ssl) < 0) {
    cerr << getOpenSSLError() << endl;
    close(clientfd);
    return -1;
  }

  if (close(clientfd) !=0 ) {
    cerr << "Error closing connection: " << strerror(errno) << endl;
    return -1;
  }
  return 0;
}

int main(int argc, const char* argv[]) {
  int port = 443;
  if (argc > 1) {
    port = atoi(argv[1]);
  }
  //cerr << port << endl;

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    cerr << "Cannot open socket: " << strerror(errno) << endl;
    return -1;
  }
  struct sockaddr_in addr = {
    AF_INET,
    htons(port),
    0
  };
  if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    cerr << "Cannot bind to port: " << strerror(errno) << endl;
    return -1;
  }
  if (listen(sockfd, 10) == -1) {
    cerr << "Cannot listen on port: " << strerror(errno) << endl;
    return -1;
  }

  // Create scratch directory if necessary
  DIR* dir = opendir("/var/lib/efergy");
  if (dir) {
    closedir(dir);
  } else if (ENOENT == errno) {
    mkdir("/var/lib/efergy", 0755);
  } else {
    cerr << "Cannot create scratch directory: " << strerror(errno) << endl;
    return -1;
  }

  OPENSSL_no_config();

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  const SSL_METHOD *m = SSLv3_method();
#pragma GCC diagnostic pop

  SSL_CTX* ctx = SSL_CTX_new(m);
  SSL_CTX_set_security_level(ctx, 0);
  SSL_CTX_set_cipher_list(ctx, "ALL:RC4-MD5");

  if (read_cert(ctx) != 0) {
    cerr << __LINE__ << getOpenSSLError() << endl;
    return -1;
  }

  struct sigaction psa;
  psa.sa_handler = intHandler;
  psa.sa_flags = SA_NOCLDSTOP;
  sigaction(SIGINT, &psa, NULL);
  sigaction(SIGTERM, &psa, NULL);

  while (keepRunning) {
    if (handle_request(sockfd, ctx) == -1) {
      //break;
    }
  }

  // rename file
  time_t current_time = time(NULL);
  std::stringstream filenameStream;
  filenameStream << "/var/lib/efergy/" << current_time << ".ts";
  if (rename("/var/lib/efergy/current", filenameStream.str().c_str()) != 0) {
    if (errno != ENOENT) {
      // This is really an error we can't recover from. The best
      // approach is to abort the process, but that won't really
      // make the error go away.
      cerr << "Aborting: cannot move current file " << strerror(errno) << endl;
      abort();
    }
  }

  if (close(sockfd) == -1) {
    cerr << "Error closing connection: " << strerror(errno) << endl;
    return -1;
  }

  return 0;
}


