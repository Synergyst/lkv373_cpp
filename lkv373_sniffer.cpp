// lkv373_sniffer.cpp
// LKV373 V2.0 HDMI transmitter sniffer with optional KVM-Proxy protocol server.
// Default behavior: write raw MJPEG frames (multipart/x-mixed-replace) to stdout.
// If --kvm-proxy-proto=1 is supplied, act as a TCP server (default 0.0.0.0:1347)
// and serve frames using the same protocol as v4l2-stream-test.cpp (RAW RGB24 frames).
// Additional: --kvm-proxy-proto-debug=1 prints detected MJPEG framerate and resolution,
// and emits detailed KVM-Proxy protocol state messages to STDERR.

#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <unistd.h>
#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <random>
#include <algorithm>
#include <chrono>
#include <jpeglib.h>
#include <signal.h>

using namespace std;

// ---------------- Common Packet Protocol (must match v4l2-stream-test.cpp) ----------------
namespace netpkt {
static inline uint64_t htonll(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return (((uint64_t)htonl((uint32_t)(v & 0xFFFFFFFFULL))) << 32) | htonl((uint32_t)(v >> 32));
#else
  return v;
#endif
}
static inline uint64_t ntohll(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return (((uint64_t)ntohl((uint32_t)(v & 0xFFFFFFFFULL))) << 32) | ntohl((uint32_t)(v >> 32));
#else
  return v;
#endif
}
static const uint32_t MAGIC = 0x56344C32; // "V4L2"
static const uint16_t PROTO_VER = 1;
enum PacketType : uint16_t {
  PT_DEVINFO  = 1,
  PT_FRAME    = 2,
  PT_HEARTBEAT= 3,
  PT_SIGNAL   = 4
};
enum CaptureSignalState : uint8_t {
  SIGNAL_UP   = 1,
  SIGNAL_DOWN = 2
};
#pragma pack(push, 1)
struct Header {
  uint32_t magic;
  uint16_t version;
  uint16_t type;
  uint32_t headerSize;
  uint64_t payloadSize;
};
#pragma pack(pop)
#pragma pack(push, 1)
struct DevInfoMeta {
  uint16_t dev_index;
  uint16_t byteScaler;
  uint32_t width;
  uint32_t height;
  uint32_t framerate;
  uint32_t target_fps_x1000;
  uint8_t  inputIsBGR;
  uint8_t  isTC358743;
  uint8_t  streamCodec; // 0=RAW, 1=MJPEG
  uint8_t  reserved;
  uint64_t frameDelayMicros_x1000;
  uint32_t deviceNameLen;
};
#pragma pack(pop)
#pragma pack(push, 1)
struct FrameMeta {
  uint64_t frame_id;
  uint64_t timestamp_us;
  uint32_t width;
  uint32_t height;
  uint32_t stride;
  uint8_t  codec;   // 0=RAW, 1=MJPEG
  uint8_t  is_bgr;  // 1 if BGR (client would swap), 0 if RGB
  uint16_t reserved;
};
#pragma pack(pop)
#pragma pack(push, 1)
struct SignalMeta {
  uint8_t state;
  uint8_t reserved[7];
};
#pragma pack(pop)
} // namespace netpkt

// ---------------- Simple bounded queue for stdout MJPEG path ----------------
template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t capacity) : cap_(capacity) {}
    bool try_push(T&& item) {
        std::lock_guard<std::mutex> lk(mu_);
        if (q_.size() >= cap_) return false;
        q_.push_back(std::move(item));
        cv_.notify_one();
        return true;
    }
    T pop() {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [&]{ return !q_.empty(); });
        T item = std::move(q_.front());
        q_.pop_front();
        return item;
    }
private:
    size_t cap_;
    std::deque<T> q_;
    std::mutex mu_;
    std::condition_variable cv_;
};

static void DumpQueueToFD(BoundedQueue<std::vector<uint8_t>>& q, int fd) {
    for (;;) {
        std::vector<uint8_t> blob = q.pop();
        size_t off = 0;
        while (off < blob.size()) {
            ssize_t n = ::write(fd, blob.data() + off, blob.size() - off);
            if (n < 0) {
                std::fprintf(stderr, "write error: %s\n", std::strerror(errno));
                std::exit(1);
            }
            off += static_cast<size_t>(n);
        }
    }
}

// ---------------- Random helper ----------------
static std::string randString(size_t n) {
    static const char* alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<size_t> dist(0, 61);
    std::string s;
    s.reserve(n);
    for (size_t i = 0; i < n; ++i) s.push_back(alphanum[dist(rng)]);
    return s;
}

// ---------------- Wakeup packet helpers (unchanged) ----------------
static bool hex_to_bytes(const std::string& s_in, std::vector<uint8_t>& out) {
    out.clear();
    std::string s;
    s.reserve(s_in.size());
    for (char c : s_in) {
        if ((c >= '0' && c <= '9') || ((c | 32) >= 'a' && (c | 32) <= 'f')) s.push_back(c);
    }
    if (s.size() % 2 != 0) return false;
    out.resize(s.size()/2);
    for (size_t i = 0; i < out.size(); ++i) {
        char hi = s[2*i], lo = s[2*i+1];
        auto h2n = [](char c)->int {
            if (c >= '0' && c <= '9') return c - '0';
            c |= 32;
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            return -1;
        };
        int a = h2n(hi), b = h2n(lo);
        if (a < 0 || b < 0) return false;
        out[i] = static_cast<uint8_t>((a << 4) | b);
    }
    return true;
}
static void BroadcastWakeups(const std::string& ifname, const std::string& sendermac) {
    unsigned ifindex = if_nametoindex(ifname.c_str());
    if (ifindex == 0) {
        std::fprintf(stderr, "Unable to get interface index of %s: %s\n", ifname.c_str(), std::strerror(errno));
        std::exit(1);
    }
    std::vector<uint8_t> macbytes;
    if (!hex_to_bytes(sendermac, macbytes) || macbytes.size() < 6) {
        std::fprintf(stderr, "Invalid MAC address string: %s\n", sendermac.c_str());
        std::exit(1);
    }
    std::vector<uint8_t> packet = {
        0x0b, 0x00, 0x0b, 0x78, 0x00, 0x60, 0x02, 0x90, 0x2b, 0x34, 0x31, 0x02, 0x08, 0x00, 0x45, 0xfc,
        0x02, 0x1c, 0x00, 0x0a, 0x00, 0x00, 0x40, 0x11, 0xa6, 0x0a, 0xc0, 0xa8, 0xa8, 0x38, 0xc0, 0xa8,
        0xa8, 0x37, 0xbe, 0x31, 0xbe, 0x31, 0x02, 0x08, 0xd6, 0xdc, 0x54, 0x46, 0x36, 0x7a, 0x60, 0x02,
        0x00, 0x00, 0x0a, 0x00, 0x00, 0x03, 0x03, 0x01, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x02, 0xef,
        0xdc
    };
    packet.resize(packet.size() + 489, 0x00);
    // Overwrite destination MAC in Ethernet header (first 6 bytes) with sendermac
    std::copy(macbytes.begin(), macbytes.begin() + 6, packet.begin());
    for (;;) {
        int sockfd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sockfd < 0) {
            std::fprintf(stderr, "Unable to open raw socket for keepalives: %s\n", std::strerror(errno));
            std::exit(1);
        }
        sockaddr_ll addr{};
        addr.sll_family = AF_PACKET;
        addr.sll_protocol = htons(ETH_P_ARP);
        addr.sll_ifindex = static_cast<int>(ifindex);
        addr.sll_hatype = 0;
        addr.sll_pkttype = 0;
        addr.sll_halen = 6;
        std::memcpy(addr.sll_addr, macbytes.data(), 6);
        ssize_t n = ::sendto(sockfd, packet.data(), packet.size(), 0,
                             reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (n < 0) {
            std::fprintf(stderr, "sendto keepalive failed: %s\n", std::strerror(errno));
            std::exit(1);
        }
        ::close(sockfd);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// ---------------- Options ----------------
struct Options {
    std::string iface = "eth0";
    bool debug = false;                 // packet debug
    bool kvm_proxy_proto = false;       // replaces mkv
    bool kvm_proxy_proto_debug = false; // KVM-Proxy protocol debug + print detected fps/res
    bool wakeups = true;
    std::string sender_mac = "000b78006001";
    std::string listen_addr = "0.0.0.0";
    int listen_port = 1347;
};

static bool parse_bool(const std::string& v) {
    if (v == "1" || v == "true" || v == "True" || v == "TRUE" || v == "yes" || v == "on") return true;
    if (v == "0" || v == "false" || v == "False" || v == "FALSE" || v == "no" || v == "off") return false;
    return true;
}
static Options parse_args(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto getv = [&](const std::string& key)->std::string {
            if (a.rfind(key + "=", 0) == 0) return a.substr(key.size()+1);
            return "";
        };
        if (a == "--help" || a == "-h") {
            std::fprintf(stderr,
                "Usage: %s [--interface=eth0] [--debug=0] [--kvm-proxy-proto=0] [--kvm-proxy-proto-debug=0]\n"
                "          [--wakeups=1] [--sender-mac=000b78006001] [--listen-addr=0.0.0.0] [--listen-port=1347]\n"
                "Default: MJPEG to stdout. If --kvm-proxy-proto=1, starts server on ADDR:PORT (RAW RGB24 frames via KVM-Proxy protocol).\n"
                "If --kvm-proxy-proto-debug=1, prints detected MJPEG resolution and FPS, and detailed protocol logs.\n",
                argv[0]);
            std::exit(0);
        }
        std::string v;
        if (!(v = getv("--interface")).empty()) o.iface = v;
        else if (!(v = getv("--debug")).empty()) o.debug = parse_bool(v);
        else if (!(v = getv("--kvm-proxy-proto")).empty()) o.kvm_proxy_proto = parse_bool(v);
        else if (!(v = getv("--kvm-proxy-proto-debug")).empty()) o.kvm_proxy_proto_debug = parse_bool(v);
        else if (!(v = getv("--wakeups")).empty()) o.wakeups = parse_bool(v);
        else if (!(v = getv("--sender-mac")).empty()) o.sender_mac = v;
        else if (!(v = getv("--listen-port")).empty()) o.listen_port = std::atoi(v.c_str());
        else if (!(v = getv("--listen-addr")).empty()) o.listen_addr = v;
    }
    if (o.listen_port <= 0 || o.listen_port > 65535) o.listen_port = 1347;
    return o;
}

// ---------------- TCP server for KVM-Proxy ----------------
struct Client {
    int fd = -1;
    bool initialized = false; // DEVINFO+SIGNAL sent
};

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    return 0;
}
static int set_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    flags &= ~O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0) return -1;
    return 0;
}
static bool send_all_dbg(int fd, const void* data, size_t len, bool dbg, const char* what) {
    const uint8_t* p = (const uint8_t*)data;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
        if (n > 0) { sent += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { std::this_thread::sleep_for(std::chrono::milliseconds(1)); continue; }
        if (dbg) std::fprintf(stderr, "[kvm-debug] send_all failed while sending %s to fd=%d: %s\n", what, fd, std::strerror(errno));
        return false;
    }
    return true;
}
static int setup_listen_socket(const std::string& addr, int port, bool dbg) {
    signal(SIGPIPE, SIG_IGN);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("[kvm] socket"); return -1; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (set_nonblocking(fd) < 0) { perror("[kvm] set_nonblocking(listen)"); close(fd); return -1; }
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (addr.empty()) {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        if (inet_pton(AF_INET, addr.c_str(), &sa.sin_addr) <= 0) {
            fprintf(stderr, "[kvm] inet_pton failed for %s\n", addr.c_str());
            close(fd); return -1;
        }
    }
    if (bind(fd, (sockaddr*)&sa, sizeof(sa)) < 0) { perror("[kvm] bind"); close(fd); return -1; }
    if (listen(fd, 16) < 0) { perror("[kvm] listen"); close(fd); return -1; }
    fprintf(stderr, "[kvm] Listening on %s:%d\n", addr.empty() ? "0.0.0.0" : addr.c_str(), port);
    if (dbg) std::fprintf(stderr, "[kvm-debug] KVM-Proxy server initialized\n");
    return fd;
}

// ---------------- JPEG decode to RGB24 ----------------
struct RGBFrame {
    int width = 0;
    int height = 0;
    std::vector<uint8_t> rgb; // size width*height*3
};

static bool jpeg_get_dims(const uint8_t* data, size_t len, int& w, int& h) {
    w = h = 0;
    if (len < 4) return false;
    jpeg_decompress_struct cinfo;
    jpeg_error_mgr jerr;
    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&cinfo);
    jpeg_mem_src(&cinfo, const_cast<unsigned char*>(data), len);
    if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
        jpeg_destroy_decompress(&cinfo);
        return false;
    }
    w = cinfo.image_width;
    h = cinfo.image_height;
    jpeg_destroy_decompress(&cinfo);
    return true;
}

static bool jpeg_decode_to_rgb(const uint8_t* data, size_t len, RGBFrame& out) {
    jpeg_decompress_struct cinfo;
    jpeg_error_mgr jerr;
    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&cinfo);
    jpeg_mem_src(&cinfo, const_cast<unsigned char*>(data), len);
    if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
        jpeg_destroy_decompress(&cinfo);
        return false;
    }
    cinfo.out_color_space = JCS_RGB;
    if (!jpeg_start_decompress(&cinfo)) {
        jpeg_destroy_decompress(&cinfo);
        return false;
    }
    out.width = cinfo.output_width;
    out.height = cinfo.output_height;
    const size_t stride = (size_t)out.width * 3;
    out.rgb.assign((size_t)out.height * stride, 0);
    while (cinfo.output_scanline < cinfo.output_height) {
        JSAMPROW rowptr = (JSAMPROW)(out.rgb.data() + cinfo.output_scanline * stride);
        if (jpeg_read_scanlines(&cinfo, &rowptr, 1) != 1) {
            jpeg_finish_decompress(&cinfo);
            jpeg_destroy_decompress(&cinfo);
            return false;
        }
    }
    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
    return true;
}

// ---------------- KVM-Proxy helpers ----------------
struct DevState {
    int width = 0;
    int height = 0;
    int byteScaler = 3;     // RGB24
    int framerate = 25;     // nominal
    double targetFps = 25;  // nominal
    double frameDelayMicros = 40000.0;
    bool inputIsBGR = false; // we output RGB
    std::string deviceName = "LKV373 Sniffer";
};

static bool send_devinfo_packet(int fd, const DevState& s, bool dbg) {
    using namespace netpkt;
    const uint16_t dev_index = 0;
    const uint8_t isTC358743 = 0;
    const uint8_t streamCodec = 0; // RAW
    const std::string name = s.deviceName;
    DevInfoMeta meta{};
    meta.dev_index = htons(dev_index);
    meta.byteScaler = htons((uint16_t)s.byteScaler);
    meta.width = htonl((uint32_t)s.width);
    meta.height = htonl((uint32_t)s.height);
    meta.framerate = htonl((uint32_t)s.framerate);
    meta.target_fps_x1000 = htonl((uint32_t)(s.targetFps * 1000.0));
    meta.inputIsBGR = s.inputIsBGR ? 1 : 0;
    meta.isTC358743 = isTC358743;
    meta.streamCodec = streamCodec;
    meta.reserved = 0;
    meta.frameDelayMicros_x1000 = htonll((uint64_t)(s.frameDelayMicros * 1000.0));
    meta.deviceNameLen = htonl((uint32_t)name.size());

    Header hdr{};
    hdr.magic = htonl(MAGIC);
    hdr.version = htons(PROTO_VER);
    hdr.type = htons(PT_DEVINFO);
    hdr.headerSize = htonl((uint32_t)(sizeof(Header) + sizeof(DevInfoMeta) + name.size()));
    hdr.payloadSize = htonll(0);

    std::vector<uint8_t> buf;
    buf.resize(sizeof(Header) + sizeof(DevInfoMeta) + name.size());
    std::memcpy(buf.data(), &hdr, sizeof(Header));
    std::memcpy(buf.data() + sizeof(Header), &meta, sizeof(DevInfoMeta));
    if (!name.empty())
        std::memcpy(buf.data() + sizeof(Header) + sizeof(DevInfoMeta), name.data(), name.size());

    bool ok = send_all_dbg(fd, buf.data(), buf.size(), dbg, "DEVINFO");
    if (dbg) {
        if (ok) std::fprintf(stderr, "[kvm-debug] Sent DEVINFO to fd=%d: %dx%d @ %d fps (RGB24)\n", fd, s.width, s.height, s.framerate);
        else std::fprintf(stderr, "[kvm-debug] Failed to send DEVINFO to fd=%d\n", fd);
    }
    return ok;
}

static bool send_signal_packet(int fd, uint8_t state, bool dbg) {
    using namespace netpkt;
    SignalMeta sm{};
    sm.state = state;
    Header hdr{};
    hdr.magic = htonl(MAGIC);
    hdr.version = htons(PROTO_VER);
    hdr.type = htons(PT_SIGNAL);
    hdr.headerSize = htonl((uint32_t)(sizeof(Header) + sizeof(SignalMeta)));
    hdr.payloadSize = htonll(0);

    uint8_t buf[sizeof(Header) + sizeof(SignalMeta)];
    std::memcpy(buf, &hdr, sizeof(hdr));
    std::memcpy(buf + sizeof(hdr), &sm, sizeof(sm));
    bool ok = send_all_dbg(fd, buf, sizeof(buf), dbg, "SIGNAL");
    if (dbg) {
        std::fprintf(stderr, "[kvm-debug] Sent SIGNAL=%s to fd=%d (%s)\n",
                     state == netpkt::SIGNAL_UP ? "UP" : "DOWN", fd, ok ? "ok" : "fail");
    }
    return ok;
}

static bool send_frame_packet_raw(int fd, const RGBFrame& f, uint64_t frame_id, uint64_t ts_us, bool dbg) {
    using namespace netpkt;
    FrameMeta fm{};
    fm.frame_id = htonll(frame_id);
    fm.timestamp_us = htonll(ts_us);
    fm.width = htonl((uint32_t)f.width);
    fm.height = htonl((uint32_t)f.height);
    fm.stride = htonl((uint32_t)(f.width * 3));
    fm.codec = 0;  // RAW
    fm.is_bgr = 0; // RGB
    fm.reserved = 0;

    Header hdr{};
    hdr.magic = htonl(MAGIC);
    hdr.version = htons(PROTO_VER);
    hdr.type = htons(PT_FRAME);
    hdr.headerSize = htonl((uint32_t)(sizeof(Header) + sizeof(FrameMeta)));
    hdr.payloadSize = htonll((uint64_t)f.rgb.size());

    if (!send_all_dbg(fd, &hdr, sizeof(hdr), dbg, "FRAME.header")) return false;
    if (!send_all_dbg(fd, &fm, sizeof(fm), dbg, "FRAME.meta")) return false;
    if (!send_all_dbg(fd, f.rgb.data(), f.rgb.size(), dbg, "FRAME.payload")) return false;
    return true;
}

// ---------------- Main ----------------
struct Frame {
    uint16_t FrameID = 0;
    uint16_t LastChunk = 0;
    std::vector<uint8_t> Data;
};

int main(int argc, char** argv) {
    Options opt = parse_args(argc, argv);

    if (opt.wakeups) {
        std::thread(BroadcastWakeups, opt.iface, opt.sender_mac).detach();
    }

    // pcap setup
    const uint8_t MULTICAST_MAC[6] = {0x01, 0x00, 0x5e, 0x02, 0x02, 0x02};
    char errbuf[PCAP_ERRBUF_SIZE]{0};
    pcap_t* handle = pcap_open_live(opt.iface.c_str(), 1500, 1, 500, errbuf);
    if (!handle) {
        std::fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    // MJPEG stdout path (default)
    int videofd = STDOUT_FILENO;
    BoundedQueue<std::vector<uint8_t>> videodis(100);
    std::thread writer_thread;
    if (!opt.kvm_proxy_proto) {
        // initial boundary
        {
            const char* hdr = "--myboundary\nContent-Type: image/jpeg\n\n";
            std::vector<uint8_t> v(hdr, hdr + std::strlen(hdr));
            videodis.try_push(std::move(v));
        }
        writer_thread = std::thread(DumpQueueToFD, std::ref(videodis), videofd);
        writer_thread.detach();
    }

    // KVM-Proxy server path
    int listen_fd = -1;
    std::vector<Client> clients;
    DevState dev{};
    std::atomic<uint64_t> frame_id_counter{0};
    bool devinfo_set = false;
    auto mono_start = std::chrono::steady_clock::now();

    if (opt.kvm_proxy_proto) {
        listen_fd = setup_listen_socket(opt.listen_addr, opt.listen_port, opt.kvm_proxy_proto_debug);
        if (listen_fd < 0) {
            pcap_close(handle);
            return 1;
        }
        if (opt.kvm_proxy_proto_debug) {
            std::fprintf(stderr, "[kvm-debug] KVM-Proxy protocol mode enabled on %s:%d\n",
                         opt.listen_addr.c_str(), opt.listen_port);
        }
    }

    auto accept_clients = [&]() {
        if (listen_fd < 0) return;
        for (;;) {
            sockaddr_in cliaddr{};
            socklen_t len = sizeof(cliaddr);
            int cfd = accept(listen_fd, (sockaddr*)&cliaddr, &len);
            if (cfd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                perror("[kvm] accept");
                break;
            }
            set_blocking(cfd);
            int one = 1;
            setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            setsockopt(cfd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
            Client c; c.fd = cfd; c.initialized = false;
            clients.push_back(c);
            char ip[64]; inet_ntop(AF_INET, &cliaddr.sin_addr, ip, sizeof(ip));
            fprintf(stderr, "[kvm] client %s:%d connected (fd=%d), total=%zu\n", ip, ntohs(cliaddr.sin_port), cfd, clients.size());
            if (opt.kvm_proxy_proto_debug) {
                std::fprintf(stderr, "[kvm-debug] New client fd=%d awaiting DEVINFO/SIGNAL\n", cfd);
            }
            // If we already have devinfo, send now
            if (devinfo_set) {
                if (send_devinfo_packet(cfd, dev, opt.kvm_proxy_proto_debug)) {
                    send_signal_packet(cfd, netpkt::SIGNAL_UP, opt.kvm_proxy_proto_debug);
                    std::fprintf(stderr, "[kvm-debug] Sent DEVINFO/SIGNAL packet to client fd=%d\n", cfd);
                    for (auto& cc : clients) { if (cc.fd == cfd) { cc.initialized = true; break; } }
                }
            }
        }
    };

    auto broadcast_raw_frame = [&](const RGBFrame& rgb) {
        if (clients.empty()) return;
        uint64_t id = frame_id_counter.fetch_add(1, std::memory_order_relaxed) + 1;
        uint64_t ts_us = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - mono_start).count();
        for (size_t i = 0; i < clients.size();) {
            Client& c = clients[i];
            if (!c.initialized) {
                if (!send_devinfo_packet(c.fd, dev, opt.kvm_proxy_proto_debug) ||
                    !send_signal_packet(c.fd, netpkt::SIGNAL_UP, opt.kvm_proxy_proto_debug)) {
                    if (opt.kvm_proxy_proto_debug) std::fprintf(stderr, "[kvm-debug] init failed, drop fd=%d\n", c.fd);
                    close(c.fd);
                    clients.erase(clients.begin() + i);
                    continue;
                }
                c.initialized = true;
            }
            if (opt.kvm_proxy_proto_debug) {
                std::fprintf(stderr, "[kvm-debug] Sending FRAME id=%" PRIu64 " %dx%d bytes=%zu to fd=%d\n",
                             id, rgb.width, rgb.height, rgb.rgb.size(), c.fd);
            }
            if (!send_frame_packet_raw(c.fd, rgb, id, ts_us, opt.kvm_proxy_proto_debug)) {
                fprintf(stderr, "[kvm] drop client fd=%d (send error: %s)\n", c.fd, std::strerror(errno));
                close(c.fd);
                clients.erase(clients.begin() + i);
                continue;
            }
            ++i;
        }
    };

    int droppedframes = 0;
    int desyncframes = 0;
    int totalframes = 0;
    Frame CurrentPacket;
    CurrentPacket.Data.clear();

    // MJPEG FPS estimation
    bool have_last_time = false;
    auto last_frame_tp = std::chrono::steady_clock::now();
    double fps_est = 0.0;
    double ema_alpha = 0.2;
    size_t fps_samples = 0;
    auto last_fps_print = std::chrono::steady_clock::now();

    // Ports
    const int UDP_DPORT_OFFSET = 36; // Ethernet(14)+IPv4(20)=34; UDP dest port at +2 -> 36..37
    const int APP_OFFSET = 42;       // 14+20+8
    const uint8_t AUDIO_DPORT_BE[2] = {0x08, 0x12}; // 2066 (ignored now)
    const uint8_t VIDEO_DPORT_BE[2] = {0x08, 0x14}; // 2068

    for (;;) {
        if (opt.kvm_proxy_proto) {
            accept_clients();
        }

        struct pcap_pkthdr* header = nullptr;
        const u_char* pkt = nullptr;
        int r = pcap_next_ex(handle, &header, &pkt);
        if (r < 0) break;
        if (r == 0) continue; // timeout
        if (header->caplen < 100) continue;

        const uint8_t* MACADDR = pkt;
        if (std::memcmp(MACADDR, MULTICAST_MAC, 6) != 0) continue;

        const uint8_t* UDP_DPORT = pkt + UDP_DPORT_OFFSET;
        const uint8_t* ApplicationData = pkt + APP_OFFSET;
        size_t app_len = header->caplen - APP_OFFSET;
        if (app_len < 5) continue;

        // Ignore audio completely now
        if (UDP_DPORT[0] == AUDIO_DPORT_BE[0] && UDP_DPORT[1] == AUDIO_DPORT_BE[1]) {
            continue;
        }

        // Video on port 2068
        if (!(UDP_DPORT[0] == VIDEO_DPORT_BE[0] && UDP_DPORT[1] == VIDEO_DPORT_BE[1])) continue;

        uint16_t FrameNumber = static_cast<uint16_t>((ApplicationData[0] << 8) | ApplicationData[1]);
        uint16_t CurrentChunk = static_cast<uint16_t>((ApplicationData[2] << 8) | ApplicationData[3]);

        if (CurrentPacket.FrameID != FrameNumber && CurrentPacket.FrameID != 0) {
            // Did we drop a packet?
            droppedframes++;
            if (CurrentPacket.FrameID < FrameNumber) {
                CurrentPacket = Frame{};
                CurrentPacket.Data.clear();
                CurrentPacket.LastChunk = 0;
                if (opt.debug) std::fprintf(stderr, "Dropped packet due to non-sane frame number (%d dropped so far)\n", droppedframes);
            }
            continue;
        }

        if (opt.debug) {
            std::fprintf(stderr, "%u/%u - %u/%u - %zu\n",
                         FrameNumber, CurrentChunk, CurrentPacket.FrameID, CurrentPacket.LastChunk, app_len);
        }

        if (CurrentPacket.LastChunk != 0 && CurrentPacket.LastChunk != static_cast<uint16_t>(CurrentChunk - 1)) {
            if (static_cast<uint16_t>(~(CurrentChunk << 15)) != 65534) {
                if (opt.debug) {
                    std::fprintf(stderr,
                        "Dropped packet because of desync detected (%d dropped so far, %d because of desync)\n",
                        droppedframes, desyncframes);
                    std::fprintf(stderr, "You see; %u != %u-1\n", CurrentPacket.LastChunk, CurrentChunk);
                }
                droppedframes++;
                desyncframes++;
                CurrentPacket = Frame{};
                CurrentPacket.Data.clear();
                CurrentPacket.LastChunk = 0;
                continue;
            }
            CurrentPacket.LastChunk = CurrentChunk;
        }

        // Append payload
        if (app_len > 4) {
            const uint8_t* payload = ApplicationData + 4;
            size_t payload_len = app_len - 4;
            size_t oldSize = CurrentPacket.Data.size();
            CurrentPacket.Data.resize(oldSize + payload_len);
            std::memcpy(CurrentPacket.Data.data() + oldSize, payload, payload_len);
            CurrentPacket.FrameID = FrameNumber;
            CurrentPacket.LastChunk = CurrentChunk;
        }

        // End of frame detection: high bit set?
        if (static_cast<uint16_t>(~(CurrentChunk >> 15)) == 65534) {
            // Completed JPEG frame in CurrentPacket.Data
            totalframes++;

            // FPS estimation
            auto now = std::chrono::steady_clock::now();
            if (have_last_time) {
                double dt = std::chrono::duration<double>(now - last_frame_tp).count();
                if (dt > 0.001 && dt < 1.0) {
                    double inst = 1.0 / dt;
                    if (fps_samples == 0) fps_est = inst;
                    else fps_est = ema_alpha * inst + (1.0 - ema_alpha) * fps_est;
                    fps_samples++;
                }
            } else {
                have_last_time = true;
            }
            last_frame_tp = now;

            if (!opt.kvm_proxy_proto) {
                const char* boundary = "\n--myboundary\nContent-Type: image/jpeg\n\n";
                std::vector<uint8_t> fin;
                fin.reserve(std::strlen(boundary) + CurrentPacket.Data.size());
                fin.insert(fin.end(), boundary, boundary + std::strlen(boundary));
                fin.insert(fin.end(), CurrentPacket.Data.begin(), CurrentPacket.Data.end());
                (void)videodis.try_push(std::move(fin));
            } else {
                // KVM mode: ensure devinfo, decode to RGB if there are clients
                int w = 0, h = 0;
                if (!devinfo_set) {
                    if (jpeg_get_dims(CurrentPacket.Data.data(), CurrentPacket.Data.size(), w, h)) {
                        dev.width = w;
                        dev.height = h;
                        // If we have at least a few fps samples, use that; otherwise default to 25
                        int fps_i = (fps_samples >= 3) ? (int)(fps_est + 0.5) : 25;
                        if (fps_i <= 0) fps_i = 25;
                        dev.framerate = fps_i;
                        dev.targetFps = (double)fps_i;
                        dev.frameDelayMicros = 1000000.0 / dev.targetFps;
                        devinfo_set = true;
                        if (opt.kvm_proxy_proto_debug) {
                            std::fprintf(stderr, "[kvm-debug] Detected MJPEG stream: %dx%d @ ~%.2f fps (initial)\n",
                                         dev.width, dev.height, (fps_samples ? fps_est : (double)dev.framerate));
                        }
                        // initialize existing clients
                        for (auto& c : clients) {
                            if (send_devinfo_packet(c.fd, dev, opt.kvm_proxy_proto_debug)) {
                                send_signal_packet(c.fd, netpkt::SIGNAL_UP, opt.kvm_proxy_proto_debug);
                                c.initialized = true;
                            }
                        }
                    }
                } else {
                    // Periodic debug print with current estimate
                    if (opt.kvm_proxy_proto_debug) {
                        auto since = std::chrono::duration<double>(now - last_fps_print).count();
                        if (since >= 2.0 && fps_samples > 0) {
                            std::fprintf(stderr, "[kvm-debug] MJPEG stream ongoing: %dx%d @ ~%.2f fps (clients=%zu)\n",
                                         dev.width, dev.height, fps_est, clients.size());
                            last_fps_print = now;
                        }
                    }
                }

                if (!clients.empty() && devinfo_set) {
                    RGBFrame rgb;
                    if (jpeg_decode_to_rgb(CurrentPacket.Data.data(), CurrentPacket.Data.size(), rgb)) {
                        // sanity: dimensions stable?
                        if (rgb.width != dev.width || rgb.height != dev.height) {
                            if (opt.kvm_proxy_proto_debug) {
                                std::fprintf(stderr, "[kvm-debug] Resolution change detected: %dx%d -> %dx%d, resending DEVINFO\n",
                                             dev.width, dev.height, rgb.width, rgb.height);
                            }
                            dev.width = rgb.width;
                            dev.height = rgb.height;
                            for (auto& c : clients) {
                                send_devinfo_packet(c.fd, dev, opt.kvm_proxy_proto_debug);
                                send_signal_packet(c.fd, netpkt::SIGNAL_UP, opt.kvm_proxy_proto_debug);
                                c.initialized = true;
                            }
                        }
                        broadcast_raw_frame(rgb);
                    } else {
                        if (opt.kvm_proxy_proto_debug) std::fprintf(stderr, "[kvm-debug] JPEG decode failed (%zu bytes)\n", CurrentPacket.Data.size());
                    }
                }
            }

            if (opt.debug) {
                std::fprintf(stderr, "Frame #%d Size: %zu\n", totalframes, CurrentPacket.Data.size());
            }
            CurrentPacket = Frame{};
            CurrentPacket.Data.clear();
            CurrentPacket.FrameID = 0;
            CurrentPacket.LastChunk = 0;
        }
    }

    pcap_close(handle);
    if (listen_fd >= 0) close(listen_fd);
    for (auto& c : clients) if (c.fd >= 0) close(c.fd);
    return 0;
}
