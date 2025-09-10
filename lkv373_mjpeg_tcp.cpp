// lkv373_restream.cpp
// Sniff LKV373 V2 video UDP, reconstruct frames, decode to RGB24,
// keep a framebuffer, and re-encode to JPEG at fixed FPS.
// Streams concatenated JPEGs over TCP (for KVM-Proxy) or stdout.
//
// Build (Debian/Ubuntu):
//   sudo apt-get update
//   sudo apt-get install -y build-essential libpcap-dev libjpeg-turbo8-dev
//   g++ -std=c++17 -O2 -pthread lkv373_restream.cpp -o lkv373-restream -lpcap -ljpeg
//
// Run (default: listen 127.0.0.1:1347):
//   ./lkv373-restream --interface=eth0
//
// Point KVM-Proxy to it:
//   export TCP_HOST=127.0.0.1
//   export TCP_PORT=1347
//   ./kvm-proxy-binary
//
// Options:
//   --interface=eth0         Capture interface (default eth0)
//   --sender-mac=000b78006001  Sender MAC for wakeups (default 000b78006001)
//   --wakeups=1|0            Send LKV373 keepalives (default 1)
//   --debug=1|0              Debug logs (default 0)
//   --tcp-port=1347          TCP port to stream to clients (0=disable TCP)
//   --bind=127.0.0.1         TCP bind IP (default 127.0.0.1)
//   --stdout=1|0             Write JPEG frames to stdout instead of TCP (default 0)
//   --fps=15                 Output FPS (default 15)
//   --quality=80             JPEG quality (1..100, default 80)
//
// Output format:
//   - TCP: raw concatenated JPEG frames (no multipart boundary)
//   - stdout: raw concatenated JPEG frames (same as TCP)

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <jpeglib.h>
#include <setjmp.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include <string_view>
#include <iostream>
#include <signal.h>

struct Options {
    std::string iface = "eth0";
    std::string bind_ip = "127.0.0.1";
    std::string sender_mac = "000b78006001";
    bool debug = false;
    bool wakeups = true;
    int tcp_port = 1347;  // 0 = disabled
    bool stdout_mode = false;
    int fps = 15;
    int quality = 80;
};

static bool parse_bool(std::string v) {
    for (auto &c : v) c = (char)std::tolower((unsigned char)c);
    if (v == "1" || v == "true" || v == "yes" || v == "on") return true;
    if (v == "0" || v == "false" || v == "no" || v == "off") return false;
    return true;
}
static std::optional<int> parse_int(const char* s) {
    if (!s) return std::nullopt;
    char* end = nullptr;
    long v = std::strtol(s, &end, 10);
    if (!end || *end != '\0') return std::nullopt;
    return (int)v;
}
static Options parse_args(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto kv = a.find('=');
        std::string k = (kv == std::string::npos) ? a : a.substr(0, kv);
        std::string v = (kv == std::string::npos) ? "" : a.substr(kv + 1);
        if (k == "--help" || k == "-h") {
            std::fprintf(stderr,
                "Usage: %s [--interface=eth0] [--bind=127.0.0.1] [--tcp-port=1347]\n"
                "          [--stdout=0] [--fps=15] [--quality=80]\n"
                "          [--wakeups=1] [--sender-mac=000b78006001] [--debug=0]\n", argv[0]);
            std::exit(0);
        } else if (k == "--interface") {
            if (!v.empty()) o.iface = v;
        } else if (k == "--bind") {
            if (!v.empty()) o.bind_ip = v;
        } else if (k == "--tcp-port") {
            if (!v.empty()) o.tcp_port = std::stoi(v);
        } else if (k == "--stdout") {
            if (!v.empty()) o.stdout_mode = parse_bool(v);
        } else if (k == "--fps") {
            if (!v.empty()) o.fps = std::stoi(v);
        } else if (k == "--quality") {
            if (!v.empty()) o.quality = std::stoi(v);
        } else if (k == "--wakeups") {
            if (!v.empty()) o.wakeups = parse_bool(v);
        } else if (k == "--sender-mac") {
            if (!v.empty()) o.sender_mac = v;
        } else if (k == "--debug") {
            if (!v.empty()) o.debug = parse_bool(v);
        } else {
            std::fprintf(stderr, "Unknown arg: %s\n", a.c_str());
            std::exit(2);
        }
    }
    if (o.stdout_mode) o.tcp_port = 0;
    if (o.quality < 1) o.quality = 1;
    if (o.quality > 100) o.quality = 100;
    if (o.fps < 1) o.fps = 1;
    return o;
}

static std::atomic<bool> g_shutdown{false};

static bool hex_to_bytes(const std::string& s_in, std::vector<uint8_t>& out) {
    out.clear();
    std::string s;
    s.reserve(s_in.size());
    for (char c : s_in) {
        if ((c >= '0' && c <= '9') || ((c|32) >= 'a' && (c|32) <= 'f')) s.push_back(c);
    }
    if (s.size() % 2 != 0) return false;
    out.resize(s.size()/2);
    auto h2n = [](char c)->int {
        if (c >= '0' && c <= '9') return c - '0';
        c |= 32;
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        return -1;
    };
    for (size_t i = 0; i < out.size(); ++i) {
        int a = h2n(s[2*i]), b = h2n(s[2*i+1]);
        if (a < 0 || b < 0) return false;
        out[i] = (uint8_t)((a << 4) | b);
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
        std::fprintf(stderr, "Invalid MAC string: %s\n", sendermac.c_str());
        std::exit(1);
    }
    std::vector<uint8_t> packet = {
        0x0b,0x00,0x0b,0x78,0x00,0x60,0x02,0x90,0x2b,0x34,0x31,0x02,0x08,0x00,0x45,0xfc,
        0x02,0x1c,0x00,0x0a,0x00,0x00,0x40,0x11,0xa6,0x0a,0xc0,0xa8,0xa8,0x38,0xc0,0xa8,
        0xa8,0x37,0xbe,0x31,0xbe,0x31,0x02,0x08,0xd6,0xdc,0x54,0x46,0x36,0x7a,0x60,0x02,
        0x00,0x00,0x0a,0x00,0x00,0x03,0x03,0x01,0x00,0x26,0x00,0x00,0x00,0x00,0x02,0xef,
        0xdc
    };
    packet.resize(packet.size() + 489, 0x00);
    // set dest MAC = provided sender mac
    std::copy(macbytes.begin(), macbytes.begin() + 6, packet.begin());

    while (!g_shutdown.load()) {
        int sockfd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sockfd < 0) {
            std::fprintf(stderr, "raw socket for keepalives failed: %s\n", std::strerror(errno));
            std::exit(1);
        }
        sockaddr_ll addr{};
        addr.sll_family = AF_PACKET;
        addr.sll_protocol = htons(ETH_P_ARP);
        addr.sll_ifindex = (int)ifindex;
        addr.sll_halen = 6;
        std::memcpy(addr.sll_addr, macbytes.data(), 6);
        ssize_t n = ::sendto(sockfd, packet.data(), packet.size(), 0,
                             reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (n < 0) {
            std::fprintf(stderr, "keepalive sendto failed: %s\n", std::strerror(errno));
            std::exit(1);
        }
        ::close(sockfd);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// JPEG helpers
struct JpegErrorMgr {
    jpeg_error_mgr pub;
    jmp_buf jb;
};
static void jpeg_error_exit_trampoline(j_common_ptr cinfo) {
    JpegErrorMgr* err = (JpegErrorMgr*)cinfo->err;
    longjmp(err->jb, 1);
}
static bool decode_jpeg_to_rgb(const uint8_t* data, size_t len, std::vector<uint8_t>& rgb, int& w, int& h) {
    jpeg_decompress_struct cinfo{};
    JpegErrorMgr jerr{};
    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = jpeg_error_exit_trampoline;

    if (setjmp(jerr.jb)) {
        jpeg_destroy_decompress(&cinfo);
        return false;
    }
    jpeg_create_decompress(&cinfo);
    jpeg_mem_src(&cinfo, const_cast<unsigned char*>(data), (unsigned long)len);
    jpeg_read_header(&cinfo, TRUE);
    cinfo.out_color_space = JCS_RGB;
    jpeg_start_decompress(&cinfo);

    w = (int)cinfo.output_width;
    h = (int)cinfo.output_height;
    rgb.resize((size_t)w * h * 3);
    while (cinfo.output_scanline < cinfo.output_height) {
        JSAMPROW rowptr = (JSAMPROW)&rgb[(size_t)cinfo.output_scanline * w * 3];
        jpeg_read_scanlines(&cinfo, &rowptr, 1);
    }
    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
    return true;
}

static bool encode_rgb_to_jpeg(const uint8_t* rgb, int w, int h, int quality, std::string& out) {
    out.clear();
    jpeg_compress_struct cinfo{};
    jpeg_error_mgr jerr{};
    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_compress(&cinfo);

    unsigned char* mem = nullptr;
    unsigned long mem_size = 0;
    jpeg_mem_dest(&cinfo, &mem, &mem_size);

    cinfo.image_width = w;
    cinfo.image_height = h;
    cinfo.input_components = 3;
    cinfo.in_color_space = JCS_RGB;
    jpeg_set_defaults(&cinfo);
    jpeg_set_quality(&cinfo, quality, TRUE);

    jpeg_start_compress(&cinfo, TRUE);
    JSAMPROW row_pointer[1];
    while (cinfo.next_scanline < cinfo.image_height) {
        row_pointer[0] = (JSAMPROW)&rgb[cinfo.next_scanline * w * 3];
        jpeg_write_scanlines(&cinfo, row_pointer, 1);
    }
    jpeg_finish_compress(&cinfo);

    if (mem && mem_size > 0) {
        out.assign(reinterpret_cast<char*>(mem), reinterpret_cast<char*>(mem) + mem_size);
    }
    if (mem) free(mem);
    jpeg_destroy_compress(&cinfo);
    return !out.empty();
}

// Framebuffer
struct Framebuffer {
    std::mutex m;
    std::vector<uint8_t> rgb; // RGB24
    int w = 0, h = 0;
    bool hasFrame = false;
    uint64_t seq = 0; // incremented on update
};

// TCP streamer (single-client)
class TcpStreamer {
public:
    TcpStreamer(const std::string& bind_ip, int port) : bind_ip_(bind_ip), port_(port) {}
    ~TcpStreamer() { stop(); }

    void start() {
        if (port_ <= 0) return;
        stop_ = false;
        th_ = std::thread(&TcpStreamer::run, this);
    }
    void stop() {
        stop_ = true;
        if (lfd_ >= 0) { ::shutdown(lfd_, SHUT_RDWR); ::close(lfd_); lfd_ = -1; }
        if (cfd_ >= 0) { ::shutdown(cfd_, SHUT_RDWR); ::close(cfd_); cfd_ = -1; }
        if (th_.joinable()) th_.join();
    }

    bool writeFrame(const std::string& jpeg) {
        if (port_ <= 0) return false;
        if (cfd_ < 0) return false;
        size_t off = 0;
        while (off < jpeg.size()) {
            ssize_t n = ::send(cfd_, jpeg.data() + off, jpeg.size() - off, 0);
            if (n <= 0) {
                if (errno == EINTR) continue;
                ::close(cfd_);
                cfd_ = -1;
                return false;
            }
            off += (size_t)n;
        }
        return true;
    }

private:
    void run() {
        lfd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (lfd_ < 0) {
            std::fprintf(stderr, "socket() failed: %s\n", std::strerror(errno));
            return;
        }
        int on = 1;
        setsockopt(lfd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)port_);
        if (::inet_pton(AF_INET, bind_ip_.c_str(), &addr.sin_addr) != 1) {
            std::fprintf(stderr, "Invalid bind IP: %s\n", bind_ip_.c_str());
            ::close(lfd_); lfd_ = -1; return;
        }
        if (::bind(lfd_, (sockaddr*)&addr, sizeof(addr)) < 0) {
            std::fprintf(stderr, "bind() failed: %s\n", std::strerror(errno));
            ::close(lfd_); lfd_ = -1; return;
        }
        if (::listen(lfd_, 1) < 0) {
            std::fprintf(stderr, "listen() failed: %s\n", std::strerror(errno));
            ::close(lfd_); lfd_ = -1; return;
        }
        std::printf("[stream] Listening on %s:%d\n", bind_ip_.c_str(), port_);
        while (!stop_) {
            sockaddr_in cli{};
            socklen_t sl = sizeof(cli);
            int c = ::accept(lfd_, (sockaddr*)&cli, &sl);
            if (c < 0) {
                if (errno == EINTR) continue;
                if (stop_) break;
                std::fprintf(stderr, "accept() failed: %s\n", std::strerror(errno));
                continue;
            }
            if (cfd_ >= 0) { ::close(cfd_); }
            cfd_ = c;
            std::printf("[stream] Client connected\n");
        }
    }

    std::string bind_ip_;
    int port_{0};
    std::thread th_;
    std::atomic<bool> stop_{false};
    int lfd_{-1};
    int cfd_{-1};
};

// stdout sink
static bool write_stdout_frame(const std::string& jpeg) {
    size_t off = 0;
    while (off < jpeg.size()) {
        ssize_t n = ::write(STDOUT_FILENO, jpeg.data() + off, jpeg.size() - off);
        if (n <= 0) {
            if (errno == EINTR) continue;
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

// Packet reassembly and capture
struct Reassembler {
    uint16_t curFrameId = 0;
    uint16_t lastChunkNum = 0;
    std::vector<uint8_t> buf;
    int dropped = 0;
    int desync = 0;
    int frames = 0;

    void reset() {
        curFrameId = 0;
        lastChunkNum = 0;
        buf.clear();
    }
};

static void capture_thread(const Options& opt, Framebuffer* fb) {
    const uint8_t MULTICAST_MAC[6] = {0x01,0x00,0x5e,0x02,0x02,0x02};
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* handle = pcap_open_live(opt.iface.c_str(), 2000, 1, 500, errbuf);
    if (!handle) {
        std::fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        std::exit(1);
    }

    Reassembler r;

    while (!g_shutdown.load()) {
        struct pcap_pkthdr* hdr = nullptr;
        const u_char* pkt = nullptr;
        int rv = pcap_next_ex(handle, &hdr, &pkt);
        if (rv < 0) break;
        if (rv == 0 || !hdr || !pkt) continue;
        if (hdr->caplen < 60) continue;

        size_t off = 0;
        // Ethernet
        uint16_t etherType = ntohs(*(const uint16_t*)(pkt + 12));
        size_t eth_hdr_len = 14;
        if (etherType == 0x8100 /* VLAN */) {
            if (hdr->caplen < 18) continue;
            etherType = ntohs(*(const uint16_t*)(pkt + 16));
            eth_hdr_len = 18;
        }
        if (hdr->caplen < eth_hdr_len + 20) continue;

        const uint8_t* dstMac = pkt + 0;
        if (std::memcmp(dstMac, MULTICAST_MAC, 6) != 0) continue;

        // IPv4 only
        if (etherType != 0x0800) continue;
        const uint8_t* ip = pkt + eth_hdr_len;
        uint8_t ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20) continue;
        if (hdr->caplen < eth_hdr_len + ihl + 8) continue;

        // UDP
        const uint8_t* udp = ip + ihl;
        uint16_t dport = (uint16_t)((udp[2] << 8) | udp[3]);
        if (dport != 2068) continue; // video only
        const uint8_t* app = udp + 8;
        size_t app_len = hdr->caplen - (eth_hdr_len + ihl + 8);
        if (app_len < 5) continue;

        // LKV373 header: [frameID(2)][chunkField(2)][payload...]
        uint16_t frameId = (uint16_t)((app[0] << 8) | app[1]);
        uint16_t chunkField = (uint16_t)((app[2] << 8) | app[3]);
        bool isLast = (chunkField & 0x8000) != 0;
        uint16_t chunkNum = (uint16_t)(chunkField & 0x7FFF);

        if (opt.debug) {
            std::fprintf(stderr, "fid=%u ch=%u%s len=%zu\n",
                frameId, chunkNum, isLast ? "(last)" : "", app_len);
        }

        if (r.curFrameId == 0) {
            r.curFrameId = frameId;
            r.lastChunkNum = 0;
            r.buf.clear();
        }

        if (frameId != r.curFrameId) {
            // dropped/old frame; reset and start new
            r.dropped++;
            r.curFrameId = frameId;
            r.lastChunkNum = 0;
            r.buf.clear();
        }

        // append payload
        if (app_len > 4) {
            const uint8_t* payload = app + 4;
            size_t payload_len = app_len - 4;
            size_t old = r.buf.size();
            r.buf.resize(old + payload_len);
            std::memcpy(r.buf.data() + old, payload, payload_len);
        }

        if (isLast) {
            // We have a complete JPEG frame
            int w=0, h=0;
            std::vector<uint8_t> rgb;
            if (decode_jpeg_to_rgb(r.buf.data(), r.buf.size(), rgb, w, h)) {
                std::lock_guard<std::mutex> lk(fb->m);
                fb->rgb.swap(rgb);
                fb->w = w; fb->h = h;
                fb->hasFrame = true;
                fb->seq++;
            } else if (opt.debug) {
                std::fprintf(stderr, "JPEG decode failed (size=%zu)\n", r.buf.size());
            }
            r.frames++;
            r.reset();
        } else {
            r.lastChunkNum = chunkNum;
        }
    }
    pcap_close(handle);
}

// Encoder thread: at fixed FPS, re-encode framebuffer to JPEG and emit
static void encoder_thread(const Options& opt, Framebuffer* fb, TcpStreamer* streamer) {
    const auto interval = std::chrono::milliseconds(1000 / opt.fps);
    uint64_t lastSeq = 0;

    while (!g_shutdown.load()) {
        auto t0 = std::chrono::steady_clock::now();

        int w=0, h=0;
        std::vector<uint8_t> rgb;
        {
            std::lock_guard<std::mutex> lk(fb->m);
            if (fb->hasFrame) {
                w = fb->w; h = fb->h;
                rgb = fb->rgb; // copy; keeps lock short
                lastSeq = fb->seq;
            }
        }
        if (w > 0 && h > 0 && !rgb.empty()) {
            std::string jpeg;
            if (encode_rgb_to_jpeg(rgb.data(), w, h, opt.quality, jpeg)) {
                if (opt.stdout_mode) {
                    write_stdout_frame(jpeg);
                } else if (streamer) {
                    streamer->writeFrame(jpeg);
                }
            } else if (opt.debug) {
                std::fprintf(stderr, "JPEG encode failed\n");
            }
        } else {
            // No frame yet; nothing to send
            if (opt.debug) std::fprintf(stderr, "No framebuffer yet\n");
        }

        auto t1 = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);
        if (elapsed < interval) {
            std::this_thread::sleep_for(interval - elapsed);
        }
    }
}

int main(int argc, char** argv) {
    Options opt = parse_args(argc, argv);

    ::signal(SIGINT, [](int){ g_shutdown.store(true); });
    ::signal(SIGTERM, [](int){ g_shutdown.store(true); });

    if (opt.wakeups) {
        std::thread(BroadcastWakeups, opt.iface, opt.sender_mac).detach();
    }

    Framebuffer fb;

    TcpStreamer streamer(opt.bind_ip, opt.tcp_port);
    if (!opt.stdout_mode && opt.tcp_port > 0) {
        streamer.start();
    }

    std::thread capTh(capture_thread, std::cref(opt), &fb);
    std::thread encTh(encoder_thread, std::cref(opt), &fb, opt.stdout_mode ? nullptr : &streamer);

    capTh.join();
    g_shutdown.store(true);
    encTh.join();
    streamer.stop();
    return 0;
}
