// lkv373_sniffer.cpp
// C++17 translation of the provided Go source for LKV373 V2.0 HDMI transmitter sniffer.

#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
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

struct Frame {
    uint16_t FrameID = 0;
    uint16_t LastChunk = 0;
    std::vector<uint8_t> Data;
};

template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t capacity) : cap_(capacity) {}

    // Non-blocking push; returns false if full.
    bool try_push(T&& item) {
        std::lock_guard<std::mutex> lk(mu_);
        if (q_.size() >= cap_) return false;
        q_.push_back(std::move(item));
        cv_.notify_one();
        return true;
    }

    // Blocking pop; returns item by value.
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

static std::string randString(size_t n) {
    static const char* alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<size_t> dist(0, 61);
    std::string s;
    s.reserve(n);
    for (size_t i = 0; i < n; ++i) s.push_back(alphanum[dist(rng)]);
    return s;
}

static bool hex_to_bytes(const std::string& s_in, std::vector<uint8_t>& out) {
    out.clear();
    std::string s;
    s.reserve(s_in.size());
    for (char c : s_in) {
        if ((c >= '0' && c <= '9') || (c|32) >= 'a' && (c|32) <= 'f') s.push_back(c);
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

static void WrapInMKV(const std::string& uuidpath, BoundedQueue<std::vector<uint8_t>>& audioQ, bool audio) {
    // Create pipes: one for child's stdout (ffmpeg -> parent) and one for child's stdin (parent -> ffmpeg).
    int pipe_out[2]; // child stdout -> parent read
    int pipe_in[2];  // parent write -> child stdin
    if (pipe(pipe_out) < 0 || pipe(pipe_in) < 0) {
        std::fprintf(stderr, "Unable to setup pipes for ffmpeg\n");
        std::exit(1);
    }

    pid_t pid = fork();
    if (pid < 0) {
        std::fprintf(stderr, "fork failed: %s\n", std::strerror(errno));
        std::exit(1);
    }

    if (pid == 0) {
        // Child
        // stdout
        dup2(pipe_out[1], STDOUT_FILENO);
        // stdin
        dup2(pipe_in[0], STDIN_FILENO);
        // stderr -> inherit parent stderr
        // Close pipe ends
        close(pipe_out[0]); close(pipe_out[1]);
        close(pipe_in[0]); close(pipe_in[1]);

        std::vector<char*> argv;
        auto push = [&](const std::string& s) {
            argv.push_back(const_cast<char*>(s.c_str()));
        };

        push("ffmpeg");
        push("-f"); push("mjpeg");
        push("-i"); push(uuidpath);
        if (audio) {
            push("-f"); push("s32be");
            push("-ac"); push("2");
            push("-ar"); push("44100");
            push("-i"); push("pipe:0");
        }
        push("-f"); push("matroska");
        push("-codec"); push("copy");
        push("pipe:1");
        argv.push_back(nullptr);

        execvp("ffmpeg", argv.data());
        std::fprintf(stderr, "execvp(ffmpeg) failed: %s\n", std::strerror(errno));
        _exit(127);
    }

    // Parent
    close(pipe_out[1]); // close child's stdout write end
    close(pipe_in[0]);  // close child's stdin read end

    // Thread to feed audio queue -> ffmpeg stdin
    std::thread audio_writer([&]() {
        DumpQueueToFD(audioQ, pipe_in[1]);
    });
    audio_writer.detach();

    // Copy ffmpeg stdout to our stdout
    int outfd = pipe_out[0];
    std::vector<uint8_t> buf(1 << 16);
    for (;;) {
        ssize_t n = ::read(outfd, buf.data(), buf.size());
        if (n < 0) {
            std::fprintf(stderr, "unable to read from ffmpeg stdout: %s\n", std::strerror(errno));
            std::exit(1);
        }
        if (n == 0) {
            // EOF
            std::exit(0);
        }
        size_t off = 0;
        while (off < static_cast<size_t>(n)) {
            ssize_t w = ::write(STDOUT_FILENO, buf.data() + off, static_cast<size_t>(n) - off);
            if (w < 0) {
                std::fprintf(stderr, "unable to write to stdout: %s\n", std::strerror(errno));
                std::exit(1);
            }
            off += static_cast<size_t>(w);
        }
    }
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
            // continue; but keep behavior similar to Go (fatal). We'll exit:
            std::exit(1);
        }
        ::close(sockfd);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

struct Options {
    std::string iface = "eth0";
    bool debug = false;
    bool mkv = true;
    bool audio = true;
    bool wakeups = true;
    std::string sender_mac = "000b78006001";
};

static bool parse_bool(const std::string& v) {
    if (v == "1" || v == "true" || v == "True" || v == "TRUE" || v == "yes" || v == "on") return true;
    if (v == "0" || v == "false" || v == "False" || v == "FALSE" || v == "no" || v == "off") return false;
    // fallback: treat anything else as true
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
                "Usage: %s [--interface=eth0] [--debug=0] [--mkv=1] [--audio=1] [--wakeups=1] [--sender-mac=000b78006001]\n",
                argv[0]);
            std::exit(0);
        }
        std::string v;
        if (!(v = getv("--interface")).empty()) o.iface = v;
        else if (!(v = getv("--debug")).empty()) o.debug = parse_bool(v);
        else if (!(v = getv("--mkv")).empty()) o.mkv = parse_bool(v);
        else if (!(v = getv("--audio")).empty()) o.audio = parse_bool(v);
        else if (!(v = getv("--wakeups")).empty()) o.wakeups = parse_bool(v);
        else if (!(v = getv("--sender-mac")).empty()) o.sender_mac = v;
    }
    return o;
}

int main(int argc, char** argv) {
    Options opt = parse_args(argc, argv);

    int videofd = -1;
    std::string pipename = randString(5);
    std::string fifoPath = "/tmp/hdmi-Vfifo-" + pipename;

    BoundedQueue<std::vector<uint8_t>> audiodis(100);
    BoundedQueue<std::vector<uint8_t>> videodis(100);

    if (opt.wakeups) {
        std::thread(BroadcastWakeups, opt.iface, opt.sender_mac).detach();
    }

    if (opt.mkv) {
        // Start ffmpeg wrapper first (as in original Go code).
        std::thread(WrapInMKV, fifoPath, std::ref(audiodis), opt.audio).detach();

        if (::mkfifo(fifoPath.c_str(), 0664) < 0) {
            std::fprintf(stderr, "Could not make a fifo at %s: %s\n", fifoPath.c_str(), std::strerror(errno));
            return 1;
        }
        videofd = ::open(fifoPath.c_str(), O_WRONLY);
        if (videofd < 0) {
            std::fprintf(stderr, "Could not open FIFO %s: %s\n", fifoPath.c_str(), std::strerror(errno));
            return 1;
        }
    } else {
        videofd = STDOUT_FILENO;
    }

    // Start writer thread for video
    std::thread(DumpQueueToFD, std::ref(videodis), videofd).detach();

    const uint8_t MULTICAST_MAC[6] = {0x01, 0x00, 0x5e, 0x02, 0x02, 0x02};

    char errbuf[PCAP_ERRBUF_SIZE]{0};
    pcap_t* handle = pcap_open_live(opt.iface.c_str(), 1500, 1, 500, errbuf);
    if (!handle) {
        std::fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    int droppedframes = 0;
    int desyncframes = 0;
    int totalframes = 0;

    Frame CurrentPacket;
    CurrentPacket.Data.clear();

    // Initial boundary for MJPEG
    {
        const char* hdr = "--myboundary\nContent-Type: image/jpeg\n\n";
        std::vector<uint8_t> v(hdr, hdr + std::strlen(hdr));
        videodis.try_push(std::move(v));
    }

    const int UDP_DPORT_OFFSET = 36; // Ethernet(14)+IPv4(20)=34; UDP dest port at +2 -> 36..37
    const int APP_OFFSET = 42;       // 14+20+8

    const uint8_t AUDIO_DPORT_BE[2] = {0x08, 0x12}; // 2066
    const uint8_t VIDEO_DPORT_BE[2] = {0x08, 0x14}; // 2068

    for (;;) {
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
        if (app_len < 5) continue; // must at least hold 4 bytes of header + 1 payload

        // Audio on port 2066
        if (UDP_DPORT[0] == AUDIO_DPORT_BE[0] && UDP_DPORT[1] == AUDIO_DPORT_BE[1] && opt.mkv && opt.audio) {
            if (app_len > 16) {
                std::vector<uint8_t> audio_blob(ApplicationData + 16, ApplicationData + app_len);
                (void)audiodis.try_push(std::move(audio_blob));
            }
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
                std::fprintf(stderr, "Dropped packet due to non-sane frame number (%d dropped so far)\n", droppedframes);
            }
            continue;
        }

        if (opt.debug) {
            std::fprintf(stderr, "%u/%u - %u/%u - %zu\n",
                         FrameNumber, CurrentChunk, CurrentPacket.FrameID, CurrentPacket.LastChunk, app_len);
        }

        if (CurrentPacket.LastChunk != 0 && CurrentPacket.LastChunk != static_cast<uint16_t>(CurrentChunk - 1)) {
            if (static_cast<uint16_t>(~(CurrentChunk << 15)) != 65534) {
                std::fprintf(stderr,
                    "Dropped packet because of desync detected (%d dropped so far, %d because of desync)\n",
                    droppedframes, desyncframes);
                std::fprintf(stderr, "You see; %u != %u-1\n", CurrentPacket.LastChunk, CurrentChunk);
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
        }

        if (static_cast<uint16_t>(~(CurrentChunk >> 15)) == 65534) {
            // Flush the frame to output
            const char* boundary = "\n--myboundary\nContent-Type: image/jpeg\n\n";
            std::vector<uint8_t> fin;
            fin.reserve(std::strlen(boundary) + CurrentPacket.Data.size());
            fin.insert(fin.end(), boundary, boundary + std::strlen(boundary));
            fin.insert(fin.end(), CurrentPacket.Data.begin(), CurrentPacket.Data.end());
            (void)videodis.try_push(std::move(fin));

            totalframes++;
            if (opt.debug) {
                std::fprintf(stderr, "Size: %zu\n", CurrentPacket.Data.size());
            }

            CurrentPacket = Frame{};
            CurrentPacket.Data.clear();
            CurrentPacket.FrameID = 0;
            CurrentPacket.LastChunk = 0;
        }
    }

    pcap_close(handle);
    return 0;
}
