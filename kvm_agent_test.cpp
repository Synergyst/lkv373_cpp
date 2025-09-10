// kvm_agent_test.cpp
// A minimal test agent compatible with the provided KVM-Proxy.
// - Video server: streams concatenated JPEG frames over TCP
// - Control server: speaks line-delimited JSON over TCP
//
// Build:
//   g++ -std=c++17 -O2 -pthread kvm_agent_test.cpp -o kvm-agent-test -ljpeg
//
// Linux deps (Debian/Ubuntu):
//   sudo apt-get update
//   sudo apt-get install -y build-essential libjpeg-turbo8-dev
//
// Run:
//   ./kvm-agent-test
//
// In a separate shell, run KVM-Proxy with env pointing to 127.0.0.1:
//   export TCP_HOST=127.0.0.1
//   export CONTROL_TCP_HOST=127.0.0.1
//   # (optional if you keep defaults) export TCP_PORT=1347 CONTROL_TCP_PORT=1444
//   ./your-kvm-proxy-binary
//
// Open the UI at: http://localhost:34878/
//
// Notes:
// - We fake "remoteSize" (default 1280x720), synthetic JPEG frames, and "shellResult".
// - The test server logs all control messages it receives.

#include <stdio.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <jpeglib.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <atomic>

static std::atomic<bool> g_shutdown{false};

// Helpers
static void set_nonblock(int fd, bool nb) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return;
    if (nb) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    else fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}
static int make_listen_socket(const std::string& bind_ip, int port, bool reuse = true) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    if (reuse) {
        int on = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (::inet_pton(AF_INET, bind_ip.c_str(), &addr.sin_addr) != 1) {
        std::cerr << "Invalid bind IP: " << bind_ip << "\n";
        ::close(fd);
        return -1;
    }
    if (::bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        ::close(fd);
        return -1;
    }
    if (::listen(fd, 16) < 0) {
        perror("listen");
        ::close(fd);
        return -1;
    }
    return fd;
}

static std::string json_line_hello(int w, int h) {
    std::ostringstream oss;
    oss << "{\"type\":\"hello\",\"agent\":\"kvm-agent-test\",\"version\":\"1.0\","
        << "\"remoteSize\":{\"w\":" << w << ",\"h\":" << h << "}}\n";
    return oss.str();
}
static std::string json_line_info_remote_size(int w, int h) {
    std::ostringstream oss;
    // The proxy forwards objects with type:"info" (and also top-level remoteSize)
    oss << "{\"type\":\"info\",\"note\":\"remoteSize set\",\"remoteSize\":{\"w\":" << w << ",\"h\":" << h << "}}\n";
    return oss.str();
}
static std::string json_line_info_note(const std::string& note) {
    std::ostringstream oss;
    oss << "{\"type\":\"info\",\"note\":" << "\"" << note << "\"}\n";
    return oss.str();
}
static std::string json_line_shell_result(const std::string& id, int code,
                                          const std::string& stdout_s,
                                          const std::string& stderr_s) {
    // Warning: The provided proxy code seems not to forward type:"shellResult" to the UI.
    std::ostringstream oss;
    oss << "{\"type\":\"shellResult\",\"id\":\"" << id << "\",\"code\":" << code
        << ",\"stdout\":";
    // naive JSON string escape for brevity
    auto esc = [](const std::string& s) {
        std::string o;
        for (char c : s) {
            if (c == '\\' || c == '"') { o.push_back('\\'); o.push_back(c); }
            else if (c == '\n') o += "\\n";
            else o.push_back(c);
        }
        return o;
    };
    oss << "\"" << esc(stdout_s) << "\",\"stderr\":\"" << esc(stderr_s) << "\"}\n";
    return oss.str();
}

// Simple JPEG encoder using libjpeg
static bool encode_rgb_to_jpeg(const uint8_t* rgb, int w, int h, int quality,
                               std::string& out) {
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

// Generate a simple moving gradient RGB frame
static void make_test_frame_rgb(int w, int h, int tick, std::vector<uint8_t>& buf) {
    buf.resize(static_cast<size_t>(w) * h * 3);
    for (int y = 0; y < h; ++y) {
        for (int x = 0; x < w; ++x) {
            int idx = (y * w + x) * 3;
            uint8_t r = static_cast<uint8_t>((x + tick) & 0xFF);
            uint8_t g = static_cast<uint8_t>((y * 2 + tick) & 0xFF);
            uint8_t b = static_cast<uint8_t>(((x + y) / 2 + tick) & 0xFF);
            buf[idx + 0] = r;
            buf[idx + 1] = g;
            buf[idx + 2] = b;
        }
    }
}

struct VideoServerConfig {
    std::string bind_ip{"127.0.0.1"};
    int port{1347};
    int width{800};
    int height{450};
    int fps{10};
    int quality{80};
};

static void video_client_thread(int cfd, VideoServerConfig cfg) {
    std::cout << "[video] client connected\n";
    std::vector<uint8_t> rgb;
    std::string jpeg;
    const auto frame_interval = std::chrono::milliseconds(1000 / std::max(1, cfg.fps));
    int tick = 0;

    while (!g_shutdown.load()) {
        make_test_frame_rgb(cfg.width, cfg.height, tick++, rgb);
        if (!encode_rgb_to_jpeg(rgb.data(), cfg.width, cfg.height, cfg.quality, jpeg)) {
            std::cerr << "[video] JPEG encode failed\n";
            break;
        }
        ssize_t off = 0;
        const char* data = jpeg.data();
        ssize_t len = static_cast<ssize_t>(jpeg.size());
        while (off < len) {
            ssize_t n = ::send(cfd, data + off, static_cast<size_t>(len - off), 0);
            if (n <= 0) {
                if (errno == EINTR) continue;
                std::cerr << "[video] send failed/closed\n";
                ::close(cfd);
                return;
            }
            off += n;
        }
        std::this_thread::sleep_for(frame_interval);
    }

    ::close(cfd);
    std::cout << "[video] client disconnected\n";
}

static void run_video_server(VideoServerConfig cfg) {
    int lfd = make_listen_socket(cfg.bind_ip, cfg.port);
    if (lfd < 0) {
        std::cerr << "[video] failed to listen on " << cfg.bind_ip << ":" << cfg.port << "\n";
        return;
    }
    fprintf(stderr, "[video] listening on %s:%d (%dx%d @ %d FPS, q=%d)\n", cfg.bind_ip.c_str(), cfg.port, cfg.width, cfg.height, cfg.fps, cfg.quality);
    while (!g_shutdown.load()) {
        sockaddr_in cli{};
        socklen_t slen = sizeof(cli);
        int cfd = ::accept(lfd, (sockaddr*)&cli, &slen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            perror("[video] accept");
            break;
        }
        std::thread(video_client_thread, cfd, cfg).detach();
    }
    ::close(lfd);
}

// Control server
struct ControlServerConfig {
    std::string bind_ip{"127.0.0.1"};
    int port{1444};
    int remote_w{1280};
    int remote_h{720};
    bool send_heartbeat{true};
    int heartbeat_sec{5};
    bool reply_shell{true};
};

static bool send_all(int fd, const std::string& s) {
    ssize_t off = 0;
    ssize_t len = static_cast<ssize_t>(s.size());
    while (off < len) {
        ssize_t n = ::send(fd, s.data() + off, static_cast<size_t>(len - off), 0);
        if (n <= 0) {
            if (errno == EINTR) continue;
            return false;
        }
        off += n;
    }
    return true;
}

static void control_client_thread(int cfd, ControlServerConfig cfg) {
    std::cout << "[ctrl] client connected\n";

    // Send hello/info and current remote size
    if (!send_all(cfd, json_line_hello(cfg.remote_w, cfg.remote_h))) {
        ::close(cfd);
        std::cout << "[ctrl] connection closed during hello\n";
        return;
    }
    if (!send_all(cfd, json_line_info_remote_size(cfg.remote_w, cfg.remote_h))) {
        ::close(cfd);
        std::cout << "[ctrl] connection closed during remoteSize info\n";
        return;
    }

    std::string inbuf;
    inbuf.reserve(4096);
    auto last_heartbeat = std::chrono::steady_clock::now();

    while (!g_shutdown.load()) {
        // Heartbeat info
        if (cfg.send_heartbeat) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_heartbeat).count() >= cfg.heartbeat_sec) {
                last_heartbeat = now;
                std::ostringstream msg;
                msg << "heartbeat @" << std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
                if (!send_all(cfd, json_line_info_note(msg.str()))) {
                    break;
                }
            }
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(cfd, &rfds);
        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200 * 1000;  // 200ms

        int rv = ::select(cfd + 1, &rfds, nullptr, nullptr, &tv);
        if (rv < 0) {
            if (errno == EINTR) continue;
            perror("[ctrl] select");
            break;
        }
        if (rv == 0) {
            continue; // timeout
        }
        if (!FD_ISSET(cfd, &rfds)) {
            continue;
        }
        char buf[4096];
        ssize_t n = ::recv(cfd, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            std::cout << "[ctrl] closed by peer\n";
            break;
        }
        inbuf.append(buf, buf + n);

        // Process complete lines
        size_t pos = 0;
        for (;;) {
            size_t eol = inbuf.find('\n', pos);
            if (eol == std::string::npos) {
                if (pos > 0) inbuf.erase(0, pos);
                break;
            }
            std::string line = inbuf.substr(pos, eol - pos);
            pos = eol + 1;
            if (line.empty()) continue;

            // Very minimal "parsing": we peek for keys; we don't depend on exact JSON library here.
            // Log the line:
            std::cout << "[ctrl<-proxy] " << line << "\n";

            // Reply to query for remote size
            if (line.find("\"type\"") != std::string::npos &&
                line.find("\"query\"") != std::string::npos &&
                line.find("\"what\"") != std::string::npos &&
                line.find("remoteSize") != std::string::npos) {
                if (!send_all(cfd, json_line_info_remote_size(cfg.remote_w, cfg.remote_h))) {
                    std::cout << "[ctrl] send failed for remoteSize reply\n";
                    break;
                }
                continue;
            }

            // Synthetic shell handling (if enabled)
            if (cfg.reply_shell &&
                line.find("\"type\"") != std::string::npos &&
                line.find("\"shell\"") != std::string::npos) {
                // Try to extract "id":"..."
                std::string id = "x";
                auto idpos = line.find("\"id\"");
                if (idpos != std::string::npos) {
                    auto q1 = line.find('"', idpos + 4);
                    if (q1 != std::string::npos) {
                        auto q2 = line.find('"', q1 + 1);
                        if (q2 != std::string::npos && q2 > q1 + 1) {
                            id = line.substr(q1 + 1, q2 - (q1 + 1));
                        }
                    }
                }
                auto resp = json_line_shell_result(id, 0, "ok: synthetic echo", "");
                if (!send_all(cfd, resp)) {
                    std::cout << "[ctrl] send failed for shellResult\n";
                    break;
                }
                continue;
            }

            // Optional: Some actions can produce info toasts
            if (line.find("\"type\"") != std::string::npos &&
                (line.find("\"system\"") != std::string::npos ||
                 line.find("\"text\"") != std::string::npos ||
                 line.find("\"killagent\"") != std::string::npos)) {
                std::string note = "ack: " + line.substr(0, std::min<size_t>(line.size(), 120));
                if (!send_all(cfd, json_line_info_note(note))) {
                    std::cout << "[ctrl] send failed for ack note\n";
                    break;
                }
            }
        }
    }

    ::close(cfd);
    std::cout << "[ctrl] client disconnected\n";
}

static void run_control_server(ControlServerConfig cfg) {
    int lfd = make_listen_socket(cfg.bind_ip, cfg.port);
    if (lfd < 0) {
        std::cerr << "[ctrl] failed to listen on " << cfg.bind_ip << ":" << cfg.port << "\n";
        return;
    }
    fprintf(stderr, "[ctrl] listening on %s:%d (%dx%d)\n", cfg.bind_ip.c_str(), cfg.port, cfg.remote_w, cfg.remote_h);

    while (!g_shutdown.load()) {
        sockaddr_in cli{};
        socklen_t slen = sizeof(cli);
        int cfd = ::accept(lfd, (sockaddr*)&cli, &slen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            perror("[ctrl] accept");
            break;
        }
        std::thread(control_client_thread, cfd, cfg).detach();
    }

    ::close(lfd);
}

// Simple CLI parsing
static std::optional<int> parse_int(const char* s) {
    if (!s) return std::nullopt;
    char* end = nullptr;
    long v = std::strtol(s, &end, 10);
    if (!end || *end != '\0') return std::nullopt;
    return static_cast<int>(v);
}

int main(int argc, char** argv) {
    // Defaults chosen to match KVM-Proxy defaults if you set TCP_HOST/CONTROL_TCP_HOST=127.0.0.1
    VideoServerConfig vcfg;
    ControlServerConfig ccfg;

    // Optional args:
    // --bind 127.0.0.1
    // --video-port 1347
    // --control-port 1444
    // --w 800 --h 450 --fps 10
    // --remote-w 1280 --remote-h 720
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](int& out) {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << a << "\n";
                std::exit(2);
            }
            auto v = parse_int(argv[i + 1]);
            if (!v) {
                std::cerr << "Invalid integer for " << a << "\n";
                std::exit(2);
            }
            out = *v;
            ++i;
        };
        if (a == "--bind") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --bind\n"; return 2; }
            vcfg.bind_ip = argv[++i];
            ccfg.bind_ip = vcfg.bind_ip;
        } else if (a == "--video-port") {
            need(vcfg.port);
        } else if (a == "--control-port") {
            need(ccfg.port);
        } else if (a == "--w") {
            need(vcfg.width);
        } else if (a == "--h") {
            need(vcfg.height);
        } else if (a == "--fps") {
            need(vcfg.fps);
        } else if (a == "--quality") {
            need(vcfg.quality);
        } else if (a == "--remote-w") {
            need(ccfg.remote_w);
        } else if (a == "--remote-h") {
            need(ccfg.remote_h);
        } else if (a == "--no-heartbeat") {
            ccfg.send_heartbeat = false;
        } else if (a == "--heartbeat-sec") {
            need(ccfg.heartbeat_sec);
        } else if (a == "--no-shell-reply") {
            ccfg.reply_shell = false;
        } else if (a == "--help" || a == "-h") {
            std::cout <<
                "Usage: " << argv[0] << " [options]\n"
                "  --bind IP              Bind IP (default 127.0.0.1)\n"
                "  --video-port N         Video TCP port (default 1347)\n"
                "  --control-port N       Control TCP port (default 1444)\n"
                "  --w N --h N            Video frame size (default 800x450)\n"
                "  --fps N                Video FPS (default 10)\n"
                "  --quality N            JPEG quality 1..100 (default 80)\n"
                "  --remote-w N --remote-h N  Reported remote size (default 1280x720)\n"
                "  --heartbeat-sec N      Send info heartbeat every N sec (default 5)\n"
                "  --no-heartbeat         Disable heartbeat messages\n"
                "  --no-shell-reply       Do not send shellResult responses\n";
            return 0;
        } else {
            std::cerr << "Unknown option: " << a << " (use --help)\n";
            return 2;
        }
    }

    // Ctrl-C handling
    ::signal(SIGINT, [](int) {
        g_shutdown.store(true);
    });
    ::signal(SIGTERM, [](int) {
        g_shutdown.store(true);
    });

    std::thread tv([&]{ run_video_server(vcfg); });
    std::thread tc([&]{ run_control_server(ccfg); });

    tv.join();
    tc.join();

    return 0;
}
