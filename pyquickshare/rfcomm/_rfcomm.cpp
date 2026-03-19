#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

extern "C" {
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
}

#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <system_error>

namespace py = pybind11;

static void throw_errno(const char *what) {
    throw std::system_error(errno, std::generic_category(), what);
}

static uuid_t parse_uuid(const std::string &s) {
    uuid_t u;
    std::string t = s;

    if (t.size() >= 2 && (t.substr(0, 2) == "0x" || t.substr(0, 2) == "0X"))
        t = t.substr(2);

    if (t.find('-') == std::string::npos) {
        if (t.size() > 8)
            throw std::invalid_argument("invalid UUID (too many hex digits): " + s);
        uint32_t val = std::stoul(t, nullptr, 16);
        if (val <= 0xFFFF)
            sdp_uuid16_create(&u, static_cast<uint16_t>(val));
        else
            sdp_uuid32_create(&u, val);
        return u;
    }

    std::string hex;
    for (char c : s)
        if (c != '-') hex += c;
    if (hex.size() != 32)
        throw std::invalid_argument("invalid UUID (bad length): " + s);
    uint8_t bytes[16];
    for (int i = 0; i < 16; i++)
        bytes[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    sdp_uuid128_create(&u, bytes);
    return u;
}

PYBIND11_MODULE(_rfcomm, m) {
    m.doc() = "pybind11 bindings for the BlueZ RFCOMM C API";

    py::class_<bdaddr_t>(m, "bdaddr_t")
        .def(py::init([]() {
            bdaddr_t addr;
            memset(&addr, 0, sizeof(addr));
            return addr;
        }))
        .def_property(
            "b",
            [](const bdaddr_t &self) {
                return py::bytes(reinterpret_cast<const char *>(self.b), 6);
            },
            [](bdaddr_t &self, py::bytes val) {
                auto s = static_cast<std::string>(val);
                if (s.size() != 6)
                    throw std::invalid_argument("bdaddr_t.b must be exactly 6 bytes");
                memcpy(self.b, s.data(), 6);
            })
        .def("__repr__", [](const bdaddr_t &self) {
            char str[18];
            ba2str(&self, str);
            return std::string("bdaddr_t('") + str + "')";
        })
        .def("__eq__", [](const bdaddr_t &a, const bdaddr_t &b) {
            return bacmp(&a, &b) == 0;
        })
        .def("__ne__", [](const bdaddr_t &a, const bdaddr_t &b) {
            return bacmp(&a, &b) != 0;
        });

    py::class_<sockaddr_rc>(m, "sockaddr_rc")
        .def(py::init([]() {
            sockaddr_rc addr;
            memset(&addr, 0, sizeof(addr));
            addr.rc_family = AF_BLUETOOTH;
            return addr;
        }))
        .def_readwrite("rc_family",  &sockaddr_rc::rc_family)
        .def_readwrite("rc_bdaddr",  &sockaddr_rc::rc_bdaddr)
        .def_readwrite("rc_channel", &sockaddr_rc::rc_channel);


    py::class_<bt_security>(m, "bt_security")
        .def(py::init([]() {
            bt_security sec;
            sec.level    = BT_SECURITY_LOW;
            sec.key_size = 0;
            return sec;
        }))
        .def(py::init([](uint8_t level, uint8_t key_size) {
            bt_security sec;
            sec.level    = level;
            sec.key_size = key_size;    
            return sec;
        }), py::arg("level"), py::arg("key_size") = uint8_t(0))
        .def_readwrite("level",    &bt_security::level)
        .def_readwrite("key_size", &bt_security::key_size)
        .def("pack", [](const bt_security &self) {
            return py::bytes(reinterpret_cast<const char *>(&self), sizeof(self));
        });


    py::class_<rfcomm_conninfo>(m, "rfcomm_conninfo")
        .def(py::init([]() {
            rfcomm_conninfo info;
            memset(&info, 0, sizeof(info));
            return info;
        }))
        .def_readwrite("hci_handle", &rfcomm_conninfo::hci_handle)
        .def_property(
            "dev_class",
            [](const rfcomm_conninfo &self) {
                return py::bytes(reinterpret_cast<const char *>(self.dev_class), 3);
            },
            [](rfcomm_conninfo &self, py::bytes val) {
                auto s = static_cast<std::string>(val);
                if (s.size() != 3)
                    throw std::invalid_argument("dev_class must be exactly 3 bytes");
                memcpy(self.dev_class, s.data(), 3);
            })
        .def_static("unpack", [](py::bytes raw) {
            auto s = static_cast<std::string>(raw);
            if (s.size() < sizeof(rfcomm_conninfo))
                throw std::invalid_argument("buffer too small for rfcomm_conninfo");
            rfcomm_conninfo info;
            memcpy(&info, s.data(), sizeof(info));
            return info;
        }, py::arg("raw"));

    m.def("str2ba", [](const std::string &str) {
        bdaddr_t ba;
        if (::str2ba(str.c_str(), &ba) != 0)
            throw std::invalid_argument("invalid BD address: " + str);
        return ba;
    }, py::arg("str"), "Parse a colon-separated BD address string into a bdaddr_t.");

    m.def("ba2str", [](const bdaddr_t &ba) {
        char str[18];
        if (::ba2str(&ba, str) < 0)
            throw std::runtime_error("ba2str failed");
        return std::string(str);
    }, py::arg("ba"), "Format a bdaddr_t as a colon-separated address string.");

    m.def("bacpy", [](bdaddr_t &dst, const bdaddr_t &src) {
        ::bacpy(&dst, &src);
    }, py::arg("dst"), py::arg("src"), "Copy src into dst (in-place mutation of dst).");

    m.def("bacmp", [](const bdaddr_t &ba1, const bdaddr_t &ba2) {
        return ::bacmp(&ba1, &ba2);
    }, py::arg("ba1"), py::arg("ba2"), "Compare two bdaddr_t values; 0 if equal.");

    m.def("make_rfcomm_socket", []() {
        int fd = ::socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
        if (fd < 0)
            throw_errno("socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)");
        return fd;
    }, "Create an RFCOMM socket; returns a raw file descriptor.\n"
       "Wrap with socket.socket(fileno=fd) for asyncio use.");

    m.def("connect_rfcomm", [](int fd, const std::string &bdaddr_str, uint8_t channel) {
        sockaddr_rc addr;
        memset(&addr, 0, sizeof(addr));
        addr.rc_family  = AF_BLUETOOTH;
        addr.rc_channel = channel;
        if (::str2ba(bdaddr_str.c_str(), &addr.rc_bdaddr) != 0)
            throw std::invalid_argument("invalid BD address: " + bdaddr_str);
        if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
            throw_errno("connect_rfcomm");
    }, py::arg("fd"), py::arg("bdaddr_str"), py::arg("channel"),
       "Connect an RFCOMM socket fd to the given BD address and channel.");

    m.def("bind_rfcomm", [](int fd, const std::string &bdaddr_str, uint8_t channel) {
        sockaddr_rc addr;
        memset(&addr, 0, sizeof(addr));
        addr.rc_family  = AF_BLUETOOTH;
        addr.rc_channel = channel;
        if (::str2ba(bdaddr_str.c_str(), &addr.rc_bdaddr) != 0)
            throw std::invalid_argument("invalid BD address: " + bdaddr_str);
        if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
            throw_errno("bind_rfcomm");
    }, py::arg("fd"), py::arg("bdaddr_str"), py::arg("channel"),
       "Bind an RFCOMM socket fd to a local adapter address and channel.");

    m.def("setsockopt_bytes",
        [](int fd, int level, int optname, py::bytes data) {
            auto s = static_cast<std::string>(data);
            if (::setsockopt(fd, level, optname, s.data(),
                             static_cast<socklen_t>(s.size())) < 0)
                throw_errno("setsockopt");
        }, py::arg("fd"), py::arg("level"), py::arg("optname"), py::arg("data"),
        "setsockopt wrapper that accepts raw bytes (e.g. bt_security.pack()).");

    m.def("getsockopt_bytes",
        [](int fd, int level, int optname, socklen_t buflen) -> py::bytes {
            std::string buf(buflen, '\0');
            socklen_t len = buflen;
            if (::getsockopt(fd, level, optname, buf.data(), &len) < 0)
                throw_errno("getsockopt");
            buf.resize(len);
            return py::bytes(buf);
        }, py::arg("fd"), py::arg("level"), py::arg("optname"), py::arg("buflen"),
        "getsockopt wrapper that returns raw bytes (pass to rfcomm_conninfo.unpack()).");


    m.def("find_rfcomm_channel",
        [](const std::string &remote_str, const std::string &uuid_str) -> int {
            bdaddr_t remote;
            if (::str2ba(remote_str.c_str(), &remote) != 0)
                throw std::invalid_argument("invalid BD address: " + remote_str);

            uuid_t svc_uuid = parse_uuid(uuid_str);

            bdaddr_t src = {};
            sdp_session_t *session = sdp_connect(&src, &remote, SDP_RETRY_IF_BUSY);
            if (!session)
                throw_errno("sdp_connect");

            sdp_list_t *search  = sdp_list_append(nullptr, &svc_uuid);
            uint32_t    range   = 0x0000FFFF;
            sdp_list_t *attrid  = sdp_list_append(nullptr, &range);
            sdp_list_t *records = nullptr;

            int ret = sdp_service_search_attr_req(
                session, search, SDP_ATTR_REQ_RANGE, attrid, &records);
            sdp_list_free(search, nullptr);
            sdp_list_free(attrid, nullptr);
            sdp_close(session);

            if (ret != 0)
                throw_errno("sdp_service_search_attr_req");
            if (!records)
                throw std::runtime_error("service not found via SDP");

            int channel = -1;
            for (sdp_list_t *r = records; r && channel < 0; r = r->next) {
                sdp_record_t *rec    = static_cast<sdp_record_t *>(r->data);
                sdp_list_t   *protos = nullptr;
                if (sdp_get_access_protos(rec, &protos) == 0) {
                    channel = sdp_get_proto_port(protos, RFCOMM_UUID);
                    sdp_list_foreach(protos,
                        reinterpret_cast<sdp_list_func_t>(sdp_list_free), nullptr);
                    sdp_list_free(protos, nullptr);
                }
                sdp_record_free(rec);
            }
            sdp_list_free(records, nullptr);

            if (channel < 0)
                throw std::runtime_error("RFCOMM channel not found in SDP records");
            return channel;
        },
        py::arg("remote_bdaddr"), py::arg("uuid"),
        "Query a remote device's SDP server for the RFCOMM channel of a service.\n"
        "\n"
        "Args:\n"
        "    remote_bdaddr: BD address string, e.g. \"18:F0:E4:3C:07:8B\"\n"
        "    uuid: service UUID — short form (\"1101\", \"0x1101\") or full\n"
        "          128-bit form (\"00001101-0000-1000-8000-00805f9b34fb\")\n"
        "\n"
        "Returns the RFCOMM channel number (int).\n"
        "Raises OSError if the SDP connection fails, RuntimeError if not found.\n"
        "This call blocks until the SDP query completes.");

    m.attr("AF_BLUETOOTH")   = int(AF_BLUETOOTH);
    m.attr("PF_BLUETOOTH")   = int(PF_BLUETOOTH);
    m.attr("BTPROTO_RFCOMM") = int(BTPROTO_RFCOMM);
    m.attr("SOCK_STREAM")    = int(SOCK_STREAM);
    m.attr("SOCK_SEQPACKET") = int(SOCK_SEQPACKET);

    m.attr("SOL_BLUETOOTH")  = int(SOL_BLUETOOTH);
    m.attr("SOL_RFCOMM")     = int(SOL_RFCOMM);

    m.attr("BT_SECURITY")        = int(BT_SECURITY);
    m.attr("BT_SECURITY_SDP")    = int(BT_SECURITY_SDP);
    m.attr("BT_SECURITY_LOW")    = int(BT_SECURITY_LOW);
    m.attr("BT_SECURITY_MEDIUM") = int(BT_SECURITY_MEDIUM);
    m.attr("BT_SECURITY_HIGH")   = int(BT_SECURITY_HIGH);
    m.attr("BT_SECURITY_FIPS")   = int(BT_SECURITY_FIPS);

    m.attr("RFCOMM_CONNINFO")      = int(RFCOMM_CONNINFO);
    m.attr("RFCOMM_LM")            = int(RFCOMM_LM);
    m.attr("RFCOMM_LM_MASTER")     = int(RFCOMM_LM_MASTER);
    m.attr("RFCOMM_LM_AUTH")       = int(RFCOMM_LM_AUTH);
    m.attr("RFCOMM_LM_ENCRYPT")    = int(RFCOMM_LM_ENCRYPT);
    m.attr("RFCOMM_LM_TRUSTED")    = int(RFCOMM_LM_TRUSTED);
    m.attr("RFCOMM_LM_RELIABLE")   = int(RFCOMM_LM_RELIABLE);
    m.attr("RFCOMM_LM_SECURE")     = int(RFCOMM_LM_SECURE);

    m.attr("RFCOMM_DEFAULT_MTU") = int(RFCOMM_DEFAULT_MTU);
    m.attr("RFCOMM_PSM")         = int(RFCOMM_PSM);

    m.attr("SHUT_RD")   = int(SHUT_RD);
    m.attr("SHUT_WR")   = int(SHUT_WR);
    m.attr("SHUT_RDWR") = int(SHUT_RDWR);
}
