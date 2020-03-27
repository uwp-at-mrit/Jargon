#pragma once

#include "syslog/logging.hpp"
#include "syslog/metainfo.hpp"
#include "syslog/receiver/racket.hpp"
#include "syslog/receiver/vstudio.hpp"

namespace WarGrey::GYDM {
    void set_default_logging_level(WarGrey::GYDM::Log level = WarGrey::GYDM::Log::Debug);
    void set_default_logging_topic(Platform::String^ topic = "WinSCADA");
    void set_default_rsyslog_multicast_group(Platform::String^ ipv4);

    WarGrey::GYDM::Syslog* default_logger();
    WarGrey::GYDM::Syslog* make_silent_logger(Platform::String^ topic);
    WarGrey::GYDM::Syslog* make_system_logger(Platform::String^ topic);
    WarGrey::GYDM::Syslog* make_system_logger(WarGrey::GYDM::Log level, Platform::String^ topic);
    WarGrey::GYDM::Syslog* make_logger(WarGrey::GYDM::Log level, Platform::String^ topic, WarGrey::GYDM::Syslog* parent = nullptr);

    void syslog(WarGrey::GYDM::Log level, Platform::String^ message);
    void syslog(WarGrey::GYDM::Log level, const wchar_t* fmt, ...);

#define declare_syslog(level) \
    void syslog_##level(const wchar_t *fmt, ...); \
    void syslog_##level(Platform::String^ message);

    declare_syslog(debug)
    declare_syslog(info)
    declare_syslog(notice)
    declare_syslog(warning)
    declare_syslog(error)
    declare_syslog(critical)
    declare_syslog(alert)
    declare_syslog(panic)

#undef declare_syslog
}
