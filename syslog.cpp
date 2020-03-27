#include "syslog.hpp"

#include "datum/string.hpp"

using namespace WarGrey::GYDM;

static Platform::String^ default_rsyslog_group = nullptr;
static Platform::String^ default_logging_topic = "WarGrey";
static Log default_logging_level = Log::Debug;

static RacketReceiver* default_rsyslog_receiver() {
	static RacketReceiver* rsyslog;

	if ((rsyslog == nullptr) && (default_rsyslog_group != nullptr)) {
		rsyslog = new RacketReceiver(default_rsyslog_group, 1618, Log::Debug);
		rsyslog->reference();
	}

	return rsyslog;
}

/*************************************************************************************************/
void WarGrey::GYDM::set_default_logging_level(Log level) {
	default_logging_level = level;
}

void WarGrey::GYDM::set_default_logging_topic(Platform::String^ topic) {
	default_logging_topic = topic;
}

void WarGrey::GYDM::set_default_rsyslog_multicast_group(Platform::String^ ipv4) {
	default_rsyslog_group = ipv4;
}

/*************************************************************************************************/
Syslog* WarGrey::GYDM::default_logger() {
	static Syslog* winlog;

	if (winlog == nullptr) {
		RacketReceiver* racket = default_rsyslog_receiver();

		winlog = make_logger(default_logging_level, default_logging_topic, nullptr);
		winlog->push_log_receiver(new VisualStudioReceiver());

		if (racket != nullptr) {
			// winlog->push_log_receiver(racket);
		}

		winlog->reference();
	}

	return winlog;
}

void WarGrey::GYDM::syslog(Log level, Platform::String^ message) {
	auto self = default_logger();

	self->log_message(level, message);
}

void WarGrey::GYDM::syslog(Log level, const wchar_t *fmt, ...) {
	VSWPRINT(message, fmt);

	syslog(level, message);
}

/*************************************************************************************************/
#define implement_syslog(fname, level) \
void syslog_##fname(const wchar_t *fmt, ...) { VSWPRINT(message, fmt); syslog(level, message); } \
void syslog_##fname(Platform::String^ message) { syslog(level, message); }

implement_syslog(debug,    Log::Debug)
implement_syslog(info,     Log::Info)
implement_syslog(notice,   Log::Notice)
implement_syslog(warning,  Log::Warning)
implement_syslog(error,    Log::Error)
implement_syslog(critical, Log::Critical)
implement_syslog(alert,    Log::Alarm)
implement_syslog(panic,    Log::Panic)

#undef implement_syslog

/*************************************************************************************************/
Syslog* WarGrey::GYDM::make_logger(Log level, Platform::String^ topic, Syslog* parent) {
	return new Syslog(level, topic, parent);
}

Syslog* WarGrey::GYDM::make_silent_logger(Platform::String^ topic) {
	return make_logger(Log::_, topic);
}

Syslog* WarGrey::GYDM::make_system_logger(Log level, Platform::String^ topic) {
	return make_logger(level, topic, default_logger());
}

Syslog* WarGrey::GYDM::make_system_logger(Platform::String^ topic) {
	return make_logger(default_logging_level, topic, default_logger());
}
