#include "syslog/receiver/racket.hpp"

#include "peer/slang.hpp"

#include "asn/der.hpp"
#include "datum/string.hpp"

using namespace WarGrey::SCADA;
using namespace WarGrey::GYDM;

/*************************************************************************************************/
class WarGrey::GYDM::RacketReceiver::Message : public IASNSequence {
public:
	virtual ~Message() noexcept {
		if (this->rsyslog != nullptr) {
			delete this->rsyslog;
		}
	}

	Message(SlangDaemon<uint8>* rsyslog) : IASNSequence(3), rsyslog(rsyslog) {}
	Message(SlangDaemon<uint8>* rsyslog, const uint8* basn, size_t* offset = nullptr) : Message(rsyslog) {
		this->from_octets(basn, offset);
	}

public:
	void multicast(Log level, Platform::String^ message, SyslogMetainfo& data, Platform::String^ topic) {
		this->level = level;
		this->message = message;
		this->topic = topic;

		this->rsyslog->multicast(this, 0);
	}

protected:
	size_t field_payload_span(size_t idx) override {
		size_t span = 0;

		switch (idx) {
		case 0: span = asn_log_span(this->level); break;
		case 1: span = asn_utf8_span(this->message); break;
		case 2: span = asn_utf8_span(this->topic); break;
		}

		return span;
	}

	size_t fill_field(size_t idx, uint8* octets, size_t offset) {
		switch (idx) {
		case 0: offset = asn_log_into_octets(this->level, octets, offset); break;
		case 1: offset = asn_utf8_into_octets(this->message, octets, offset); break;
		case 2: offset = asn_utf8_into_octets(this->topic, octets, offset); break;
		}

		return offset;
	}

	void extract_field(size_t idx, const uint8* basn, size_t* offset) {
		switch (idx) {
		case 0: this->level = asn_octets_to_log(basn, offset); break;
		case 1: this->message = make_wstring(asn_octets_to_utf8(basn, offset)); break;
		case 2: this->message = make_wstring(asn_octets_to_utf8(basn, offset)); break;
		}
	}

private:
	Log level;
	Platform::String^ message;
	Platform::String^ topic;

private:
	SlangDaemon<uint8>* rsyslog;
};

/*************************************************************************************************/
RacketReceiver::RacketReceiver(Platform::String^ multicast_group, unsigned short service, Log level, Platform::String^ topic) : ISyslogReceiver(level, topic) {
	auto rsyslog = new SlangDaemon<uint8>(nullptr, service, 1024U);
	
	rsyslog->set_target_multicast_group(multicast_group);
	rsyslog->bind_multicast_service();

	this->record = new RacketReceiver::Message(rsyslog);
}

RacketReceiver::~RacketReceiver() {
	if (this->record != nullptr) {
		delete this->record;
	}
}

void RacketReceiver::on_log_message(Log level, Platform::String^ message, SyslogMetainfo& data, Platform::String^ topic) {
	this->record->multicast(level, message, data, topic);
}
