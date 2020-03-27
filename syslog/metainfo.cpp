#include "syslog/metainfo.hpp"

#include "asn/der.hpp"
#include "system.hpp"

using namespace WarGrey::SCADA;
using namespace WarGrey::GYDM;

using namespace Windows::ApplicationModel;

/*************************************************************************************************/
SyslogMetainfo::SyslogMetainfo() : IASNSequence(3) {
	Platform::String^ pname = Package::Current->DisplayName;

	this->pname = std::wstring(pname->Data(), pname->Length());
	this->pid = system_process_id();
}

SyslogMetainfo::SyslogMetainfo(const uint8* basn, size_t* offset) : SyslogMetainfo() {
	this->from_octets(basn, offset);
}

size_t SyslogMetainfo::field_payload_span(size_t idx) {
	size_t span = 0;

	switch (idx) {
	case 0: span = asn_utf8_span(this->pname); break;
	case 1: span = asn_fixnum_span(this->pid); break;
	case 2: span = asn_fixnum_span(this->timestamp); break;
	}

	return span;
}

size_t SyslogMetainfo::fill_field(size_t idx, uint8* octets, size_t offset) {
	switch (idx) {
	case 0: offset = asn_utf8_into_octets(this->pname, octets, offset); break;
	case 1: offset = asn_fixnum_into_octets(this->pid, octets, offset); break;
	case 2: offset = asn_fixnum_into_octets(this->timestamp, octets, offset); break;
	}

	return offset;
}

void SyslogMetainfo::extract_field(size_t idx, const uint8* basn, size_t* offset) {
	switch (idx) {
	case 0: this->pname = asn_octets_to_utf8(basn, offset); break;
	case 1: this->pid = static_cast<uint32>(asn_octets_to_fixnum(basn, offset)); break;
	case 2: this->timestamp = asn_octets_to_fixnum(basn, offset); break;
	}
}
