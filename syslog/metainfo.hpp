#pragma once

#include "datum/object.hpp"

#include "asn/der/sequence.hpp"

namespace WarGrey::GYDM {
	private class SyslogMetainfo : public WarGrey::GYDM::IASNSequence, public WarGrey::SCADA::SharedObject {
	public:
		SyslogMetainfo();
		SyslogMetainfo(const uint8* basn, size_t* offset = nullptr);

	public:
		std::wstring pname;
		unsigned int pid;
		long long timestamp;

	private:
		~SyslogMetainfo() noexcept {}

	protected:
		size_t field_payload_span(size_t idx) override;
		size_t fill_field(size_t idx, uint8* octets, size_t offset) override;
		void extract_field(size_t idx, const uint8* basn, size_t* offset) override;
	};
}
