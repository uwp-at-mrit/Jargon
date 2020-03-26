#pragma once

#include "syslog/logging.hpp"

namespace WarGrey::GYDM {
	private class RacketReceiver : public WarGrey::GYDM::ISyslogReceiver {
	public:
		RacketReceiver(Platform::String^ multicast_group, unsigned short service,
			WarGrey::GYDM::Log level = WarGrey::GYDM::Log::Debug,
			Platform::String^ topic = "");

	protected:
		void on_log_message(WarGrey::GYDM::Log level, Platform::String^ message,
			WarGrey::GYDM::SyslogMetainfo& data, Platform::String^ topic) override;

	protected:
		~RacketReceiver() noexcept;

	private:
		class Message;
		WarGrey::GYDM::RacketReceiver::Message* record;
	};
}
