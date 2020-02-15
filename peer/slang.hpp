#pragma once

#include <list>

#include "network/udp.hpp"
#include "datum/enum.hpp"
#include "asn/der.hpp"

#include "syslog.hpp"

namespace WarGrey::GYDM {
	Windows::Foundation::IAsyncOperation<uint32>^ slang_cast(uint16 peer_port, uint8 type, Platform::Array<uint8>^ payload,
		uint16 response_port = 0U, uint16 transaction = 0U);
	Windows::Foundation::IAsyncOperation<uint32>^ slang_cast(Platform::String^ peer, uint16 peer_port, uint8 type, Platform::Array<uint8>^ payload,
		uint16 response_port = 0U, uint16 transaction = 0U);

	Windows::Foundation::IAsyncOperation<uint32>^ slang_cast(uint16 peer_port, uint8 type, const uint8* payload, size_t size,
		uint16 response_port = 0U, uint16 transaction = 0U);
	Windows::Foundation::IAsyncOperation<uint32>^ slang_cast(Platform::String^ peer, uint16 peer_port, uint8 type, const uint8* payload, size_t size,
		uint16 response_port = 0U, uint16 transaction = 0U);

	/**********************************************************************************************/
	private class ISlangLocalPeer abstract {
	public:
		virtual bool absent() { return false; }

	public:
		virtual void pre_read_message(WarGrey::SCADA::Syslog* logger) = 0;
		virtual void post_read_message(WarGrey::SCADA::Syslog* logger) = 0;
	};

	private class ISlangDaemon abstract : public WarGrey::GYDM::IUDPStatedDaemon {
    public:
        virtual ~ISlangDaemon() noexcept;
		ISlangDaemon(WarGrey::SCADA::Syslog* logger, uint16 service, WarGrey::GYDM::ISlangLocalPeer* confirmation = nullptr);
		ISlangDaemon(WarGrey::SCADA::Syslog* logger, uint16 service, size_t recv_size, WarGrey::GYDM::ISlangLocalPeer* confirmation = nullptr);

	public:
		WarGrey::SCADA::Syslog* get_logger() override;
		Platform::String^ daemon_hostname() override;
		Platform::String^ daemon_description() override;
		
	public:
		void push_slang_peer(WarGrey::GYDM::ISlangLocalPeer* confirmation);

	protected:
		virtual void apply_message(long long timepoint_ms, WarGrey::GYDM::ISlangLocalPeer* peer,
			Platform::String^ remote_peer, uint16 port, uint8 type, const uint8* message) = 0;
		
	private:
		void bind();
		void clear_if_peer_broken();
		void on_message(long long timepoint_ms, Platform::String^ remote_peer, uint16 port, uint8 type, const uint8* message);
		void on_message(long long timepoint_ms, Platform::String^ remote_peer, uint16 port, uint16 transaction, uint16 response_port, uint8 type, const uint8* message);

	protected:
		std::list<WarGrey::GYDM::ISlangLocalPeer*> local_peers;
		WarGrey::GYDM::ISlangLocalPeer* current_peer;
		WarGrey::SCADA::Syslog* logger;

    private:
		Windows::Networking::Sockets::DatagramSocket^ socket;
		Platform::Object^ ghostcat;
		Platform::String^ service;

	private:
		ref class GhostDaemon; // delegate only accepts C++/CX class
    };

	/**********************************************************************************************/
	template<typename E>
	private class SlangLocalPeer : public WarGrey::GYDM::ISlangLocalPeer {
	public:
		void pre_read_message(WarGrey::SCADA::Syslog* logger) override {}
		void post_read_message(WarGrey::SCADA::Syslog* logger) override {}

	public:
		virtual void on_message(long long timepoint_ms,
			Platform::String^ remote_peer, uint16 port, E type, const uint8* message,
			WarGrey::SCADA::Syslog* logger) = 0;
	};

	template<typename E>
	private class SlangDaemon : public WarGrey::GYDM::ISlangDaemon {
	public:
		SlangDaemon(WarGrey::SCADA::Syslog* logger, uint16 port, ISlangLocalPeer* confirmation = nullptr)
			: ISlangDaemon(logger, port, confirmation) {}

		SlangDaemon(WarGrey::SCADA::Syslog* logger, uint16 port, size_t recv_size, ISlangLocalPeer* confirmation = nullptr)
			: ISlangDaemon(logger, port, recv_size, confirmation) {}

	protected:
		void apply_message(long long timepoint_ms, WarGrey::GYDM::ISlangLocalPeer* local_peer
			, Platform::String^ remote_peer, uint16 port, uint8 type, const uint8* message) override {
			auto peer = static_cast<WarGrey::GYDM::SlangLocalPeer<E>*>(local_peer);

			if (peer != nullptr) {
				peer->on_message(timepoint_ms, remote_peer, port, _E(E, type), message, this->get_logger());
			}
		};
	};
}
