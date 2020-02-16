#pragma once

#include <list>

#include "network/udp.hpp"
#include "asn/der.hpp"

#include "datum/enum.hpp"

#include "syslog.hpp"

namespace WarGrey::GYDM {
	typedef std::function<void(Platform::String^, uint16, unsigned int, double, Platform::String^ exn_msg)> slang_cast_task_then_t;

	void slang_cast_log_message(Platform::String^ host, uint16 port, unsigned int size, double span_ms, Platform::String^ exn_msg);

	void slang_cast(uint16 peer_port, Platform::Array<uint8>^ payload,
		uint8 type = 0U, uint16 response_port = 0U, uint16 transaction = 0U, WarGrey::GYDM::slang_cast_task_then_t fthen = slang_cast_log_message);
	void slang_cast(Platform::String^ peer, uint16 peer_port, Platform::Array<uint8>^ payload,
		uint8 type = 0U, uint16 response_port = 0U, uint16 transaction = 0U, WarGrey::GYDM::slang_cast_task_then_t fthen = slang_cast_log_message);

	void slang_cast(uint16 peer_port, const WarGrey::GYDM::octets& payload,
		uint8 type = 0U, uint16 response_port = 0U, uint16 transaction = 0U, WarGrey::GYDM::slang_cast_task_then_t fthen = slang_cast_log_message);
	void slang_cast(Platform::String^ peer, uint16 peer_port, const WarGrey::GYDM::octets& payload,
		uint8 type = 0U, uint16 response_port = 0U, uint16 transaction = 0U, WarGrey::GYDM::slang_cast_task_then_t fthen = slang_cast_log_message);

	void slang_cast(uint16 peer_port,  WarGrey::GYDM::IASNSequence* payload,
		uint8 type = 0U, uint16 response_port = 0U, uint16 transaction = 0U, WarGrey::GYDM::slang_cast_task_then_t fthen = slang_cast_log_message);
	void slang_cast(Platform::String^ peer, uint16 peer_port, WarGrey::GYDM::IASNSequence* payload,
		uint8 type = 0U, uint16 response_port = 0U, uint16 transaction = 0U, WarGrey::GYDM::slang_cast_task_then_t fthen = slang_cast_log_message);

	template<typename E>
	void slang_cast(uint16 peer_port, Platform::Array<uint8>^ payload
		, E type, uint16 response_port = 0U, uint16 transaction = 0U, WarGrey::GYDM::slang_cast_task_then_t fthen = slang_cast_log_message) {
		return WarGrey::GYDM::slang_cast(peer_port, payload, _I(type), response_port, transaction, fthen);
	}

	template<typename E>
	void slang_cast(Platform::String^ peer, uint16 peer_port, Platform::Array<uint8>^ payload
		, E type, uint16 response_port = 0U, uint16 transaction = 0U, WarGrey::GYDM::slang_cast_task_then_t fthen = slang_cast_log_message) {
		return WarGrey::GYDM::slang_cast(peer, peer_port, payload, _C(type), response_port, transaction, fthen);
	}

	template<typename E>
	void slang_cast(uint16 peer_port, const uint8* payload, size_t size
		, E type, uint16 response_port = 0U, uint16 transaction = 0U, WarGrey::GYDM::slang_cast_task_then_t fthen = slang_cast_log_message) {
		return WarGrey::GYDM::slang_cast(nullptr, peer_port, payload, size, _C(type), response_port, transaction, fthen);
	}
	
	template<typename E>
	void slang_cast(Platform::String^ peer, uint16 peer_port, const uint8* payload, size_t size
		, E type, uint16 response_port = 0U, uint16 transaction = 0U, WarGrey::GYDM::slang_cast_task_then_t fthen = slang_cast_log_message) {
		return WarGrey::GYDM::slang_cast(peer, peer_port, payload, size, _C(type), response_port, transaction, fthen);
	}

	template<typename E>
	void slang_cast(uint16 peer_port, WarGrey::GYDM::IASNSequence* payload
		, E type, uint16 response_port = 0U, uint16 transaction = 0U, WarGrey::GYDM::slang_cast_task_then_t fthen = slang_cast_log_message) {
		return WarGrey::GYDM::slang_cast(nullptr, peer_port, payload, _C(type), response_port, transaction, fthen);
	}
	
	template<typename E>
	void slang_cast(Platform::String^ peer, uint16 peer_port, WarGrey::GYDM::IASNSequence* payload
		, E type, uint16 response_port = 0U, uint16 transaction = 0U, WarGrey::GYDM::slang_cast_task_then_t fthen = slang_cast_log_message) {
		return WarGrey::GYDM::slang_cast(peer, peer_port, payload, _C(type), response_port, transaction, fthen);
	}

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
		void push_slang_local_peer(WarGrey::GYDM::ISlangLocalPeer* confirmation);

	public:
		void join_multicast_group(Platform::String^ group_ipv4);

	public:
		void cast(Platform::String^ peer, uint16 peer_port, const WarGrey::GYDM::octets& payload, uint8 type = 0U, uint16 transaction = 0U);
		void cast(uint16 peer_port, const WarGrey::GYDM::octets& payload, uint8 type = 0U, uint16 transaction = 0U);
		void multicast(uint16 peer_port, const WarGrey::GYDM::octets& payload, uint8 type = 0U, uint16 transaction = 0U);

		void cast(Platform::String^ peer, uint16 peer_port, WarGrey::GYDM::IASNSequence* payload, uint8 type = 0U, uint16 transaction = 0U);
		void cast(uint16 peer_port, WarGrey::GYDM::IASNSequence* payload, uint8 type = 0U, uint16 transaction = 0U);
		void multicast(uint16 peer_port, WarGrey::GYDM::IASNSequence* payload, uint8 type = 0U, uint16 transaction = 0U);

		template<typename E>
		void cast(Platform::String^ peer, uint16 peer_port, const WarGrey::GYDM::octets& payload, E type, uint16 transaction = 0U) {
			this->cast(peer, peer_port, payload, _C(type), this->service, transaction);
		}

		template<typename E>
		void cast(uint16 peer_port, const WarGrey::GYDM::octets& payload, E type, uint16 transaction = 0U) {
			this->cast(peer_port, payload, _C(type), this->service, transaction);
		}

		template<typename E>
		void multicast(uint16 peer_port, const WarGrey::GYDM::octets& payload, E type, uint16 transaction = 0U) {
			this->multicast(peer_port, payload, _C(type), this->service, transaction);
		}

		template<typename E>
		void cast(Platform::String^ peer, uint16 peer_port, WarGrey::GYDM::IASNSequence* payload, E type, uint16 transaction = 0U) {
			this->cast(peer, peer_port, payload, _C(type), this->service, transaction);
		}

		template<typename E>
		void cast(uint16 peer_port, WarGrey::GYDM::IASNSequence* payload, E type, uint16 transaction = 0U) {
			this->cast(peer_port, payload, _C(type), this->service, transaction);
		}

		template<typename E>
		void multicast(uint16 peer_port, WarGrey::GYDM::IASNSequence* payload, E type, uint16 transaction = 0U) {
			this->multicast(peer_port, payload, _C(type), this->service, transaction);
		}

	protected:
		virtual Platform::String^ message_typename(uint8 type);
		virtual void apply_message(long long timepoint_ms, WarGrey::GYDM::ISlangLocalPeer* peer,
			Platform::String^ remote_peer, uint16 port, uint8 type, const uint8* message) = 0;
		
	private:
		void bind();
		void clear_if_peer_broken();
		void on_message(long long timepoint_ms, Platform::String^ remote_peer, uint16 port, uint8 type, const uint8* message);
		void on_message(long long timepoint_ms, Platform::String^ remote_peer, uint16 port, uint16 transaction, uint16 response_port, uint8 type, const uint8* message);		
		void cast_then(Platform::String^ host, uint16 port, unsigned int size, double span_ms, Platform::String^ exn_msg, uint8 type, uint16 transaction);

	protected:
		std::list<WarGrey::GYDM::ISlangLocalPeer*> local_peers;
		WarGrey::GYDM::ISlangLocalPeer* current_peer;
		WarGrey::SCADA::Syslog* logger;

    private:
		Windows::Networking::Sockets::DatagramSocket^ socket;
		Platform::Object^ ghostcat;
		Platform::String^ group;
		unsigned short service;

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
		Platform::String^ message_typename(uint8 type) override {
			return _E(E, type).ToString();
		}

		void apply_message(long long timepoint_ms, WarGrey::GYDM::ISlangLocalPeer* local_peer
			, Platform::String^ remote_peer, uint16 port, uint8 type, const uint8* message) override {
			auto peer = static_cast<WarGrey::GYDM::SlangLocalPeer<E>*>(local_peer);

			if (peer != nullptr) {
				peer->on_message(timepoint_ms, remote_peer, port, _E(E, type), message, this->logger);
			}
		};
	};
}
