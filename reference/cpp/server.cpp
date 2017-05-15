#include <stdint.h>

#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <memory>

#ifdef _WIN32
	#include <winsock2.h>
#else
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netdb.h>
	#include <unistd.h>
#endif

#ifdef _WIN32
	#define CLOSE_SOCKET closesocket
#else
	#define CLOSE_SOCKET close
#endif

#include <google/protobuf/util/time_util.h>

#include "cxxopts.hpp"
#include "Utility.hpp"
#include "obdi.pb.h"

using namespace std;

std::unique_ptr<ServerCrypto> server_crypto;
int main_socket;
const uint8_t marker_data[4] = OBDI_MARKER_DATA;

void dispatch_message(const uint64_t vessel_id, const sockaddr_storage &address, const socklen_t address_length, const MessageType message_type, const void *payload, const size_t payload_size);

template<typename M>
vector<uint8_t> prepare_message(const M& m, const MessageType message_type, const uint64_t vessel_id) {
	const auto &response_data = m.SerializeAsString();

	vector<uint8_t> send_data(sizeof(ServerMessageHeader) + response_data.size());
	auto header = reinterpret_cast<ServerMessageHeader*>(send_data.data());
	memcpy(header->marker, marker_data, sizeof(marker_data));
	header->version = 0;
	header->message_type = message_type;
	header->payload_header.payload_size = response_data.size();
	server_crypto->encrypt_payload(vessel_id, header->payload_header,
		response_data.data(), send_data.data() + sizeof(ServerMessageHeader));
	return send_data;
}

int main(int argc, char **argv) {
#ifdef _WIN32
	{
		WSADATA wsaData;

		if (WSAStartup(MAKEWORD(2,0), &wsaData) != 0) {
			return 1;
		}
	}
#endif
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	cxxopts::Options options("server", "OBDI reference server");
	options.add_options()
		("l,listen", "address to listen",
			cxxopts::value<string>()->default_value("0.0.0.0"))
		("p,port", "port to listen",
			cxxopts::value<uint16_t>()->default_value("1234"))
		("k,keydir", "Directory where server.pub, server.key, and client public keys are. Client public keys should be named as [id-hex].pub",
			cxxopts::value<string>()->default_value("keys"))
		("h,help", "Print help")
	;
	options.parse(argc, argv);
	if ( options["help"].as<bool>() ) {
		cout << options.help();
		return 0;
	}

	try {
		server_crypto.reset(new ServerCrypto(options["keydir"].as<string>().c_str()));

		struct addrinfo hints = {0}, *service_info = 0;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_PASSIVE;

		if ( auto gai_r = getaddrinfo(options["listen"].as<string>().c_str(), options["port"].as<string>().c_str(), &hints, &service_info) ) {
			cerr << "[ERROR] Cannot resolve listen address: " << gai_strerror(gai_r) << endl;
			return 1;
		}
		if ( service_info == 0 ) {
			cerr << "[ERROR] No address resolved\n";
			return 1;
		}

		main_socket = -1;
		for ( auto p = service_info; p != 0; p = p->ai_next ) {
			if ( (main_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1 ) {
				const auto desc = strerror(errno);
				cerr << "[WARNING] Cannot create server socket: " << desc << endl;
				
				continue;
			}
			if ( ::bind(main_socket, p->ai_addr, p->ai_addrlen) == -1 ) {
				const auto desc = strerror(errno);
				cerr << "[WARNING] Unable to bind socket to address: " << desc << endl;
				continue;
			}

			break;
		}

		if ( main_socket == -1 ) {
			cerr << "[ERROR] Cannot create UDP socket.\n";
			return 1;
		}

		freeaddrinfo(service_info);

		while ( true ) {
			sockaddr_storage src_addr;
			socklen_t src_addrlen = sizeof(src_addr);
			uint8_t buffer[1024];
			
			const auto recvlen = recvfrom(main_socket, buffer, sizeof(buffer), 0, (sockaddr*)&src_addr, &src_addrlen);
			if ( recvlen < 0 ) {
				cerr << "[WARNING] Receive error: " << strerror(errno) << endl;
				continue;
			}
			if (recvlen < sizeof(ClientMessageHeader) ) {
				cerr << "[WARNING] Received data too small: " << recvlen << endl;
				continue;
			}

			const auto client_header = reinterpret_cast<ClientMessageHeader*>(buffer);
			
			if ( memcmp(client_header->marker, marker_data, sizeof(marker_data)) != 0 ) {
				cerr << "[WARNING] Client header marker mismatch." << endl;
				continue;
			}
			if ( client_header->version != OBDI_VERSION ) {
				cerr << "[WARNING] Client header version mismatch." << endl;
				continue;
			}
			if ( client_header->payload_header.payload_size > recvlen - sizeof(*client_header) ) {
				cerr << "[WARNING] Payload size field greater than packet size." << endl;
				continue;
			}
			if ( !server_crypto->decrypt_payload(client_header->vessel_id, client_header->payload_header, buffer + sizeof(*client_header)) ) {
				obdi::CryptoError crypto_error;
				crypto_error.set_details("Unable to decrypt payload.");

				const auto &response_data = crypto_error.SerializeAsString();

				vector<uint8_t> send_data(sizeof(ServerMessageHeader) + response_data.size());
				memcpy(send_data.data() + sizeof(ServerMessageHeader), response_data.data(), response_data.size());

				auto header = reinterpret_cast<ServerMessageHeader*>(send_data.data());
				memcpy(header->marker, marker_data, sizeof(marker_data));
				header->version = 0;
				header->message_type = MessageType::CRYPTO_ERROR;
				header->payload_header.payload_size = response_data.size();

				server_crypto->sign_payload(response_data.data(), header->payload_header);
				sendto(main_socket, send_data.data(), send_data.size(), 0, (sockaddr*)&src_addr, src_addrlen);
				continue;
			}

			dispatch_message(client_header->vessel_id, src_addr, src_addrlen, client_header->message_type, buffer + sizeof(*client_header), client_header->payload_header.payload_size);
		}

		CLOSE_SOCKET(main_socket);
	} catch ( const std::exception &e ) {
		cerr << "[ERROR] " << e.what() << endl;
	}
#ifdef _WIN32
	WSACleanup();
#endif
	google::protobuf::ShutdownProtobufLibrary();
	return 0;
}

void dispatch_message(const uint64_t vessel_id, const sockaddr_storage &address, const socklen_t address_length, const MessageType message_type, const void *payload, const size_t payload_size) {
#define PARSE_MESSAGE(Type, ident) \
	Type ident;\
	if ( !ident.ParseFromArray(payload, payload_size) ) { \
		cerr << "[WARNING] Unable to parse " #Type " message from " << vessel_id << endl; \
		break; \
	}

#define SEND_MESSAGE(Type, message) { \
	auto sent_size = sendto(main_socket, message.data(), message.size(), 0, (sockaddr*)&address, address_length); \
	if ( sent_size != message.size() ) { \
		cerr << "[WARNING] Sent " #Type " message size mismatch (actual: " << sent_size << ", expected: " << message.size() << ")" << endl; \
	} \
}	
	switch (message_type) {
		case MessageType::NOTICE: {
			PARSE_MESSAGE(obdi::Notice, notice);

			cout << "Received from " << vessel_id << ": " << notice.DebugString() << endl;

			obdi::NoticeResponse response;
			response.set_message_id(notice.message_id());
			using namespace google::protobuf;
			response.set_allocated_notice_receive_time(new Timestamp(util::TimeUtil::GetCurrentTime()));
			
			const auto &send_data = prepare_message(response, MessageType::NOTICE_RESPONSE, vessel_id);
			
			SEND_MESSAGE(obdi::NoticeResponse, send_data);
			break;
		}
		case MessageType::NOTICE_RESPONSE: {
			PARSE_MESSAGE(obdi::NoticeResponse, notice_response);
			cout << "Received from " << vessel_id << ": " << notice_response.DebugString() << endl;
			break;
		}
		case MessageType::PING: {
			PARSE_MESSAGE(obdi::Ping, ping);
			cout << "Received from " << vessel_id << ": " << ping.DebugString() << endl;

			obdi::Pong pong;
			pong.set_message_id(ping.message_id());
			using namespace google::protobuf;
			pong.set_allocated_time_generated(new Timestamp(util::TimeUtil::GetCurrentTime()));
			
			const auto &send_data = prepare_message(pong, MessageType::PONG, vessel_id);
			
			SEND_MESSAGE(obdi::Pong, send_data);
			break;
		}
		case MessageType::PONG: {
			PARSE_MESSAGE(obdi::Pong, pong);
			cout << "Received from " << vessel_id << ": " << pong.DebugString() << endl;
			break;
		}
		case MessageType::LOCATION_UPDATE: {
			PARSE_MESSAGE(obdi::LocationUpdate, location_update);
			cout << "Received from " << vessel_id << ": " << location_update.DebugString() << endl;
			break;
		}
		case MessageType::CHANGE_SETTINGS_RESPONSE: {
			PARSE_MESSAGE(obdi::ChangeSettingsResponse, change_settings_response);
			cout << "Received from " << vessel_id << ": " << change_settings_response.DebugString() << endl;
			break;
		}
		case MessageType::TRIP_INFO_UPDATE_STATUS: {
			PARSE_MESSAGE(obdi::TripInfoUpdateStatus, trip_info_update_status);
			cout << "Received from " << vessel_id << ": " << trip_info_update_status.DebugString() << endl;
			break;
		}
		case MessageType::CHANGE_SETTINGS:
		case MessageType::ERROR:
		case MessageType::ETA_UPDATE:
		case MessageType::TRIP_INFO_UPDATE:
			cout << "Got server message (id: " << (int)message_type << ") from " << vessel_id << endl;
			break;
		default: {
			cerr << "[WARNING] Unknown message type: " << (uint16_t)message_type << endl;
			break;
		}
	}
}
