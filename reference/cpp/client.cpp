#include <stdint.h>

#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <memory>
#include <atomic>

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

std::unique_ptr<ClientCrypto> client_crypto;
int main_socket;
const uint8_t marker_data[4] = OBDI_MARKER_DATA;
uint64_t client_id = 0;

// Used to generate new message ids, incremented every time one is created
uint32_t message_id_counter = 0;

// Accepts a recieved message, and sends the appropriate response
void dispatch_message(const sockaddr_storage &address, const socklen_t address_length, const MessageType message_type, const void *payload, const size_t payload_size);

// Prepends the header to the Message object, then encrypts it
template<typename M>
vector<uint8_t> prepare_message(const M& m, const MessageType message_type) {
	unsigned char data[m.ByteSize()];
	m.SerializeToArray(data, m.ByteSize());
	vector<uint8_t> send_data(sizeof(ClientMessageHeader) + m.ByteSize());
	auto header = reinterpret_cast<ClientMessageHeader*>(send_data.data());
	memcpy(header->marker, marker_data, sizeof(marker_data));
	header->vessel_id = client_id;
	header->version = 0;
	header->message_type = message_type;
	header->payload_header.payload_size = m.ByteSize();
	client_crypto->encrypt_payload(header->payload_header,
		data, send_data.data() + sizeof(ClientMessageHeader));
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
		("s,server", "Server address.",
			cxxopts::value<string>()->default_value("localhost"))
		("p,port", "Server port.",
			cxxopts::value<string>()->default_value("1234"))
		("id", "Client id.",
			cxxopts::value<uint64_t>()->default_value("1"))
		("pub", "Public key path.",
			cxxopts::value<string>()->default_value("client.pub"))
		("priv", "Private/secret key path.",
			cxxopts::value<string>()->default_value("client.priv"))
		("sk", "Server public key path.",
			cxxopts::value<string>()->default_value("server.pub"))
		("h,help", "Print help")
	;

	options.parse(argc, argv);
	if ( options["help"].as<bool>() ) {
		cout << options.help();
		return 0;
	}

	try {
		client_crypto.reset(new ClientCrypto(
			options["id"].as<uint64_t>(),
			options["pub"].as<string>().c_str(),
			options["priv"].as<string>().c_str(),
			options["sk"].as<string>().c_str()
		));

		client_id = options["id"].as<uint64_t>();

		struct addrinfo hints = {0}, *service_info = 0;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;

		if ( auto gai_r = getaddrinfo(options["server"].as<string>().c_str(), options["port"].as<string>().c_str(), &hints, &service_info) ) {
			cerr << "[ERROR] Cannot resolve listen address: " << gai_strerror(gai_r) << endl;
			return 1;
		}
		if ( service_info == 0 ) {
			cerr << "[ERROR] No address resolved\n";
			return 1;
		}

		main_socket = -1;
		sockaddr_storage server_addr;
		socklen_t server_addrlen;
		for ( auto p = service_info; p != 0; p = p->ai_next ) {
			if ( (main_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1 ) {
				const auto desc = strerror(errno);
				cerr << "[WARNING] Cannot create server socket: " << desc << endl;
				
				continue;
			}
			//if ( ::bind(main_socket, p->ai_addr, p->ai_addrlen) == -1 ) {
			//	const auto desc = strerror(errno);
			//	cerr << "[WARNING] Unable to bind socket to address: " << desc << endl;
			//	continue;
			//}

			memcpy(&server_addr, p->ai_addr, p->ai_addrlen);
			server_addrlen = p->ai_addrlen;
			break;
		}

		if ( main_socket == -1 ) {
			cerr << "[ERROR] Cannot create UDP socket.\n";
			return 1;
		}

		freeaddrinfo(service_info);

		atomic<bool> is_running(true);

		thread dispatch_thread([&is_running](){
			while ( is_running ) {
				sockaddr_storage src_addr;
				socklen_t src_addrlen = sizeof(src_addr);
				uint8_t buffer[1024];
				
				const auto recvlen = recvfrom(main_socket, buffer, sizeof(buffer), 0, (sockaddr*)&src_addr, &src_addrlen);
				if ( recvlen < 0 ) {
					cerr << "[WARNING] Receive error: " << strerror(errno) << endl;
					continue;
				}
				if (recvlen < sizeof(ServerMessageHeader) ) {
					cerr << "[WARNING] Received data too small: " << recvlen << endl;
					continue;
				}

				const auto client_header = reinterpret_cast<ServerMessageHeader*>(buffer);
				
				if ( memcmp(client_header->marker, marker_data, sizeof(marker_data)) != 0 ) {
					cerr << "[WARNING] Client header marker mismatch.\n";
					continue;
				}
				if ( client_header->version != OBDI_VERSION ) {
					cerr << "[WARNING] Client header version mismatch.\n";
					continue;
				}
				if ( client_header->payload_header.payload_size > recvlen - sizeof(*client_header) ) {
					cerr << "[WARNING] Payload size field greater than packet size.\n";
					continue;
				}
				if ( client_header->message_type == MessageType::CRYPTO_ERROR ) {
					if ( !client_crypto->verify_signed_server_payload(buffer + sizeof(*client_header), client_header->payload_header) ) {
						cerr << "[WARNING] Signed server payload verification failed.\n";
						continue;
					}
				} else if ( client_crypto->decrypt_payload(client_header->payload_header, buffer + sizeof(*client_header)) != ClientCrypto::Result::OK ) {
					cerr << "[WARNING] Unable to decrypt server payload.\n";
					continue;
				}

				dispatch_message(src_addr, src_addrlen, client_header->message_type, buffer + sizeof(*client_header), client_header->payload_header.payload_size);
			}
		});
		
		cout << "Client started.\n";
		string command_buffer;
#define SEND_USER_MESSAGE(Type, message) { \
        auto sent_size = sendto(main_socket, message.data(), message.size(), 0, (sockaddr*)&server_addr, server_addrlen); \
        if ( sent_size != message.size() ) { \
                cerr << "[WARNING] Sent " #Type " message size mismatch (actual: " << sent_size << ", expected: " << message.size() << ")" << endl; \
        } \
} 

#define GET_MESSAGE_ID	message_id_counter++
#define GET_CURRENT_TIME new google::protobuf::Timestamp(google::protobuf::util::TimeUtil::GetCurrentTime())

		obdi::Ping ping;
		// Ping the server upon connecting to it 
		ping.set_message_id(GET_MESSAGE_ID);
		ping.set_allocated_time_generated(GET_CURRENT_TIME);
		SEND_USER_MESSAGE(obdi::Ping, prepare_message(ping, MessageType::PING));
		while( getline(cin, command_buffer) ) {
			if ( command_buffer.empty() ) {
				continue;
			}
			if ( command_buffer[0] == 'q' ) {
				break;
			}

			// Simulates sending a Notice message
			if ( strcmp(command_buffer.c_str(), "notice") == 0 ) {
				obdi::Notice notice;
				notice.set_message_id(GET_MESSAGE_ID);
				string notice_message;
				cout << "Enter notice message: ";
				getline(cin, notice_message);
				notice.set_details(notice_message);
				using namespace obdi;
				cout << "Enter severity: ";
				int severity;
				cin >> severity;
				notice.set_severity((Severity)severity);
				notice.set_allocated_time_generated(GET_CURRENT_TIME);

				SEND_USER_MESSAGE(obdi::Notice, prepare_message(notice, MessageType::NOTICE));
			}

			// Simulates sending a Ping message
			if ( strcmp(command_buffer.c_str(), "ping") == 0 ) {
				obdi::Ping ping;
				ping.set_message_id(GET_MESSAGE_ID);
				ping.set_allocated_time_generated(GET_CURRENT_TIME);

				SEND_USER_MESSAGE(obdi::Ping, prepare_message(ping, MessageType::PING));
			}

			// Simulates sending a LocationUpdate message
			if ( strcmp(command_buffer.c_str(), "location update") == 0 ) {
				obdi::LocationUpdate lu;
				obdi::LocationUpdate::Entry* e = lu.add_entries();
				e->set_allocated_ts(GET_CURRENT_TIME);
				float longitude, latitude, bearing, speed;
				int current_load, status, current_trip_id, stop;

				cout << "Enter longitude: "; cin >> longitude;
				cout << "Enter latitude: "; cin >> latitude;
				cout << "Enter bearing: "; cin >> bearing;
				cout << "Enter speed: "; cin >> speed;
				cout << "Enter current load: "; cin >> current_load;
				cout << "Enter status: "; cin >> status;
				cout << "Enter trip ID: "; cin >> current_trip_id;
				cout << "Enter stop: "; cin >> stop;

				e->set_longitude(longitude);
				e->set_latitude(latitude);
				e->set_bearing(bearing);
				e->set_speed(speed);
				e->set_current_load(current_load);
				using namespace obdi;
				e->set_status((VesselStatus)status);
				e->set_current_trip_id(current_trip_id);
				e->set_stop(stop);
				cout << "size of entry: " << sizeof(e) << endl;		
				SEND_USER_MESSAGE(obdi::LocationUpdate, prepare_message(lu, MessageType::LOCATION_UPDATE))
			}

		}
		// Ping the server when disconnecting from it
		ping.set_message_id(GET_MESSAGE_ID);
		ping.set_allocated_time_generated(GET_CURRENT_TIME);
		SEND_USER_MESSAGE(obdi::Ping, prepare_message(ping, MessageType::PING));

		is_running = false;
		dispatch_thread.join();

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

void dispatch_message(const sockaddr_storage &address, const socklen_t address_length, const MessageType message_type, const void *payload, const size_t payload_size) {
#define PARSE_MESSAGE(Type, ident) \
	Type ident;\
	if ( !ident.ParseFromArray(payload, payload_size) ) { \
		cerr << "[WARNING] Unable to parse " #Type " message.\n"; \
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

			cout << "Received from server: " << notice.DebugString() << endl;

			obdi::Ack response;
			response.set_message_id(notice.message_id());
			using namespace google::protobuf;
			response.set_allocated_time_generated(new Timestamp(util::TimeUtil::GetCurrentTime()));
			
			const auto &send_data = prepare_message(response, MessageType::ACK);
			
			SEND_MESSAGE(obdi::Ack, send_data);
			break;
		}
		case MessageType::PING: {
			PARSE_MESSAGE(obdi::Ping, ping);
			cout << "Received from server: " << ping.DebugString() << endl;

			obdi::Ack ack;
			ack.set_message_id(ping.message_id());
			using namespace google::protobuf;
			ack.set_allocated_time_generated(new Timestamp(util::TimeUtil::GetCurrentTime()));
			
			const auto &send_data = prepare_message(ack, MessageType::ACK);
			
			SEND_MESSAGE(obdi::Ack, send_data);
			break;
		}
		case MessageType::ACK: {
			PARSE_MESSAGE(obdi::Ack, ack);
			cout << "Received from server: " << ack.DebugString() << endl;
			break;
		}
		case MessageType::CRYPTO_ERROR: {
			PARSE_MESSAGE(obdi::CryptoError, crypto_error);
			cout << "Received from server: " << crypto_error.DebugString() << endl;
			break;	
		}
		case MessageType::LOCATION_UPDATE:
		case MessageType::TRIP_INFO_UPDATE_STATUS: {
			cout << "Received client message from server.\n";
			break;
		}
		case MessageType::CHANGE_SETTINGS: {
			PARSE_MESSAGE(obdi::ChangeSettings, change_settings);
			cout << "Received from server: " << change_settings.DebugString() << endl;

			obdi::Ack ack;
			ack.set_message_id(change_settings.message_id());
			using namespace google::protobuf;
			ack.set_allocated_time_generated(new Timestamp(util::TimeUtil::GetCurrentTime()));
			
			const auto &send_data = prepare_message(ack, MessageType::ACK);
			
			SEND_MESSAGE(obdi::Ack, send_data);
			break;
		}
		case MessageType::ERROR: {
			PARSE_MESSAGE(obdi::Error, error_response);
			cout << "Received from server: " << error_response.DebugString() << endl;
			break;
		}
		case MessageType::ETA_UPDATE: {
			PARSE_MESSAGE(obdi::ETAUpdate, eta_update);
			cout << "Received from server: " << eta_update.DebugString() << endl;
			break;	
		}
		case MessageType::TRIP_INFO_UPDATE: {
			PARSE_MESSAGE(obdi::TripInfoUpdate, trip_info_update);
			cout << "Received from server: " << trip_info_update.DebugString() << endl;

			obdi::TripInfoUpdateStatus response;
			response.set_update_id(trip_info_update.update_id());
			response.set_status(obdi::TripInfoUpdateStatus_Status_DONE);
			const auto &send_data = prepare_message(response, MessageType::TRIP_INFO_UPDATE_STATUS);

			SEND_MESSAGE(obdi::TripInfoUpdateStatus, send_data);
			break;
		}
		default: {
			cerr << "[WARNING] Unknown message type: " << (uint16_t)message_type << endl;
			break;
		}
	}
}
