#ifndef MESSAGEHEADERS_HPP
#define MESSAGEHEADERS_HPP
#include <stdint.h>

#define NONCE_SIZE 24 //crypto_secretbox_NONCEBYTES
#define MAC_SIZE 16 //crypto_secretbox_MACBYTES
#define RESERVE_SIZE 24
#define SIGNATURE_SIZE 64

enum class MessageType : uint8_t {
	NOTICE = 0,
	NOTICE_RESPONSE = 1,
	PING = 2,
	ACK = 3,

	CRYPTO_ERROR = 10,

	LOCATION_UPDATE = 20,
	TRIP_INFO_UPDATE_STATUS = 21,

	CHANGE_SETTINGS = 50,
	ERROR = 51,
	ETA_UPDATE = 52,
	TRIP_INFO_UPDATE = 53
};

#pragma pack(push, 1)
struct PayloadHeader {
	uint16_t payload_size;
	union {
		struct {
			uint8_t nonce[NONCE_SIZE];
			uint8_t mac[MAC_SIZE];
			uint8_t reserved[RESERVE_SIZE];
		};
		uint8_t signature[SIGNATURE_SIZE];
	};
};

struct ClientMessageHeader {
	uint8_t marker[4];
	uint8_t version;
	MessageType message_type;
	uint32_t server_id;
	uint64_t vessel_id;
	PayloadHeader payload_header;
};

struct ServerMessageHeader {
	uint8_t marker[4];
	uint8_t version;
	MessageType message_type;
	uint32_t server_id;
	PayloadHeader payload_header;
};
#pragma pack(pop)

#define OBDI_MARKER_DATA {'O','B','D','I'}
#define OBDI_VERSION 0

#endif