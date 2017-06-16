#ifndef MESSAGEHEADERS_HPP
#define MESSAGEHEADERS_HPP
#include <stdint.h>

#define NONCE_SIZE 12 //crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define MAC_SIZE 16 //crypto_aead_chacha20poly1305_ietf_ABYTES

enum class MessageType : uint8_t {
	NOTICE = 0,
	PING = 2,
	ACK = 3,

	CRYPTO_ERROR = 10,
	MODIFY_SERVER_KEYS = 11,

	LOCATION_UPDATE = 20,
	TRIP_INFO_UPDATE_STATUS = 21,

	CHANGE_SETTINGS = 50,
	ERROR = 51,
	ETA_UPDATE = 52,
	TRIP_INFO_UPDATE = 53
};

#pragma pack(push, 1)
struct PayloadAuthenticationData {
	uint8_t nonce[NONCE_SIZE];
	uint8_t mac[MAC_SIZE];
};

struct ClientMessageHeader {
	uint8_t marker[4];
	uint8_t version;
	MessageType message_type;
	uint16_t payload_size;
	uint64_t vessel_id;
	PayloadAuthenticationData payload_ad;
};

struct ServerMessageHeader {
	uint8_t marker[4];
	uint8_t version;
	uint16_t payload_size;
	MessageType message_type;
	PayloadAuthenticationData payload_ad;
};
#pragma pack(pop)

#define OBDI_MARKER_DATA {'O','B','D','I'}
#define OBDI_VERSION 0

#endif