#ifndef UTILITY_HPP
#define UTILITY_HPP

#include <algorithm>
#include <string>
#include <vector>
#include <cstdio>

#include <sodium.h>
#include <stdint.h>

#include "MessageHeaders.hpp"

class SecureMemory {
	uint8_t *m_data;
	size_t m_size;
public:
	SecureMemory(size_t size);

	SecureMemory() : m_size(0), m_data(0) {}

	SecureMemory(const SecureMemory &rhs) = delete;
	SecureMemory& operator=(const SecureMemory &) = delete;

	SecureMemory(SecureMemory &&rhs) : m_data(rhs.m_data), m_size(rhs.m_size) {
		rhs.m_data = 0;
		rhs.m_size = 0;
	}
	SecureMemory& operator=(SecureMemory &&rhs) {
		std::swap(rhs.m_data, m_data);
		std::swap(rhs.m_size, m_size);
		return *this;
	}

	~SecureMemory();


	uint8_t* data() { return m_data; }
	uint8_t* const data() const { return m_data; }
	size_t size() const { return m_size; }
};

inline std::vector<uint8_t> readfile(const char * path) {
	using namespace std;
	
	vector<uint8_t> v;
	if ( FILE *fp = fopen(path, "rb") ) {
		uint8_t buf[1024];
		while (size_t len = fread(buf, 1, sizeof(buf), fp))
			v.insert(v.end(), buf, buf + len);
		fclose(fp);
	}
	return v;
}

struct KeyPair {
	SecureMemory secret_key, public_key;

	static KeyPair generate();
};
struct SessionKeyPair {
	SecureMemory reception_key, transmisson_key;
};

struct NonceGenerator {
	uint64_t counter = 0;
	struct NonceStruct {
		uint8_t rng[crypto_aead_chacha20poly1305_ietf_NPUBBYTES - sizeof(uint64_t)];
		uint64_t counter;
	};
	void next(uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]) {
		auto n = reinterpret_cast<NonceStruct*>(nonce);
		randombytes_buf(&(n->rng), sizeof(n->rng));
		n->counter = counter++;
	}
};

#define SERVER_PRIVATE_KEY_FILE "server.key"
#define SERVER_PUBLIC_KEY_FILE "server.pub"

class ServerCrypto {
public:
	enum class Result {
		OK,
		KEY_NOT_FOUND,
		WRONG_CLIENT_KEY_SIZE,
		WRONG_KEY,
		INVALID_PAYLOAD
	};
private:
	std::string m_keydir;
	std::vector<uint8_t> server_pk, sign_pk;
	SecureMemory server_sk, sign_sk;
	NonceGenerator ng;
	
	Result load_keys(const uint64_t client_id, SessionKeyPair &dst);
public:
	ServerCrypto(const char *keydir);
	Result decrypt_payload(const uint64_t client_id, const ClientMessageHeader &payload_header, void *payload);
	Result encrypt_payload(const uint64_t client_id, ServerMessageHeader &payload_header, const void *payload, void *destination);
	void sign_payload(ServerMessageHeader &header, uint8_t destination[crypto_sign_BYTES]);
};

class ClientCrypto {
public:
	enum class Result {
		OK,
		KEY_NOT_FOUND,
		WRONG_CLIENT_KEY_SIZE,
		WRONG_KEY,
		INVALID_PAYLOAD
	};
private:
	std::vector<uint8_t> sign_pk, server_sign_pk, master_sign_pk;
	SecureMemory client_rx, client_tx, sign_sk;
	NonceGenerator ng;
	const uint64_t client_id;
	
	void derive_keys();
public:
	ClientCrypto(const uint64_t client_id, const char *pk_path, const char *sk_path, const char *server_key_path, const char *master_key_path);
	Result decrypt_payload(const ServerMessageHeader &payload_header, void *payload);
	Result encrypt_payload(ClientMessageHeader &payload_header, const void *payload, void *destination);
	void sign_payload(ClientMessageHeader &header, uint8_t destination[crypto_sign_BYTES]);
	bool verify_signed_server_payload(const ServerMessageHeader &header, const uint8_t signature[crypto_sign_BYTES]);
	bool verify_signed_master_payload(const ServerMessageHeader &header, const uint8_t signature[crypto_sign_BYTES]);
	void replace_server_key(const std::vector<uint8_t> &server_sign_pk);
};

#endif