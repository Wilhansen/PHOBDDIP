# OBD Data Interchange Protocol
Updated: 2017.05.15

Author: Wilhansen Li
<!--TOC-->

## General principles

1. Minimize data consumption.
2. Keep security in mind.
3. Make data formats clear.

##
1. Limit everything to 1 MTU (576 bytes).
2. Utilize binary formats, [protobuf3](https://developers.google.com/protocol-buffers/docs/proto3) in particular.
3. Utilize [libsodium](https://download.libsodium.org) library for cryptography.
4. Use UDP for high frequency data, HTTP for file transfers.
5. Byte order for non-protobuf entries is Little Endian.

### Key Exchange Algorithm

1. The server has a private-public key pair, the server's public key is available to everyone.
2. Upon registration, the client should generate a private-public key pair (using `crypto_kx_keypair`) and give the public key to the server.
3. Session keys are generated upon startup of the client/server and uses symmetric encryption for performance (use `crypto_kx_client_session_keys` in libsodium 1.0.12+).

## Message Protocol

Message payload between client and server is in protobuf3 binary format wrapped uses the following format (each pair of square brackets describe a block of data in `[datatype name]` format).

### Payload Header
The `payload_header` is as follows:
```
[uint16 payload_size][24-byte nonce][16-byte mac][24-byte reserve]
```

### Client to Server

```
[c(OBDI) marker][uint8 version][uint64 vessel_id][uint8 message_type][payload_header][bytes payload]
```

* `marker` — Always set to the string "OBDI".
* `version` — currently at 0.
* `vessel_id` — 8-byte ID of the vessel.
* `message_type` — Message type ID, see "Messages" for the list of possible messages.
* `payload_size` — size of the payload data, in bytes. When parsing, make sure that this is less than the total packet size - 16.
* `payload` — Protobuf3 payload data encrypted using the client's transmission key from the Key Exchange Algorithm with the `crypto_secretbox_*` method in libsodium.

### Server to Client
```
[c(OBDI) marker][uint8 version][uint8 message_type][payload_header][bytes payload]
```

* `marker` — Always set to the string "OBDI".
* `version` — currently at 0.
* `message_type` — Message type ID, see "Messages" for the list of possible messages. Server responses start with 50 onwards.
* `size` — size of the payload data, in bytes. When parsing, make sure that this is less than the total packet size - 8.
* `payload` — Protobuf3 payload data decryptable using the client's reception key from the Key Exchange Algorithm with the `crypto_secretbox_*` method in libsodium.

## Messages
Numbers in square brackets are the message type IDs.

Messages listed below with an asterisk (`*`) have to be sent reliably; they have "response" counterparts. These have a `message_id` field for tracking and response messages should use the same `message_id` as the original message it is responding to.

The value of the `message_id` does not matter as long as it is unique for all reliable message within a day. One way to implement the distribution of `message_id` is to keep a global message_id counter which increments everytime a message is constructed (i.e. `current_message.message_id = message_id_counter++`).

The sender algorithm is as follows:

```Swift
let timeouts = [3, 3, 5, 5, 10, 15, 20, 25, 30, 30];
var msg = create_message();
msg.message_id = message_id_counter++;
var try_count = 0;

send(destination: target, message: msg);

while( try_count < 10 ) {
	let response = recieve(from: target, withID: msg.id, timeout: timeouts[try_count]);
	if (response.status == ERROR_TIMEOUT) {
		try_count++;
	} else {
		success();
	}
}
fail();
```

The reciever algorithm is as follows
```Swift
var tracker = Map<int32, Timestamp>();
var packet = listen();

if ( !tracker.contains(packet.message.message_id) ||
	Timestame.now() - tracker[packet.message.message_id] >= 1.day ) {
	message_id_tracker[packet.message.message_id] = Timestamp.now();
	execute(message: packet.message);
}
let response = create_response(for: packet.message);
send(response, to: packet.source);
```
Make sure to purge the `tracker` regularly (if the program is long-running) to prevent overconsumption of memory.

### Common

#### Enums
```protobuf
enum Severity {
	DEBUG = 0;
	INFO = 1;
	WARNING = 2;
	SYSTEM_ERROR = 3;
	MECHANICAL_FAILURE = 4;
	ACCIDENT = 5;
	ENVIRONMENT = 6;
}

enum VesselStatus {
	TRANSIT = 0;
	LOADING = 1;
	SERVICING = 2;
	EMERGENCY = 3;
}

message Setting {
	string name = 1;
	string value = 2;
}
```

#### [`0`] Notice*
Response message: Notice Response

Notices are sent from server to client or client to server. The usual behavior of the client upon receiving a server notice is to display it on-screen.

```protobuf
message Notice {
	uint32 message_id = 1;
	Timestamp time_generated = 2;
	Severity severity = 3;
	string details = 4;
}
```

#### [`1`] Notice Response
Response to: Notice

```protobuf
message NoticeResponse {
	uint32 message_id = 1;
	Timestamp notice_receive_time = 2;
}
```

#### [`2`] Ping
Response message: Pong

Note that although this uses a message ID, this is not re-sent in case of failure.
```protobuf
message Ping {
	uint32 message_id = 1;
	Timestamp time_generated = 2;
}
```

#### [`3`] Pong
Response to: Ping

```protobuf
message Pong {
	uint32 message_id = 1; //should be identical to the Ping message it's responding to
	Timestamp time_generated = 2;
}
```

### Unencrypted Messages
These messages have payloads that are unencrypted but signed. The nonce, mac, and reserved entries in the payload header form the message signature.

#### [`10`] Crypto Error
```protobuf
message CryptoError {
	string details = 1;	
}
```

### Client Messages
#### [`20`] Location Update
```protobuf
message LocationUpdate {
	Timestamp ts = 1;
	float longitude = 2;
	float latitude = 3;
	float bearing = 4;
	float speed = 5;
	int32 current_load = 6; //negative number if unavailable
	VesselStatus status = 7;
	uint32 current_trip_id = 8;
}
```

#### [`21`] Change Settings Response
Response to: Change Settings

```protobuf
message ChangeSettingsResponse {
	uint32 message_id = 1; //refers to the message_id used in "ChangeSettings"
}
```

#### [`22`] Trip Info Update Status
Response to: Trip Info Update

Sent:
1. The moment a Trip Update server message is sent.
2. Every minute that a Trip Update is being downloaded.
3. When the Trip Update is done.

```protobuf
message TripInfoUpdateStatus {
	enum Status {
		IN_PROGRESS = 0;
		DONE = 1;
		ERROR = 2;
	}
	uint32 update_id = 1;
	Status status = 2;
}
```

### Server Messages
#### [`50`] Change Settings*
Response message: Change Settings Response

If the total ChangeSettings payload exceeds 540 bytes, the settings list must be split and sent separately.
Setting string values are formatted according to the JSON protobuf mapping stated [here](https://developers.google.com/protocol-buffers/docs/proto3#json).
Currently, possible settings are:

|   name       |              type        |
|--------------|--------------------------|
| UpdatePeriod | google.protobuf.Duration |

```protobuf
message ChangeSettings {
	uint32 message_id = 1;
	repeated Setting settings = 2;
}
```

#### [`51`] Error Response
```protobuf
message Error {
	enum Reason {
		PAYLOAD_SIZE_MISMATCH = 0;
		PAYLOAD_CANNOT_DECRYPT = 1;
		PAYLOAD_PARSE_FAIL = 2;
		INVALID_MESSAGE_TYPE = 3;
		INVALID_SETTING_VALUES = 4;
	}
	Reason code = 1;
	uint32 message_id = 2; //the message id this error refers to
	string details = 3;
}
```

#### [`52`] ETA Update
```protobuf
message ETAUpdate {
	Timestamp server_timestamp = 1;
	Duration time_remaining = 2;
	double meters_left = 3;
	float percentage_completed = 4;
}
```

#### [`53`] Trip Info Update*
Response message: Trip Info Update Status

Requests the client to download trip update data over HTTP/S using the specified URL.
```protobuf
message TripInfoUpdate {
	uint32 update_id = 1;
	Timestamp request_date = 2;
	string url = 3;
}
```