#OBD Data Interchange Protocol
Updated: 2017.05.12
Author: Wilhansen Li
<!--TOC-->

##General principles

1. Limit everything to 1 MTU (576 bytes)
2. Utilize binary formats (protobuf)
3. Utilize libsodium library for cryptography
4. Use UDP
5. Network byte order is used for non-protobuf entries

###Key Exchange Algorithm

1. The server has a private-public key pair, the server's public key is available to all clients.
2. Upon registration, the client should generate a private-public key pair (using `crypto_kx_keypair`) and give the public key to the server.
3. Session keys are generated upon startup of the client/server and uses symmetric encryption for performance (use `crypto_kx_client_session_keys` in libsodium 1.0.12+).

##Message Protocol

Message payload between client and server is in protobuf3 binary format wrapped uses the following format (each pair of square brackets describe a block of data in `[datatype name]` format).

###Client to Server

```
[c(OBDI) marker][uint8 version][uint64 vessel_id][uint8 message_type][uint16 payload_size][bytes payload]
```

* `marker` — Always set to the string "OBDI".
* `version` — currently at 0.
* `vessel_id` — 8-byte ID of the vessel.
* `message_type` — Message type ID, see "Messages" for the list of possible messages.
* `payload_size` — size of the payload data, in bytes. When parsing, make sure that this is less than the total packet size - 16.
* `payload` — Protobuf3 payload data encrypted using the client's transmission key from the Key Exchange Algorithm with the `crypto_secretbox_*` method in libsodium.

###Server to client
```
[c(OBDI) marker][uint8 version][uint8 message_type][uint16 payload_size][bytes payload]
```

* `marker` — Always set to the string "OBDI".
* `version` — currently at 0.
* `message_type` — Message type ID, see "Messages" for the list of possible messages. Server responses start with 50 onwards.
* `size` — size of the payload data, in bytes. When parsing, make sure that this is less than the total packet size - 8.
* `payload` — Protobuf3 payload data decryptable using the client's reception key from the Key Exchange Algorithm with the `crypto_secretbox_*` method in libsodium.

##Messages
Numbers in square brackets are the message type IDs.

Messages with an asterisk (`*`) have to be sent reliably; they have "response" counterparts. These have a `message_id` field for tracking and response messages should use the same `message_id` as the original message it is responding to.

The value of the `message_id` does not matter as long as it is unique for all reliable message within a day. One way to implement the distribution of `message_id` is to keep a global message_id counter which increments everytime a message is constructed (i.e. `current_message.message_id = message_id_counter++`).

The sender algorithm is as follows:

```Swift
let timeouts = [3, 3, 5, 5, 10, 15, 20, 25, 30, 30];
var msg = create_message();
msg.message_id = message_id_counter++;
var try_count = 0;

send(destination: target, message: msg);

while( try_count < 10 ) {
	let response = recieve(from: target, withIID: msg.id, timeout: timeouts[try_count]);
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

###Common

####Enums
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

####[`0`] Notice*
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

####[`1`] Notice Response
Response to: Notice

```protobuf
message NoticeResponse {
	uint32 message_id = 1;
	Timestamp notice_recieve_time = 2;
}
```

####[`2`] Ping*
Response message: Pong

```protobuf
message Ping {
	uint32 message_id = 1;
	uint32 try_count = 2;
	Timestamp original_time_generated = 3;
	Timestamp current_time_generated = 4;
}
```

####[`3`] Pong
Response to: Ping

```protobuf
message Pong {
	uint32 message_id = 1; //should be identical to the Ping message it's responding to
	uint32 ping_try_count = 2;
	Timestamp time_generated = 3;
}
```


### Client Messages
####[`10`] Location Update
```protobuf
message LocationUpdate {
	Timestamp ts = 1;
	uint32 message_id = 2;
	float longitude = 3;
	float latitude = 4;
	float bearing = 5;
	float speed = 6;
	int32 current_load = 7; //negative number if unavailable
	VesselStatus status = 8;
	uint32 current_trip_id = 9;
}
```

####[`11`] Change Settings Response
Response to: Change Settings

```protobuf
message ChangeSettingsResponse {
	uint32 message_id = 1; //refers to the message_id used in "ChangeSettings"
}
```

####[`12`] Trip Info Update Status
Response to: Trip Info Update

Sent:
1. The moment a Trip Update server message is sent.
2. Every minute that a Trip Update is being downloaded.
3. When the Trip Update is done.

```protobuf
message TripUpdateStatus {
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
####[`50`] Change Settings*
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

####[`51`] Error Response
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

####[`52`] ETA Update
```protobuf
message ETAUpdate {
	Timestamp server_timestamp = 1;
	Duration time_remaining = 2;
	double meters_left = 3;
	float percentage_completed = 4;
}
```

####[`53`] Trip Info Update*
Response message: Trip Info Update Status

Requests the client to download trip update data over HTTP/S using the specified URL.
```protobuf
message TripInfoUpdate {
	uint32 update_id = 1;
	Timestamp request_date = 2;
	string url = 3;
}
```