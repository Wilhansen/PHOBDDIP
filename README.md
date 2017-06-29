# OBD Data Interchange Protocol

## Building (CPP)
Requirements:
1. C++11 compiler
2. libsodium 1.0.12+
3. protobuf 3.3.0+ compiler and c++ runtime library

Steps:
1. Install libsodium (1.0.12) and protobuf (3.3.0)
2. Compile the OBDI proto file using  
`protoc --cpp_out=/reference/cpp/ obdi.proto`
3. Compile the source files using `make`

## Building (NodeJS)
1. Make sure you have npm and nodejs installed. Run `npm install` in the node directory
2. No need to compile the .proto file, the protobuf package does this for you

## Running
1. Generate the keys, save to their default location
```shell
./keygen keys/server
./keygen client.pub client.priv
```
2. Copy the client.pub key to the keys directory, rename it 0000000000000001.pub (that's 15 `0` followed by a `1`; the default client id is `1`)
3. Run server and client  
```shell
./server
./client --sk keys/server.pub
node index.js --sk keys/server.pub
```
4. Send messages from the client command line (`help` to show commands)
