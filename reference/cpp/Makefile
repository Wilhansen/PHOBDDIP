all: server keygen client

client: client.cpp Utility.cpp Utility.hpp obdi.pb.cc
	$(CXX) $(CXXFLAGS) `pkg-config --cflags --libs libsodium protobuf` -o client -std=c++11 client.cpp Utility.cpp obdi.pb.cc

server: server.cpp Utility.cpp Utility.hpp obdi.pb.cc
	$(CXX) $(CXXFLAGS) `pkg-config --cflags --libs protobuf libsodium` -o server -std=c++11 server.cpp Utility.cpp obdi.pb.cc

keygen: keygen.cpp Utility.cpp Utility.hpp
	$(CXX) $(CXXFLAGS) -o keygen -std=c++11 `pkg-config --cflags --libs libsodium` keygen.cpp Utility.cpp
