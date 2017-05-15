all: server keygen client

client: client.cpp Utility.cpp Utility.hpp obdi.pb.cc
	$(CXX) $(CXXFLAGS) `pkg-config --cflags --libs protobuf` -o client -std=c++11 -lsodium client.cpp Utility.cpp obdi.pb.cc

server: server.cpp Utility.cpp Utility.hpp obdi.pb.cc
	$(CXX) $(CXXFLAGS) `pkg-config --cflags --libs protobuf` -o server -std=c++11 -lsodium server.cpp Utility.cpp obdi.pb.cc

keygen: keygen.cpp Utility.cpp Utility.hpp
	$(CXX) $(CXXFLAGS) -o keygen -std=c++11 -lsodium keygen.cpp Utility.cpp
