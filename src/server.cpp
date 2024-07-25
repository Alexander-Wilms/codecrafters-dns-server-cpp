#include <cctype>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// https://en.cppreference.com/w/cpp/language/bit_field
struct header_struct {
	unsigned int id : 16;
	unsigned int qr : 1;
	unsigned int opcode : 4;
	unsigned int aa : 1;
	unsigned int tc : 1;
	unsigned int rd : 1;
	unsigned int ra : 1;
	unsigned int z : 3;
	unsigned int rcode : 4;
	unsigned int qdcount : 16;
	unsigned int ancount : 16;
	unsigned int nscount : 16;
	unsigned int arcount : 16;
};

int main() {
	// Flush after every std::cout / std::cerr
	std::cout << std::unitbuf;
	std::cerr << std::unitbuf;

	// Disable output buffering
	setbuf(stdout, NULL);

	// You can use print statements as follows for debugging, they'll be visible when running tests.
	std::cout << "Logs from your program will appear here!" << std::endl;

	int udpSocket;
	struct sockaddr_in clientAddress;

	udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if (udpSocket == -1) {
		std::cerr << "Socket creation failed: " << strerror(errno) << "..." << std::endl;
		return 1;
	}

	// Since the tester restarts your program quite often, setting REUSE_PORT
	// ensures that we don't run into 'Address already in use' errors
	int reuse = 1;
	if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
		std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
		return 1;
	}

	sockaddr_in serv_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(2053),
		.sin_addr = {htonl(INADDR_ANY)},
	};

	if (bind(udpSocket, reinterpret_cast<struct sockaddr *>(&serv_addr), sizeof(serv_addr)) != 0) {
		std::cerr << "Bind failed: " << strerror(errno) << std::endl;
		return 1;
	}

	int bytesRead;
	char buffer[512];
	socklen_t clientAddrLen = sizeof(clientAddress);

	header_struct h = {};
	while (true) {
		// Receive data
		bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr *>(&clientAddress), &clientAddrLen);
		if (bytesRead == -1) {
			perror("Error receiving data");
			break;
		}

		buffer[bytesRead] = '\0';
		std::cout << "Received " << bytesRead << " bytes: " << buffer << std::endl;

		int byte_count = 0;
		for (int i = 11; i < bytesRead; i++) {
			std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);

			std::cout << " ";

			byte_count++;
			if (byte_count % 16 == 0) {
				std::cout << std::endl;
			}
		}

		std::printf("\n");

		byte_count = 0;
		for (int i = 11; i < bytesRead; i++) {
			if (std::isprint(buffer[i])) {
				printf("%2c ", buffer[i]);
			} else {
				printf("%2c ", '.');
			}
			byte_count++;
			if (byte_count % 16 == 0) {
				std::printf("\n");
			}
		}

		std::printf("\n");

		memcpy(&h, buffer, 12);

		h.id = 1234;
		h.qr = 1;
		h.opcode = 0;
		h.aa = 0;
		h.tc = 0;
		h.rd = 0;
		h.ra = 0;
		h.z = 0;
		h.rcode = 0;
		h.qdcount = 0;
		h.ancount = 0;
		h.nscount = 0;
		h.arcount = 0;

		// Create an empty response
		char response[512];
		memcpy(response, &buffer, bytesRead);
		//memcpy(response, &h, 12);

		// Send response
		if (sendto(udpSocket, response, sizeof(response), 0, reinterpret_cast<struct sockaddr *>(&clientAddress), sizeof(clientAddress)) == -1) {
			perror("Failed to send response");
		}
	}

	close(udpSocket);

	return 0;
}
