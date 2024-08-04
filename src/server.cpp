#include <cctype>
#include <cstdint>
#include <cstring>
#include <ios>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#define PORT 2053

// https://en.cppreference.com/w/cpp/language/bit_field
struct __attribute__((packed)) header_struct {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;

	bool isQuery() const {
		return (flags >> 15) & 0x1;
	}

	void setQuery(bool isQuery) {
		if (isQuery) {
			flags |= (0x1 << 15);
		} else {
			flags &= ~(0x1 << 15);
		}
	}

	uint8_t getOpcode() const {
		return (flags >> 11) & 0xF;
	}

	void setOpcode(uint8_t opcode) {
		flags &= 0xF8FF;			   // Clear the 4 bits for OPCODE field
		flags |= (opcode & 0xF) << 11; // Set the 4 bits for OPCODE field
	}

	bool isAuthoritative() const {
		return (flags >> 10) & 0x1;
	}

	void setAuthoritative(bool isAuthoritative) {
		if (isAuthoritative) {
			flags |= (0x1 << 10);
		} else {
			flags &= ~(0x1 << 10);
		}
	}

	bool isTruncated() const {
		return (flags >> 9) & 0x1;
	}

	void setTruncated(bool isTruncated) {
		if (isTruncated) {
			flags |= (0x1 << 9);
		} else {
			flags &= ~(0x1 << 9);
		}
	}

	bool isRecursionDesired() const {
		return (flags >> 8) & 0x1;
	}

	void setRecursionDesired(bool recursionDesired) {
		if (recursionDesired) {
			flags |= (0x1 << 8);
		} else {
			flags &= ~(0x1 << 8);
		}
	}

	bool isRecursionAvailable() const {
		return (flags >> 7) & 0x1;
	}

	void setRecursionAvailable(bool recursionAvailable) {
		if (recursionAvailable) {
			flags |= (0x1 << 7);
		} else {
			flags &= ~(0x1 << 7);
		}
	}

	uint8_t getReserved() const {
		return (flags >> 4) & 0x7;
	}

	void setReserved(uint8_t zField) {
		flags &= 0xFF8F;			  // Clear the 3 bits for Z field
		flags |= (zField & 0x7) << 4; // Set the 3 bits for Z field
	}

	uint8_t getRcode() const {
		return flags & 0xF;
	}

	void setRcode(uint8_t rcode) {
		flags &= 0xFFF0;	  // Clear the 4 bits for RCODE field
		flags |= rcode & 0xF; // Set the 4 bits for RCODE field
	}
};

struct __attribute__((packed)) question_struct {
	char name[512];
	uint16_t type;
	uint16_t _class;
};

struct __attribute__((packed)) answer_struct {
	char name[512];
	uint16_t type;
	uint16_t _class;
	uint32_t ttl;
	uint16_t length;
	char data[512];
};

typedef uint16_t (*byte_order_conversion_func)(uint16_t);

header_struct convert_struct_byte_order(const header_struct &struct_with_network_byte_order, byte_order_conversion_func conversion_func) {
	header_struct struct_with_host_byte_order;
	struct_with_host_byte_order = struct_with_network_byte_order;
	struct_with_host_byte_order.id = conversion_func(struct_with_network_byte_order.id);
	struct_with_host_byte_order.flags = conversion_func(struct_with_network_byte_order.flags);
	struct_with_host_byte_order.qdcount = conversion_func(struct_with_network_byte_order.qdcount);
	struct_with_host_byte_order.ancount = conversion_func(struct_with_network_byte_order.ancount);
	struct_with_host_byte_order.nscount = conversion_func(struct_with_network_byte_order.nscount);
	struct_with_host_byte_order.arcount = conversion_func(struct_with_network_byte_order.arcount);

	return struct_with_host_byte_order;
}

void print_header_struct(const header_struct &hs) {
	// used Wiresark to determine that ID uses a different byte order than my system
	// this applies to all uint16_t fields
	std::cout << "id: " << ntohs(hs.id) << std::endl;
	std::cout << "qr: " << ((hs.flags >> 15) & 0x1) << std::endl;
	std::cout << "opcode: " << ((hs.flags >> 11) & 0xF) << std::endl;
	std::cout << "aa: " << ((hs.flags >> 10) & 0x1) << std::endl;
	std::cout << "tc: " << ((hs.flags >> 9) & 0x1) << std::endl;
	std::cout << "rd: " << ((hs.flags >> 8) & 0x1) << std::endl;
	std::cout << "ra: " << ((hs.flags >> 7) & 0x1) << std::endl;
	std::cout << "z: " << ((hs.flags >> 4) & 0x7) << std::endl;
	std::cout << "rcode: " << (hs.flags & 0xF) << std::endl;
	std::cout << "qdcount: " << ntohs(hs.qdcount) << std::endl;
	std::cout << "ancount: " << ntohs(hs.ancount) << std::endl;
	std::cout << "nscount: " << ntohs(hs.nscount) << std::endl;
	std::cout << "arcount: " << ntohs(hs.arcount) << std::endl;
}

void print_hex(std::string var_name, void *request, int bytesRead) {

	int byte_count = 0;

	printf("%s:\n↓\n", var_name.c_str());

	for (int i = 0; i < bytesRead; i++) {
		std::printf("%02x ", static_cast<unsigned char>(((char *)request)[i]));

		byte_count++;
		if (byte_count % 16 == 0 && bytesRead > 16) {
			std::cout << std::endl;
		}
	}

	std::printf("\n↑\n");
}
void print_message(std::string name, char *request, int bytesRead) {
	print_hex(name, request, bytesRead);

	std::printf("%s (ASCII):\n↓\n", name.c_str());

	int byte_count = 0;
	for (int i = 0; i < bytesRead; i++) {
		if (std::isprint(request[i])) {
			printf("%2c ", request[i]);
		} else {
			printf("%2c ", '.');
		}
		byte_count++;
		if (byte_count % 16 == 0) {
			std::printf("\n");
		}
	}

	std::printf("\n↑\n");
}

void add_question_section(const char *question, header_struct &h_h, char *response, int &responseSize, int &questionLength) {
	// putting the hex code in the string without additional quotes results in this warning and results in the wrong value being stored:
	// warning: hex escape sequence out of range
	// Cf. https://www.unix.com/programming/149172-how-use-hex-escape-char-string-c.html

	question_struct request_question;

	question_struct q = {};
	strcpy(q.name, question);

	// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
	std::unordered_map<std::string, uint16_t> typeToValue = {
		{"A", 1},
		{"NS", 2},
		{"MD", 3},
		{"MF", 4},
		{"CNAME", 5},
		{"SOA", 6},
		{"MB", 7},
		{"MG", 8},
		{"MR", 9},
		{"NULL", 10},
		{"WKS", 11},
		{"PTR", 12},
		{"HINFO", 13},
		{"MINFO", 14},
		{"MX", 15},
		{"TXT", 16}};
	uint16_t numeric_type = typeToValue["A"];
	q.type = htons(numeric_type);
	// class should always be 1
	// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
	q._class = htons((uint16_t)1);

	print_hex("q.type", &q.type, 2);
	print_hex("q._class", &q._class, 2);

	h_h.qdcount = 1;
	print_header_struct(h_h);

	// add 1 for the null terminator to fix this error
	// ;; Warning: Message parser reports malformed message packet.
	// ;; Got answer:
	// ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48552
	// ;; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
	// ;; WARNING: Message has 3 extra bytes at end
	memcpy(response + sizeof(header_struct), q.name, strlen(q.name) + 1);
	memcpy(response + sizeof(header_struct) + strlen(q.name) + 1, &q.type, sizeof(q.type));
	memcpy(response + sizeof(header_struct) + strlen(q.name) + 1 + 2, &q._class, sizeof(q._class));

	questionLength = strlen(q.name) + 1 + sizeof(q.type) + sizeof(q._class);
	responseSize += questionLength;
	print_hex("question", response + sizeof(header_struct), questionLength);
}

void print_map(const std::map<int, std::string> &map) {
	for (auto &entry : map) {
		std::cout << entry.first << ": " << entry.second << ", len " << entry.second.length() << std::endl;
	}
}

std::map<int, std::string> found_labels_to_compression_dict(const std::map<int, std::string> &found_labels) {

	std::map<int, std::string> compression_dict = found_labels;

	print_map(compression_dict);
	printf("exapnding entries\n");

	bool compression_entry_complete = false;
	for (auto &entry : compression_dict) {
		std::cout << entry.first << ": " << entry.second << ", len " << entry.second.length() << std::endl;
		compression_entry_complete = false;
		while (!compression_entry_complete) {
			printf("checking if label at index %d can be expanded further\n", entry.first);
			int next_label_idx = entry.first + compression_dict[entry.first].length();
			if (compression_dict.find(next_label_idx) != compression_dict.end()) {
				printf("yes\n");
				// https://www.geeksforgeeks.org/how-to-convert-a-single-character-to-string-in-cpp/

				compression_dict[entry.first] = entry.second + compression_dict[next_label_idx];
				print_hex("", (void *)compression_dict[entry.first].c_str(), compression_dict[entry.first].length());
			} else {
				printf("no\n");
				compression_entry_complete = true;
			}
			print_map(compression_dict);
		}
	}

	return compression_dict;
}

std::vector<std::vector<char>> extract_questions(char *questions, int questions_buffer_size) {
	printf("extract_questions()\n");
	std::vector<std::vector<char>> questions_list;
	std::string name_so_far = "";
	char current_label[512];
	int label_length = 0;
	bool done_extracting_names = false;
	uint8_t octet;
	int name_length = 0;
	enum enum_name_label_or_pointer { label,
									  pointer };
	bool currently_constructing_name_from_labels = true;
	enum_name_label_or_pointer name_label_or_pointer;
	// map is used to access previous labels referenced by pointers used for compression
	std::map<int, std::string> found_labels;
	std::map<int, std::string> compression_dict;

	for (int q_byte_idx = 0; q_byte_idx < questions_buffer_size; q_byte_idx++) {
		octet = questions[q_byte_idx];
		if (octet == 0 && currently_constructing_name_from_labels) {
			// The domain name terminates with the
			// zero length octet for the null label of the root.
			// https://www.rfc-editor.org/rfc/rfc1035#section-4.1.2

			printf("✓ extraction of name complete\n");
			printf("extracted name: %s\n", name_so_far.c_str());
			print_hex("extracted name", (void *)name_so_far.c_str(), name_so_far.length());

			std::vector<char> complete_name;
			for (int i = 0; i < name_so_far.length(); i++) {
				complete_name.push_back(name_so_far[i]);
			}
			questions_list.push_back(complete_name);

			q_byte_idx += 4;
			currently_constructing_name_from_labels = false;
			name_so_far = "";
			continue;
		}
		printf("\nbyte: 0x%02x\n", octet);

		if (octet != 0) {
			if ((0b11000000 & octet) == 0) {
				// label must begin with two zero bits
				// https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
				printf("this is a label\n");
				currently_constructing_name_from_labels = true;
				label_length = octet;
				name_label_or_pointer = label;
				printf("found label of length %d\n", octet);
				// ensure the c string in current_label ends with 0x0
				for (int i = 0; i < 512; i++) {
					current_label[i] = 0;
				}
				memcpy(current_label, &questions[q_byte_idx], 1 + label_length);
				current_label[1 + label_length] = 0;
				printf("current label: %s\n", current_label);
				found_labels.insert({q_byte_idx + 12, std::string(current_label)});

				name_so_far += std::string(current_label);

				q_byte_idx += label_length;

				printf("extracted name so far: %s\n", name_so_far.c_str());
				print_hex("extracted name so far", (void *)name_so_far.c_str(), name_so_far.length());
			} else if (((0b10000000 & octet) != 0) && ((0b01000000 & octet) != 0)) {
				// pointer must begin with two one bits
				// https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
				printf("this is a pointer\n");
				uint8_t first_offset_byte = questions[q_byte_idx] & 0b00111111;
				uint8_t second_offset_byte = questions[q_byte_idx + 1];

				uint16_t offset = 0;

				offset |= ((uint16_t)first_offset_byte) << 8; // Shift first_offset_byte to the left by 8 bits
				offset |= (uint16_t)second_offset_byte;		  // Perform a bitwise OR with second_offset_byte

				printf("the pointer has an offset of %d bytes from the start of the entire message\n", offset);

				compression_dict = found_labels_to_compression_dict(found_labels);

				// Print all entries in the map
				printf("found these labels so far:\n");
				print_map(found_labels);

				printf("resulting in this compression dict:\n");
				print_map(compression_dict);

				if (compression_dict.find(offset) != compression_dict.end()) {
					std::string found_label = compression_dict[offset];
					printf("found referenced label: %s\n", found_label.c_str());
					//name_so_far += questions[offset - 12]; // append the label length
					name_so_far += found_label;
					// The pointer takes the form of a two octet sequence
					// https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
					// c0 10 00 01 00 01 00
					// p1 p2 x0 type  class
					q_byte_idx += 6;
				} else {
					printf("didn't find referenced label at offset %d\n", offset);
				}
			}
		} else {
			printf("octet is 0x00, end of names reached\n");
			break;
		}
	}

	return questions_list;
}

void add_answer_section(std::string question, header_struct &h_h, char *response, int &responseSize, int &questionLength, header_struct &h_n) {
	answer_struct a = {};
	strncpy(a.name, question.c_str(),
			512);
	a.type = htons((uint16_t)1);
	a._class = htons((uint16_t)1);
	a.ttl = htons((uint32_t)60);
	a.length = htons((uint16_t)4);
	memcpy(a.data, "\x08"
				   "\x08"
				   "\x08"
				   "\x08",
		   4);

	printf("name in answer: %s\n", a.name);

	int answerLength = strlen(a.name) + 1 + sizeof(a.type) + sizeof(a._class) + sizeof(a.ttl) + sizeof(a.length) + 4;
	responseSize += answerLength;

	// this is necessary since the name car array is bigger tan te actual string
	memcpy(response + sizeof(header_struct) + questionLength, a.name, strlen(a.name) + 1);
	memcpy(response + sizeof(header_struct) + questionLength + strlen(a.name) + 1, &a.type, sizeof(a.type));
	memcpy(response + sizeof(header_struct) + questionLength + strlen(a.name) + 1 + sizeof(a.type), &a._class, sizeof(a._class));
	memcpy(response + sizeof(header_struct) + questionLength + strlen(a.name) + 1 + sizeof(a.type) + sizeof(a._class), &a.ttl, sizeof(a.ttl));
	memcpy(response + sizeof(header_struct) + questionLength + strlen(a.name) + 1 + sizeof(a.type) + sizeof(a._class) + sizeof(a.ttl), &a.length, sizeof(a.length));
	memcpy(response + sizeof(header_struct) + questionLength + strlen(a.name) + 1 + sizeof(a.type) + sizeof(a._class) + sizeof(a.ttl) + sizeof(a.length), &a.data, 4);

	h_h.ancount += 1;
	// header was updated and needs to copied into the response again

	h_n = convert_struct_byte_order(h_h, htons);
	memcpy(response, &h_n, sizeof(header_struct));
}

int main() {
	// Flush after every std::cout / std::cerr
	std::cout << std::unitbuf;
	std::cerr << std::unitbuf;

	// Disable output buffering
	setbuf(stdout, nullptr);

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
	if (int reuse = 1; setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
		std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
		return 1;
	}

	sockaddr_in serv_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(PORT),
		.sin_addr = {htonl(INADDR_ANY)},
	};
	if (
		bind(udpSocket, reinterpret_cast<struct sockaddr *>(&serv_addr), sizeof(serv_addr)) != 0) {
		std::cerr << "Bind failed: " << strerror(errno) << std::endl;
		return 1;
	}

	std::cout << "Bound port: " << ntohs(serv_addr.sin_port) << std::endl;

	int bytesRead;
	char request[512];
	char response[512];
	socklen_t clientAddrLen = sizeof(clientAddress);

	header_struct h_n = {};
	header_struct h_h = {};
	while (true) {
		int responseSize = sizeof(header_struct);

		std::printf("↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓\n");

		// Receive data
		bytesRead = recvfrom(udpSocket, request, sizeof(request), 0, reinterpret_cast<struct sockaddr *>(&clientAddress), &clientAddrLen);
		if (bytesRead == -1) {
			perror("Error receiving data");
			break;
		}

		uint16_t source_port = ntohs(reinterpret_cast<struct sockaddr_in *>(&clientAddress)->sin_port);
		uint16_t destination_port = htons(2053);

		request[bytesRead] = '\0';
		std::cout << "Received UDP packet with " << bytesRead << " bytes" << std::endl;

		print_message("request", request, bytesRead);

		// Copy request to create response
		memcpy(response, request, bytesRead);

		int questionLength = 0;

		bool answer_section_enabled = true;
		bool question_section_enabled = true || answer_section_enabled;
		bool add_header_section = true || question_section_enabled;

		if (add_header_section) {
			memcpy(&h_n, request, sizeof(header_struct));

			h_h = convert_struct_byte_order(h_n, ntohs);

			print_header_struct(h_h);
			h_h.setQuery(true);
			h_h.setReserved(0);
			if (h_h.getOpcode() == 0) {
				h_h.setRcode(0);
			} else {
				h_h.setRcode(4);
			}

#ifdef DEBUG
			h_h.qdcount = 44;
			h_h.ancount = 55;
			h_h.nscount = 66;
			h_h.arcount = 77;
#endif

			h_n = convert_struct_byte_order(h_h, htons);
			memcpy(response, &h_n, sizeof(header_struct));
		}

		char questions[512];
		memcpy(&questions, request + 12, sizeof(request) - 12);

		print_hex("questions", questions, sizeof(request) - 12);

		printf("request contains the following questions:\n");
		std::vector<std::vector<char>> questions_list = extract_questions(questions, sizeof(request) - 12);
		if (question_section_enabled) {
			for (std::vector<char> question_char_vec : questions_list) {
				std::string question(question_char_vec.begin(), question_char_vec.end());
				print_hex("adding question", (void *)question.c_str(), question.length());
				add_question_section(question.c_str(), h_h, response, responseSize, questionLength);
			}
		}

		if (answer_section_enabled) {
			for (std::vector<char> question_char_vec : questions_list) {
				std::string question(question_char_vec.begin(), question_char_vec.end());
				print_hex("adding answer to question", (void *)question.c_str(), question.length());
				add_answer_section(question, h_h, response, responseSize, questionLength, h_n);
			}
		}

		print_message("response", response, responseSize);

		// Send response
		if (sendto(udpSocket, &response, responseSize, 0, reinterpret_cast<struct sockaddr *>(&clientAddress), sizeof(clientAddress)) == -1) {
			perror("Failed to send response");
		}

		std::printf("↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑\n");
	}

	close(udpSocket);

	return 0;
}
