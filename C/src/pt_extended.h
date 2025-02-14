#ifndef PT_EXTENDED_H
#define PT_EXTENDED_H

#define PT_EXT_START_PACKET_SIZE 10

enum pt_extended_package_types {
        PT_EXTENDED_PACKAGE_TYPE_FIRST = 1,
        PT_EXTENDED_PACKAGE_TYPE_PAYLOAD = 2,
        PT_EXTENDED_PACKAGE_TYPE_LAST = 3,
        PT_EXTENDED_PACKAGE_TYPE_RESPONSE = 4,
};


struct pt_extended_package_start_package {
	uint8_t header;
	uint32_t full_payload_size;
	uint32_t payload_packet_payload_size;
	uint8_t bsd8_cs;
};


#endif