struct Beacon {
    unsigned char type;
    unsigned short uuid;
    unsigned short data_length;
    //char * data;
    char data[];
} __attribute__((packed));

struct Task {
    unsigned char type;
    unsigned short data_length;
    char data[];
} __attribute__((packed));

// Message Types
#define BEACON_PING     0x0
#define BEACON_DATA     0x1

// Task Types
#define TASK_CLI        0x0
#define TASK_PYTHON     0x1

// Message formats
#define FORMAT_PLAIN    0x0
#define FORMAT_BASE64   0x1

