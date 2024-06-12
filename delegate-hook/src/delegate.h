#ifndef DELEGATE_INCLUDED
#define DELEGATE_INCLUDED 1

#include "../lib/hookapi.h"

#define ASSERT(cond) \
    if (!(cond))     \
        rollback(SBUF(__FILE__), __LINE__);

#define PERMIT() \
    accept(SBUF(__FILE__), __LINE__);

#define SVAR(x) \
    &(x), sizeof(x)

#define COPY_BYTE(lhsbuf, rhsbuf) \
    *(uint8_t *)(lhsbuf) = *(uint8_t *)(rhsbuf);

#define COPY_2BYTES(lhsbuf, rhsbuf) \
    *(uint16_t *)(lhsbuf) = *(uint16_t *)(rhsbuf);

#define COPY_4BYTES(lhsbuf, rhsbuf) \
    *(uint32_t *)(lhsbuf) = *(uint32_t *)(rhsbuf);

#define COPY_8BYTES(lhsbuf, rhsbuf) \
    *(uint64_t *)(lhsbuf) = *(uint64_t *)(rhsbuf);

#define BUFFER_EQUAL_1(buf1, buf2) \
    (*(uint8_t *)(buf1) == *(uint8_t *)(buf2))

#define BUFFER_EQUAL_2(buf1, buf2) \
    (*(uint16_t *)(buf1) == *(uint16_t *)(buf2))

#define BUFFER_EQUAL_4(buf1, buf2) \
    (*(uint32_t *)(buf1) == *(uint32_t *)(buf2))

#define BUFFER_EQUAL_8(buf1, buf2) \
    (*(uint64_t *)(buf1) == *(uint64_t *)(buf2))

#define COPY_16BYTES(lhsbuf, rhsbuf) \
    COPY_8BYTES(lhsbuf, rhsbuf);     \
    COPY_8BYTES((lhsbuf + 8), (rhsbuf + 8));

#define COPY_20BYTES(lhsbuf, rhsbuf)         \
    COPY_8BYTES(lhsbuf, rhsbuf);             \
    COPY_8BYTES((lhsbuf + 8), (rhsbuf + 8)); \
    COPY_4BYTES((lhsbuf + 16), (rhsbuf + 16));

#define COPY_32BYTES(lhsbuf, rhsbuf)           \
    COPY_8BYTES(lhsbuf, rhsbuf);               \
    COPY_8BYTES((lhsbuf + 8), (rhsbuf + 8));   \
    COPY_8BYTES((lhsbuf + 16), (rhsbuf + 16)); \
    COPY_8BYTES((lhsbuf + 24), (rhsbuf + 24));

uint8_t STP_HOST_ID[32] = {'E', 'V', 'R', 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

#define HOST_ID_KEY(host_account_id)                        \
    COPY_8BYTES((STP_HOST_ID + 12), (host_account_id));     \
    COPY_8BYTES((STP_HOST_ID + 20), (host_account_id + 8)); \
    COPY_4BYTES((STP_HOST_ID + 28), (host_account_id + 16));

#define MAX_EVENT_TYPE_SIZE 40
#define MAX_HOOK_PARAM_SIZE 256 // Maximum txn param length.
#define HASH_SIZE 32

// Events
#define REPUTATION_CONTRACT_INFO_UPDATE "evnRepConInfoUpdate"

#define EQUAL_REPUTATION_CONTRACT_INFO_UPDATE(buf, len)                    \
    (sizeof(REPUTATION_CONTRACT_INFO_UPDATE) == (len + 1) &&               \
     BUFFER_EQUAL_8(buf, REPUTATION_CONTRACT_INFO_UPDATE) &&               \
     BUFFER_EQUAL_8((buf + 8), (REPUTATION_CONTRACT_INFO_UPDATE + 8)) &&   \
     BUFFER_EQUAL_2((buf + 16), (REPUTATION_CONTRACT_INFO_UPDATE + 16)) && \
     BUFFER_EQUAL_1((buf + 18), (REPUTATION_CONTRACT_INFO_UPDATE + 18)))

const uint8_t PARAM_EVENT_TYPE_KEY[32] = {'E', 'V', 'R', 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
const uint8_t PARAM_EVENT_DATA_KEY[32] = {'E', 'V', 'R', 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3};

const uint32_t HOST_ID_VAL_SIZE = 43;

// HOST_ADDR
const uint32_t PUBKEY_OFFEST = 0;
const uint32_t PEER_PORT_OFFEST = 33;
const uint32_t MOMENT_OFFSET = 35;

#endif