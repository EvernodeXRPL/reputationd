
/**
 * Delegate - Reputation related delegate hook for an Evernode Host.
 * This Hook will be triggered upon ttACCOUNT_SET Txn once this is considered as 1:M delegate account.
 * 
 * State:
 *   [host registration account id : 20b] => [public_key: 33b, peer_port : 2b, moment: 8b]
 */

#include "delegate.h"

int64_t hook(uint32_t reserved)
{

    int64_t txn_type = otxn_type();

    uint8_t event_type[MAX_EVENT_TYPE_SIZE];
    const int64_t event_type_len = otxn_param(SBUF(event_type), SBUF(PARAM_EVENT_TYPE_KEY));

    // Hook param analysis
    uint8_t event_data[MAX_HOOK_PARAM_SIZE];
    const int64_t event_data_len = otxn_param(SBUF(event_data), SBUF(PARAM_EVENT_DATA_KEY));

    if (event_type_len == DOESNT_EXIST || !EQUAL_REPUTATION_CONTRACT_INFO_UPDATE(event_type, event_type_len))
    {
        // PERMIT_MSG >> Transaction is not handled.
        PERMIT();
    }

    HOST_ID_KEY(event_data);

    uint8_t contract_info[HOST_ID_VAL_SIZE];
    COPY_32BYTES((contract_info + PUBKEY_OFFEST), (event_data + 20));
    COPY_BYTE((contract_info + 32), (event_data + 52));
    COPY_2BYTES((contract_info + PEER_PORT_OFFEST), (event_data + 53));
    COPY_8BYTES((contract_info + MOMENT_OFFSET), (event_data + 55));

    state_set(SBUF(contract_info), SBUF(STP_HOST_ID));

    PERMIT();

    _g(1, 1); // every hook needs to import guard function and use it at least once
    // unreachable
    return 0;
}