#ifndef LWS_PROTO_PARSER_H
#define LWS_PROTO_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <arraylist.h>
#include "uint256.h"

#define CERT_PATH_MAX 4096
#define DEVICE_ID_LEN 100
#define LWS_ID_LEN 100
#define HOST_LEN 100
#define TOPIC_LEN 256
#define SERVICE_REQ_INV 5
#define SYNC_INV 60

typedef struct _LwsProtocol {
    char device_id[DEVICE_ID_LEN];
    
    unsigned char fork[32];
    char privkey_hex[65];
    char pubkey_hex[65];
    uint256_t secret;
    uint256_t pubkey;
    uint16_t nonce;
    unsigned char api_keyseed[32];
    uint32_t address_id;

    unsigned char last_block_hash[32];
    uint32_t last_block_height;
    uint32_t last_block_time;

    uint16_t sync_nonce;
    uint16_t sendtx_nonce;
    
    ArrayList *utxo_list;
    uint8_t service_reply_flag;
    uint8_t sync_reply_flag;
    uint32_t last_sync_time;

    uint32_t service_req_time;
    uint32_t sync_req_time;
    uint32_t send_tx_time;

    
    uint32_t recived_msg_id;
    uint32_t send_msg_id;
    int32_t msg_id_array[128];    
}LwsProtocol;

typedef struct _LwsClient LwsClient;
typedef struct _Transaction Transaction;
typedef struct ServiceReply ServiceReply;
typedef struct SyncReply SyncReply;
typedef struct SendTxReply SendTxReply;


void set_lws_protocol_fork(LwsProtocol* proto, const char* fork_hex);

size_t serialize_service_request(const LwsProtocol* proto, unsigned char* data);
void deserialize_service_reply(const unsigned char* data, ServiceReply* reply);

size_t serialize_sync_request(const LwsProtocol* proto, unsigned char* data);
void deserialize_sync_reply(const unsigned char* data, SyncReply* reply);

size_t serialize_sendtx_request(const LwsProtocol* proto, const Transaction* tx, unsigned char* data, uint16_t *nonce);
void deserialize_sendtx_reply(const unsigned char* data, SendTxReply* reply);

#ifdef __cplusplus
}
#endif

#endif