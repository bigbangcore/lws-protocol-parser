#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "lwsiot.h"
#include "lws_proto_parser.h"

typedef struct _LwsClient {
    ClientType type;
    char device_id[DEVICE_ID_LEN];
    char lws[LWS_ID_LEN];

    char host[HOST_LEN];
    int port;
    char certs_path[CERT_PATH_MAX + 1];
    void *client;
    void *mutex;

    char service_reply_topic[TOPIC_LEN];
    char sync_reply_topic[TOPIC_LEN];
    char utxo_update_topic[TOPIC_LEN];
    char sendtx_reply_topic[TOPIC_LEN];

    char service_req_topic[TOPIC_LEN];
    char sync_req_topic[TOPIC_LEN];
    char utxo_abort_topic[TOPIC_LEN];
    char sendtx_req_topic[TOPIC_LEN];

    char device_req_topic[TOPIC_LEN];
    char device_reply_topic[TOPIC_LEN];

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
    pthread_mutex_t utxo_list_mutex;
    ArrayList *utxo_list;
    uint8_t service_reply_flag;
    uint8_t sync_reply_flag;
    uint32_t last_sync_time;

    uint32_t service_req_time;
    uint32_t sync_req_time;
    uint32_t send_tx_time;

    pthread_mutex_t recived_msg_mutex;
    pthread_mutex_t send_msg_mutex;
    uint32_t recived_msg_id;
    uint32_t send_msg_id;
    int32_t msg_id_array[128];

    pthread_mutex_t uuid_mutex;

    //struct _LwsClientDevice device;
}LwsClient;

static void lws_client_2_protocol(const LwsClient* client, LwsProtocol* proto)
{
    proto->address_id = client->address_id;
    memcpy((unsigned char*)(proto->api_keyseed), client->api_keyseed, 32);
    memcpy((unsigned char*)(proto->device_id), client->device_id, 100);
    memcpy((unsigned char*)(proto->fork), client->fork, 32);
    memcpy((unsigned char*)(proto->last_block_hash), client->last_block_hash, 32);
    proto->last_block_height = client->last_block_height;
    proto->last_block_time = client->last_block_time;
    proto->last_sync_time = client->last_sync_time;
    memcpy((unsigned char*)(proto->msg_id_array), client->msg_id_array, sizeof(int32_t)*128);
    proto->nonce = client->nonce;
    memcpy((unsigned char*)(proto->privkey_hex), client->privkey_hex, sizeof(char)*65);
    memcpy((unsigned char*)(proto->pubkey.pn), client->pubkey.pn, sizeof(uint32_t)*8);
    memcpy((unsigned char*)(proto->pubkey_hex), client->pubkey_hex, sizeof(char)*65);
    proto->recived_msg_id = client->recived_msg_id;
    memcpy((unsigned char*)(proto->secret.pn), client->secret.pn, sizeof(uint32_t)*8);
    proto->send_msg_id = client->send_msg_id;
    proto->send_tx_time = client->send_tx_time;
    proto->sendtx_nonce = client->sendtx_nonce;
    proto->service_reply_flag = client->service_reply_flag;
    proto->service_req_time = client->service_req_time;
    proto->sync_nonce = client->sync_nonce;
    proto->sync_reply_flag = client->sync_reply_flag;
    proto->sync_req_time = client->sync_req_time;
    proto->utxo_list = client->utxo_list;
}

static void lws_protocol_2_lws_client(const LwsProtocol* proto, LwsClient* client)
{
    client->address_id = proto->address_id;
    memcpy((unsigned char*)(client->api_keyseed), proto->api_keyseed, 32);
    memcpy((unsigned char*)(client->device_id), proto->device_id, 100);
    memcpy((unsigned char*)(client->fork), proto->fork, 32);
    memcpy((unsigned char*)(client->last_block_hash), proto->last_block_hash, 32);
    client->last_block_height = proto->last_block_height;
    client->last_block_time = proto->last_block_time;
    client->last_sync_time = proto->last_sync_time;
    memcpy((unsigned char*)(client->msg_id_array), proto->msg_id_array, sizeof(int32_t)*128);
    client->nonce = proto->nonce;
    memcpy((unsigned char*)(client->privkey_hex), proto->privkey_hex, sizeof(char)*65);
    memcpy((unsigned char*)(client->pubkey.pn), proto->pubkey.pn, sizeof(uint32_t)*8);
    memcpy((unsigned char*)(client->pubkey_hex), proto->pubkey_hex, sizeof(char)*65);
    client->recived_msg_id = proto->recived_msg_id;
    memcpy((unsigned char*)(client->secret.pn), proto->secret.pn, sizeof(uint32_t)*8);
    client->send_msg_id = proto->send_msg_id;
    client->send_tx_time = proto->send_tx_time;
    client->sendtx_nonce = proto->sendtx_nonce;
    client->service_reply_flag = proto->service_reply_flag;
    client->service_req_time = proto->service_req_time;
    client->sync_nonce = proto->sync_nonce;
    client->sync_reply_flag = proto->sync_reply_flag;
    client->sync_req_time = proto->sync_req_time;
    client->utxo_list = proto->utxo_list;
}

int main()
{
    printf("Test beging.\n");
    
    char *client_id = "lwc00";
    FILE *log_fp = fopen("./lwc.log", "a");
    LwsClient *lws_client = lwsiot_client_new(client_id, AwsClient, log_fp);
    
    if(lws_client == NULL)
    {
        printf("lws_client must be not equal to NULL");
        return -1;
    }

    char *fork = "0000000006854ebdc236f48dbbe5c87312ea0abd7398888374b5ee9a5eb1d291";
    LwsProtocol proto;
    lws_client_2_protocol(lws_client, &proto);
    set_lws_protocol_fork(&proto, fork);
    lwsiot_fork_set(lws_client, fork, LwsForkAdd);

    if(memcmp(proto.fork, lws_client->fork, 32) != 0)
    {
        printf("set_lws_protocol_fork test failed\n");
        return -1;
    }

    lws_protocol_2_lws_client(&proto, lws_client);
    if(memcmp(proto.fork, lws_client->fork, 32) != 0)
    {
        printf("lws_protocol_2_lws_client test failed\n");
        return -1;
    }

    if(test_lws_proto_parser(lws_client) != 0)
    {
        printf("test_lws_proto_parser test failed.\n");
        return -1;
    }

    printf("Test End.\n");
    return 0;
}