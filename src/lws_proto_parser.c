#include "lws_proto_parser.h"

#include <string.h>
#include <time.h>
#include <sodium.h>
#include <openssl/hmac.h>

#include "sharedkey.h"

typedef struct _Transaction {
    uint16_t version;
    uint16_t type;
    uint32_t timestamp;
    uint32_t lock_until;
    unsigned char hash_anchor[32];
    uint8_t size0;
    unsigned char *input;
    uint8_t prefix;
    unsigned char address[32];
    uint64_t amount;
    uint64_t tx_fee;
    uint8_t size1;
    unsigned char *vch_data;
    uint8_t size2;
    unsigned char sign[64];
} Transaction;

struct ServiceReq {
    uint16_t nonce;
    uint8_t prefix;
    unsigned char address[32];
    uint32_t version;
    uint32_t timestamp;
    uint8_t fork_num;
    unsigned char *fork_list;
    uint16_t reply_utxo;
    uint8_t *topic_prefix;
    uint16_t sign_size;
    unsigned char sign[64];
    uint256_t key[2];
};

struct ServiceReply {
    uint16_t nonce;
    uint32_t version;
    uint8_t error;
    uint32_t address_id;
    unsigned char fork_bitmap[8];
    unsigned char api_keyseed[32];
};

struct SyncReq {
    uint16_t nonce;
    uint32_t address_id;
    unsigned char fork_id[32];
    unsigned char utxo_hash[32];
    unsigned char signature[20];
};

struct SyncReply {
    uint16_t nonce;
    uint8_t error;
    unsigned char block_hash[32];
    uint32_t block_height;
    uint32_t block_time;
    uint16_t utxo_num;
    ArrayList *utxo_list;
    uint8_t continue_flag;
};

struct UTXO {
    unsigned char txid[32];
    uint8_t out;
    uint32_t block_height;
    uint16_t type;
    uint64_t amount;
    unsigned char sender[33];
    uint32_t lock_until;
    uint16_t data_size;
    unsigned char *data;
    uint64_t new_amount;
    int is_used;
};

struct UTXOIndex {
    unsigned char txid[32];
    uint8_t out;
};

struct UTXOUpdateItem {
    uint8_t op_type;
    struct UTXOIndex index;
    uint32_t blocke_height;
    struct UTXO new_utxo;
};

struct UTXOUpdate {
    uint16_t nonce;
    uint32_t address_id;
    unsigned char fork_id[32];
    unsigned char block_hash[32];
    uint32_t block_height;
    uint32_t block_time;
    uint16_t update_num;
    ArrayList *update_list;
    uint8_t continue_flag;
};

struct UTXOAbort {
    uint16_t nonce;
    uint32_t address_id;
    uint8_t reason;
    unsigned char signature[20];
};

struct SendTxReq {
    uint16_t nonce;
    uint32_t address_id;
    unsigned char fork_id[32];
    uint8_t *tx_data;
    unsigned char signature[20];
};

struct SendTxReply {
    uint16_t nonce;
    uint8_t error;
    uint8_t err_code;
    unsigned char txid[64];
    char *err_desc;
};

static void hex_to_uchar(const char *hex, unsigned char *out)
{
    size_t len = strlen(hex);
    size_t final_len = len / 2;
    size_t i, j;
    for (i = 0, j = 0; j < final_len; i += 2, j++) {
        out[j] = (unsigned char)((hex[i] % 32 + 9) % 25 * 16 + (hex[i + 1] % 32 + 9) % 25);
    }
}

static unsigned int lwsiot_rand()
{
    unsigned int seed;
    //struct timeb time_buf;
    //ftime(&time_buf);
    //seed = ((((unsigned int)time_buf.time & 0xFFFF) + (unsigned int)time_buf.millitm) ^ (unsigned int)time_buf.millitm);
    srand((unsigned int)seed);
    unsigned int ret = rand();
    return ret;
}

void set_lws_protocol_fork(LwsProtocol* proto, const char* fork_hex)
{
    memset(proto->fork, 0, 32);
    hex_to_uchar(fork_hex, proto->fork);
}

static struct ServiceReq create_service_req(const LwsProtocol *proto)
{
    struct ServiceReq service_req;
    memset(&service_req, 0x00, sizeof(struct ServiceReq));
    // service_req.nonce = lws_client_rand();
    service_req.nonce = proto->nonce;
    service_req.prefix = 1;
    memcpy(service_req.address, &proto->pubkey, 32);
    service_req.version = 1;
    time_t now_time;
    time(&now_time);
    service_req.timestamp = now_time;
    service_req.fork_num = 1;
    // warning
    service_req.fork_list = (unsigned char*)(&proto->fork[0]);
    service_req.reply_utxo = 0;
    // warning
    service_req.topic_prefix = (uint8_t*)(&proto->device_id[0]);
    service_req.key[0] = proto->secret;
    service_req.key[1] = proto->pubkey;

    return service_req;
}

static size_t serialize_join(size_t *size, void *thing, size_t size_thing, unsigned char *data)
{
    memcpy(data + *size, thing, size_thing);
    *size += size_thing;
    return *size;
}

static size_t service_req_serialize(struct ServiceReq *req, unsigned char *data)
{
    size_t size = 0;
    size_t size_thing = sizeof(req->nonce);
    serialize_join(&size, &req->nonce, size_thing, data);

    size_thing = sizeof(req->prefix);
    serialize_join(&size, &req->prefix, size_thing, data);

    size_thing = sizeof(req->address);
    serialize_join(&size, &req->address, size_thing, data);

    size_thing = sizeof(req->version);
    serialize_join(&size, &req->version, size_thing, data);

    size_thing = sizeof(req->timestamp);
    serialize_join(&size, &req->timestamp, size_thing, data);

    size_thing = sizeof(req->fork_num);
    serialize_join(&size, &req->fork_num, size_thing, data);

    size_thing = sizeof(unsigned char) * 32;
    serialize_join(&size, req->fork_list, size_thing, data);

    size_thing = sizeof(req->reply_utxo);
    serialize_join(&size, &req->reply_utxo, size_thing, data);

    size_thing = strlen(req->topic_prefix) + 1;
    serialize_join(&size, req->topic_prefix, size_thing, data);

    unsigned char hash[32] = {0};
    unsigned char buff[64] = {0};
    crypto_generichash_blake2b(hash, sizeof(hash), data, size, NULL, 0);
    crypto_sign_ed25519_detached(buff, NULL, hash, sizeof(hash), (uint8_t *)&req->key[0]);
    req->sign_size = sizeof(buff);

    size_thing = sizeof(req->sign_size);
    serialize_join(&size, &req->sign_size, size_thing, data);

    size_thing = sizeof(buff);
    serialize_join(&size, buff, size_thing, data);

    return size;
}

size_t serialize_service_request(const LwsProtocol* proto, unsigned char* data)
{
    struct ServiceReq service_req = create_service_req(proto);
    return service_req_serialize(&service_req, data);
}

static size_t deserialize_join(size_t *size, unsigned char *data, void *thing, size_t size_thing)
{
    memcpy(thing, data + *size, size_thing);
    *size += size_thing;

    return *size;
}

static struct ServiceReply service_reply_deserialize(unsigned char *data)
{
    struct ServiceReply service_reply;
    size_t size = 0;
    size_t size_thing = sizeof(service_reply.nonce);
    deserialize_join(&size, data, &service_reply.nonce, size_thing);

    size_thing = sizeof(service_reply.version);
    deserialize_join(&size, data, &service_reply.version, size_thing);

    size_thing = sizeof(service_reply.error);
    deserialize_join(&size, data, &service_reply.error, size_thing);

    size_thing = sizeof(service_reply.address_id);
    deserialize_join(&size, data, &service_reply.address_id, size_thing);

    size_thing = sizeof(service_reply.fork_bitmap);
    deserialize_join(&size, data, service_reply.fork_bitmap, size_thing);

    size_thing = sizeof(service_reply.api_keyseed);
    deserialize_join(&size, data, service_reply.api_keyseed, size_thing);

    return service_reply;
}

void deserialize_service_reply(const unsigned char* data, ServiceReply* reply)
{
    struct ServiceReply service_reply = service_reply_deserialize((unsigned char*)data);
    *reply = service_reply;
}

static void utxo_hash(ArrayList *array_list, unsigned char *hash)
{
    if (!array_list) {
        return;
    }

   // pthread_mutex_lock(mutex);

    size_t len = array_list->length;
    if (0 >= len) {
        //pthread_mutex_unlock(mutex);
        return;
    }

    int data_size = len * (32 + sizeof(uint8_t) + sizeof(uint32_t));
    uint8_t *data = malloc(data_size);

    size_t size = 0;

    int i;
    for (i = 0; i < len; i++) {
        struct UTXO *utxo = array_list->data[i];

        size_t size_thing = sizeof(utxo->txid);
        serialize_join(&size, utxo->txid, size_thing, data);

        size_thing = sizeof(utxo->out);
        serialize_join(&size, &utxo->out, size_thing, data);

        size_thing = sizeof(utxo->block_height);
        serialize_join(&size, &utxo->block_height, size_thing, data);
    }

    crypto_generichash_blake2b(hash, 32, data, size, NULL, 0);
    free(data);

  //  pthread_mutex_unlock(mutex);

    return;
}


static struct SyncReq create_sync_req(LwsProtocol* proto, struct ServiceReply *service_reply)
{
    struct SyncReq sync_req;
    memset(&sync_req, 0x00, sizeof(struct SyncReq));
    // sync_req.nonce = service_reply->nonce;
    sync_req.nonce = lwsiot_rand();
    // sync_req.nonce = 1234;
    proto->sync_nonce = sync_req.nonce;
    sync_req.address_id = service_reply->address_id;
    memcpy(sync_req.fork_id, proto->fork, sizeof(proto->fork));

    unsigned char data[100] = {'\0'};
    size_t size = 0;
    size_t size_thing = sizeof(sync_req.nonce);
    serialize_join(&size, &sync_req.nonce, size_thing, data);

    size_thing = sizeof(sync_req.address_id);
    serialize_join(&size, &sync_req.address_id, size_thing, data);

    size_thing = sizeof(sync_req.fork_id);
    serialize_join(&size, &sync_req.fork_id, size_thing, data);

    // utxo_hash
    utxo_hash(proto->utxo_list, sync_req.utxo_hash);

    size_thing = sizeof(sync_req.utxo_hash);
    serialize_join(&size, &sync_req.utxo_hash, size_thing, data);

    // signature
    unsigned char sig_buff[20] = {'\0'};
    char api_seed_hex[65] = {'\0'};
    unsigned char api_key[32] = {'\0'};

    uint256_t api_seed;
    memcpy(&api_seed, service_reply->api_keyseed, sizeof(uint256_t));
    uint256_get_hex(&api_seed, api_seed_hex);

    shared(proto->privkey_hex, api_seed_hex, api_key);
    HMAC(EVP_ripemd160(), api_key, sizeof(api_key), data, size, sig_buff, NULL);

    memcpy(sync_req.signature, sig_buff, sizeof(sig_buff));

    return sync_req;
}

static size_t sync_req_serialize(struct SyncReq *req, unsigned char *data)
{
    size_t size = 0;
    size_t size_thing = sizeof(req->nonce);
    serialize_join(&size, &req->nonce, size_thing, data);

    size_thing = sizeof(req->address_id);
    serialize_join(&size, &req->address_id, size_thing, data);

    size_thing = sizeof(req->fork_id);
    serialize_join(&size, &req->fork_id, size_thing, data);

    size_thing = sizeof(req->utxo_hash);
    serialize_join(&size, &req->utxo_hash, size_thing, data);

    size_thing = sizeof(req->signature);
    serialize_join(&size, &req->signature, size_thing, data);

    return size;
}


size_t serialize_sync_request(const LwsProtocol* proto, unsigned char* data)
{
    struct ServiceReply reply;
    reply.address_id = proto->address_id;
    memcpy(reply.api_keyseed, proto->api_keyseed, sizeof(reply.api_keyseed));

    struct SyncReq req = create_sync_req((LwsProtocol*)proto, &reply);
    return sync_req_serialize(&req, data);
}

static struct SyncReply sync_reply_deserialize(unsigned char *data)
{
    struct SyncReply sync_reply;
    sync_reply.utxo_list = arraylist_new(0);
    size_t size = 0;
    size_t size_thing = sizeof(sync_reply.nonce);
    deserialize_join(&size, data, &sync_reply.nonce, size_thing);

    size_thing = sizeof(sync_reply.error);
    deserialize_join(&size, data, &sync_reply.error, size_thing);

    if (sync_reply.error > 1) {
        return sync_reply;
    }

    size_thing = sizeof(sync_reply.block_hash);
    deserialize_join(&size, data, &sync_reply.block_hash, size_thing);

    size_thing = sizeof(sync_reply.block_height);
    deserialize_join(&size, data, &sync_reply.block_height, size_thing);

    size_thing = sizeof(sync_reply.block_time);
    deserialize_join(&size, data, &sync_reply.block_time, size_thing);

    size_thing = sizeof(sync_reply.utxo_num);
    deserialize_join(&size, data, &sync_reply.utxo_num, size_thing);

    // UTXOList
    int i;
    for (i = 0; i < sync_reply.utxo_num; i++) {
        struct UTXO *utxo = malloc(sizeof(struct UTXO));

        size_thing = sizeof(utxo->txid);
        deserialize_join(&size, data, utxo->txid, size_thing);

        size_thing = sizeof(utxo->out);
        deserialize_join(&size, data, &utxo->out, size_thing);

        size_thing = sizeof(utxo->block_height);
        deserialize_join(&size, data, &utxo->block_height, size_thing);

        size_thing = sizeof(utxo->type);
        deserialize_join(&size, data, &utxo->type, size_thing);

        size_thing = sizeof(utxo->amount);
        deserialize_join(&size, data, &utxo->amount, size_thing);

        size_thing = sizeof(utxo->sender);
        deserialize_join(&size, data, utxo->sender, size_thing);

        size_thing = sizeof(utxo->lock_until);
        deserialize_join(&size, data, &utxo->lock_until, size_thing);

        size_thing = sizeof(utxo->data_size);
        deserialize_join(&size, data, &utxo->data_size, size_thing);

        size_thing = utxo->data_size;
        unsigned char *d = malloc(sizeof(unsigned char) * size_thing);
        deserialize_join(&size, data, d, size_thing);

        utxo->data = d;

        arraylist_append(sync_reply.utxo_list, utxo);
    }

    size_thing = sizeof(sync_reply.continue_flag);
    deserialize_join(&size, data, &sync_reply.continue_flag, size_thing);

    return sync_reply;
}

void deserialize_sync_reply(const unsigned char* data, SyncReply* reply)
{
    struct SyncReply sync_reply = sync_reply_deserialize((unsigned char*)data);
    *reply = sync_reply;
}


static size_t tx_serialize_without_sign(Transaction *tx, unsigned char *data)
{
    size_t size = 0;
    size_t size_thing = sizeof(tx->version);
    serialize_join(&size, &tx->version, size_thing, data);

    size_thing = sizeof(tx->type);
    serialize_join(&size, &tx->type, size_thing, data);

    size_thing = sizeof(tx->timestamp);
    serialize_join(&size, &tx->timestamp, size_thing, data);

    size_thing = sizeof(tx->lock_until);
    serialize_join(&size, &tx->lock_until, size_thing, data);

    size_thing = sizeof(tx->hash_anchor);
    serialize_join(&size, tx->hash_anchor, size_thing, data);

    size_thing = sizeof(tx->size0);
    serialize_join(&size, &tx->size0, size_thing, data);

    size_thing = (sizeof(unsigned char) * (32 + 1)) * tx->size0;
    serialize_join(&size, tx->input, size_thing, data);

    size_thing = sizeof(tx->prefix);
    serialize_join(&size, &tx->prefix, size_thing, data);

    size_thing = sizeof(tx->address);
    serialize_join(&size, tx->address, size_thing, data);

    size_thing = sizeof(tx->amount);
    serialize_join(&size, &tx->amount, size_thing, data);

    size_thing = sizeof(tx->tx_fee);
    serialize_join(&size, &tx->tx_fee, size_thing, data);

    size_thing = sizeof(tx->size1);
    serialize_join(&size, &tx->size1, size_thing, data);

    size_thing = tx->size1;
    serialize_join(&size, tx->vch_data, size_thing, data);

    return size;
}

static size_t sendtx_req_serialize_without_sign(struct SendTxReq *req, size_t len, unsigned char *data)
{
    size_t size = 0;
    size_t size_thing = sizeof(req->nonce);
    serialize_join(&size, &req->nonce, size_thing, data);

    size_thing = sizeof(req->address_id);
    serialize_join(&size, &req->address_id, size_thing, data);

    size_thing = sizeof(req->fork_id);
    serialize_join(&size, req->fork_id, size_thing, data);

    size_thing = len;
    serialize_join(&size, req->tx_data, size_thing, data);

    return size;
}

static struct SendTxReq create_sendtx_req(LwsProtocol *proto, unsigned char *tx_data, size_t len)
{
    struct SendTxReq sendtx_req;
    memset(&sendtx_req, 0x00, sizeof(struct SendTxReq));

    //sendtx_req.nonce = lwsiot_rand();
    sendtx_req.nonce = 1234;
    proto->sendtx_nonce = sendtx_req.nonce;

    sendtx_req.address_id = proto->address_id;

    memcpy(sendtx_req.fork_id, proto->fork, sizeof(proto->fork));

    sendtx_req.tx_data = tx_data;

    unsigned char data[4096];
    size_t size = sendtx_req_serialize_without_sign(&sendtx_req, len, data);

    // signature
    unsigned char sign[20] = {'\0'};
    char api_seed_hex[65] = {'\0'};
    unsigned char api_key[32] = {'\0'};

    uint256_t api_seed;
    memcpy(&api_seed, proto->api_keyseed, sizeof(uint256_t));
    uint256_get_hex(&api_seed, api_seed_hex);

    shared(proto->privkey_hex, api_seed_hex, api_key);
    HMAC(EVP_ripemd160(), api_key, sizeof(api_key), data, size, sign, NULL);

    memcpy(sendtx_req.signature, sign, sizeof(sign));

    return sendtx_req;
}



static size_t tx_serialize(Transaction *tx, unsigned char *data)
{
    size_t size = tx_serialize_without_sign(tx, data);

    size_t size_thing = sizeof(tx->size2);
    serialize_join(&size, &tx->size2, size_thing, data);

    size_thing = tx->size2;
    serialize_join(&size, tx->sign, size_thing, data);

    return size;
}

static size_t sendtx_req_serialize(struct SendTxReq *req, size_t tx_data_len, unsigned char *data)
{
    size_t size = sendtx_req_serialize_without_sign(req, tx_data_len, data);
    size_t size_thing = sizeof(req->signature);
    serialize_join(&size, req->signature, size_thing, data);

    return size;
}

size_t serialize_sendtx_request(const LwsProtocol* proto, const Transaction* tx, unsigned char* data, uint16_t *nonce)
{
    unsigned char tx_data[4096];
    size_t size_tx = tx_serialize((Transaction*)tx, tx_data);

    struct SendTxReq req = create_sendtx_req((LwsProtocol*)proto, tx_data, size_tx);
    *nonce = req.nonce;
    return sendtx_req_serialize(&req, size_tx, data);
}

static struct SendTxReply sendtx_reply_deserialize(unsigned char *data)
{
    struct SendTxReply sendtx_reply;
    size_t size = 0;
    size_t size_thing = sizeof(sendtx_reply.nonce);
    deserialize_join(&size, data, &sendtx_reply.nonce, size_thing);

    size_thing = sizeof(sendtx_reply.error);
    deserialize_join(&size, data, &sendtx_reply.error, size_thing);

    size_thing = sizeof(sendtx_reply.err_code);
    deserialize_join(&size, data, &sendtx_reply.err_code, size_thing);

    size_thing = sizeof(sendtx_reply.txid);
    deserialize_join(&size, data, sendtx_reply.txid, size_thing);

    size_t str_len = strlen(data + size);
    char *str = malloc(str_len + 1);
    memset(str, 0x00, str_len + 1);
    strncpy(str, data + size, str_len);
    sendtx_reply.err_desc = str;
    // TODO: memory leak

    return sendtx_reply;
}


void deserialize_sendtx_reply(const unsigned char* data, SendTxReply* reply)
{
    struct SendTxReply sendtx_reply = sendtx_reply_deserialize((unsigned char*)data);
    *reply = sendtx_reply;
}

