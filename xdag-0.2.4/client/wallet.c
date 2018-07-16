/* кошелёк, T13.681-T13.788 $DVS:time$ */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "crypt.h"
#include "wallet.h"
#include "init.h"
#include "transport.h"
#include "utils/log.h"
#include "utils/utils.h"

#define WALLET_FILE (g_xdag_testnet ? "wallet-testnet.dat" : "wallet.dat")
//钱包内部数据模型
struct key_internal {
	xdag_hash_t pub, priv;
    // void *任意类型 存储EC_KEY
	void *key;
    // prev 保存前一默认秘钥
	struct key_internal *prev;
	uint8_t pub_bit; // 奇偶性
};

// 默认钱包
static struct key_internal *def_key = 0;
// 公钥数组
static struct xdag_public_key *keys_arr = 0;
// 钱包文件同步锁
static pthread_mutex_t wallet_mutex = PTHREAD_MUTEX_INITIALIZER;
int nkeys = 0, maxnkeys = 0;
// 根据私钥创建钱包文件，0：创建新
static int add_key(xdag_hash_t priv)
{
	struct key_internal *k = malloc(sizeof(struct key_internal));

	if (!k) return -1;
    // 加锁
	pthread_mutex_lock(&wallet_mutex);
    // 传入私钥
	if (priv) {
		memcpy(k->priv, priv, sizeof(xdag_hash_t));
        // 通过已知私钥生成k->priv参数有值
		k->key = xdag_private_to_key(k->priv, k->pub, &k->pub_bit);
	} else {
		FILE *f;
		uint32_t priv32[sizeof(xdag_hash_t) / sizeof(uint32_t)];
        // 创建新秘钥，参数均未赋值
		k->key = xdag_create_key(k->priv, k->pub, &k->pub_bit);
		// a以附加方式打开只写文件，文件存在添加内容在末尾，不存在则新建文件
		f = xdag_open_file(WALLET_FILE, "ab");
        // 打开秘钥文件失败
		if (!f) goto fail;
		
		memcpy(priv32, k->priv, sizeof(xdag_hash_t));
		// 1加密私钥
		xdag_user_crypt_action(priv32, nkeys, sizeof(xdag_hash_t) / sizeof(uint32_t), 1);
		// 将加密后的私钥写入钱包文件，返回实际写入的数据项个数，传入的是1
		if (fwrite(priv32, sizeof(xdag_hash_t), 1, f) != 1) {
            // 写入私钥失败
			xdag_close_file(f);
			goto fail;
		}

		xdag_close_file(f);
	}

	if (!k->key) goto fail;
	// prev 保存前一默认秘钥
	k->prev = def_key;
    // 设置默认秘钥
	def_key = k;
	// nkeys序号  maxnKeys总秘钥数
	if (nkeys == maxnkeys) {
        // 重新分配内存，扩大keys_arr所占空间，增加一个用来存储新的xdag_public_key，成功返回新内存地址，失败返回NULL
        // | 0xff 高地址位置0，保留低8位数，主要用来做数据类型转换时保持二进制数据一致性（补码）
		struct xdag_public_key *newarr = (struct xdag_public_key *)
			realloc(keys_arr, ((maxnkeys | 0xff) + 1) * sizeof(struct xdag_public_key));
		if (!newarr) goto fail;
		
		maxnkeys |= 0xff;
		maxnkeys++;
		keys_arr = newarr;
	}

	keys_arr[nkeys].key = k->key;
	keys_arr[nkeys].pub = (uint64_t*)((uintptr_t)&k->pub | k->pub_bit);

	xdag_debug("Key %2d: priv=[%s] pub=[%02x:%s]", nkeys,
					xdag_log_hash(k->priv), 0x02 + k->pub_bit,  xdag_log_hash(k->pub));
	
	nkeys++;
	
	pthread_mutex_unlock(&wallet_mutex);
	
	return 0;
 
fail:
	pthread_mutex_unlock(&wallet_mutex);
	free(k);
	return -1;
}

/* generates a new key and sets is as defauld, returns its index */
int xdag_wallet_new_key(void)
{
	int res = add_key(0);

	if (!res)
		res = nkeys - 1;

	return res;
}
/* imports a new key and sets is as defauld, returns its index */
int xdag_wallet_import_key(xdag_hash_t hash){
    int res = add_key(hash);
    
    if (!res) {
        res =nkeys -1;
    }
    return res;
}

/* initializes a wallet */
int xdag_wallet_init(void)
{
	uint32_t priv32[sizeof(xdag_hash_t) / sizeof(uint32_t)];
	xdag_hash_t priv;
    // b二进制文件方式打开（以文本打开的文件，在Windows下写入换行时会默认加换行符），r只读，文件必须存在，不存在返回NULL
	FILE *f = xdag_open_file(WALLET_FILE, "rb");
	int n;
    
	if (!f) {
        // 不存在钱包文件，新建钱包文件创建私钥
		if (add_key(0)) return -1;
		
		f = xdag_open_file(WALLET_FILE, "r");
		if (!f) return -1;
		// 重复调用？
		fread(priv32, sizeof(xdag_hash_t), 1, f);
		
		n = 1;
	} else {
		n = 0;
	}

	while (fread(priv32, sizeof(xdag_hash_t), 1, f) == 1) {
        // 解密私钥
		xdag_user_crypt_action(priv32, n++, sizeof(xdag_hash_t) / sizeof(uint32_t), 2);
		memcpy(priv, priv32, sizeof(xdag_hash_t));
		add_key(priv);
	}

	xdag_close_file(f);
	
	return 0;
}

/* returns a default key, the index of the default key is written to *n_key */
struct xdag_public_key *xdag_wallet_default_key(int *n_key)
{
	if (nkeys) {
		if (n_key) {
			*n_key = nkeys - 1;
			return keys_arr + nkeys - 1;
		}
	}

	return 0;
}

/* returns an array of our keys */
struct xdag_public_key *xdag_wallet_our_keys(int *pnkeys)
{
	*pnkeys = nkeys;

	return keys_arr;
}

/* completes work with wallet */
void xdag_wallet_finish(void)
{
	pthread_mutex_lock(&wallet_mutex);
}
