#include <linux/init.h>
#include <linux/ratelimit.h>
#include <linux/signal.h>
#include <linux/kernel.h>
#include <linux/module.h>
// sha256 hash functions for extracted page content 
#include <crypto/hash.h>

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

static int calc_hash(struct crypto_shash *alg,
             const unsigned char *data, unsigned int datalen,
             unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

static int do_sha256(const unsigned char *data, unsigned char *out_digest)
{
    struct crypto_shash *alg;
    char *hash_alg_name = "sha256";
    unsigned int datalen = sizeof(data) - 1; // remove the null byte

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if(IS_ERR(alg)){
        pr_info("can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(alg);
    }
    calc_hash(alg, data, datalen, out_digest);

    // Very dirty print of 8 first bytes for comparaison with sha256sum
    printk(KERN_INFO "HASH(%s, %i): %02x%02x%02x%02x%02x%02x%02x%02x\n",
          data, datalen, out_digest[0], out_digest[1], out_digest[2], out_digest[3], out_digest[4], 
          out_digest[5], out_digest[6], out_digest[7]);

    crypto_free_shash(alg);
    return 0;
}

static int __init SHA256Hash_init(void) {
    printk(KERN_INFO "HASH: Start kernel hash test.\n");
    unsigned char *digest;
    digest = kmalloc(256, GFP_KERNEL);
    // devm_kzalloc(digest, 256, GFP_KERNEL); // auto free memory after use.
    if(digest < 0)
        return 1;

    do_sha256("Test start string", digest);
    return 0;
}

static void __exit SHA256Hash_exit(void) {
    printk(KERN_INFO "HASH: End kernel hash test.\n");
    unsigned char *digest;
    digest = kmalloc(256, GFP_KERNEL);
    // devm_kzalloc(digest, 256, GFP_KERNEL); // auto free memory after use.
    if(digest < 0)
        return 1;

    do_sha256("Test end string", digest);
    return 0;
}

module_init(SHA256Hash_init);
module_exit(SHA256Hash_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yanjing Ren");