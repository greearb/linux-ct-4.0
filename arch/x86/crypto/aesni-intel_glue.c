/*
 * Support for Intel AES-NI instructions. This file contains glue
 * code, the real AES implementation is in intel-aes_asm.S.
 *
 * Copyright (C) 2008, Intel Corp.
 *    Author: Huang Ying <ying.huang@intel.com>
 *
 * Added RFC4106 AES-GCM support for 128-bit keys under the AEAD
 * interface for 64-bit kernels.
 *    Authors: Adrian Hoban <adrian.hoban@intel.com>
 *             Gabriele Paoloni <gabriele.paoloni@intel.com>
 *             Tadeusz Struk (tadeusz.struk@intel.com)
 *             Aidan O'Mahony (aidan.o.mahony@intel.com)
 *    Copyright (c) 2010, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/hardirq.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/module.h>
#include <linux/err.h>
#include <crypto/algapi.h>
#include <crypto/aes.h>
#include <crypto/cryptd.h>
#include <crypto/ctr.h>
#include <crypto/b128ops.h>
#include <crypto/lrw.h>
#include <crypto/xts.h>
#include <asm/cpu_device_id.h>
#include <asm/i387.h>
#include <asm/crypto/aes.h>
#include <crypto/ablk_helper.h>
#include <crypto/scatterwalk.h>
#include <crypto/aead.h>
#include <crypto/internal/aead.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#ifdef CONFIG_X86_64
#include <asm/crypto/glue_helper.h>
#endif


/* This data is stored at the end of the crypto_tfm struct.
 * It's a type of per "session" data storage location.
 * This needs to be 16 byte aligned.
 */
struct aesni_rfc4106_gcm_ctx {
	u8 hash_subkey[16];
	struct crypto_aes_ctx aes_key_expanded;
	u8 nonce[4];
	struct cryptd_aead *cryptd_tfm;
};

struct aesni_gcm_set_hash_subkey_result {
	int err;
	struct completion completion;
};

struct aesni_hash_subkey_req_data {
	u8 iv[16];
	struct aesni_gcm_set_hash_subkey_result result;
	struct scatterlist sg;
};

#define AESNI_ALIGN	(16)
#define AES_BLOCK_MASK	(~(AES_BLOCK_SIZE-1))
#define RFC4106_HASH_SUBKEY_SIZE 16

struct aesni_lrw_ctx {
	struct lrw_table_ctx lrw_table;
	u8 raw_aes_ctx[sizeof(struct crypto_aes_ctx) + AESNI_ALIGN - 1];
};

struct aesni_xts_ctx {
	u8 raw_tweak_ctx[sizeof(struct crypto_aes_ctx) + AESNI_ALIGN - 1];
	u8 raw_crypt_ctx[sizeof(struct crypto_aes_ctx) + AESNI_ALIGN - 1];
};

asmlinkage int aesni_set_key(struct crypto_aes_ctx *ctx, const u8 *in_key,
			     unsigned int key_len);
asmlinkage void aesni_enc(struct crypto_aes_ctx *ctx, u8 *out,
			  const u8 *in);
asmlinkage void aesni_dec(struct crypto_aes_ctx *ctx, u8 *out,
			  const u8 *in);
asmlinkage void aesni_ecb_enc(struct crypto_aes_ctx *ctx, u8 *out,
			      const u8 *in, unsigned int len);
asmlinkage void aesni_ecb_dec(struct crypto_aes_ctx *ctx, u8 *out,
			      const u8 *in, unsigned int len);
asmlinkage void aesni_cbc_enc(struct crypto_aes_ctx *ctx, u8 *out,
			      const u8 *in, unsigned int len, u8 *iv);
asmlinkage void aesni_cbc_dec(struct crypto_aes_ctx *ctx, u8 *out,
			      const u8 *in, unsigned int len, u8 *iv);

int crypto_fpu_init(void);
void crypto_fpu_exit(void);

#define AVX_GEN2_OPTSIZE 640
#define AVX_GEN4_OPTSIZE 4096

#ifdef CONFIG_X86_64

static void (*aesni_ctr_enc_tfm)(struct crypto_aes_ctx *ctx, u8 *out,
			      const u8 *in, unsigned int len, u8 *iv);
asmlinkage void aesni_ctr_enc(struct crypto_aes_ctx *ctx, u8 *out,
			      const u8 *in, unsigned int len, u8 *iv);

asmlinkage void aesni_xts_crypt8(struct crypto_aes_ctx *ctx, u8 *out,
				 const u8 *in, bool enc, u8 *iv);

/* asmlinkage void aesni_gcm_enc()
 * void *ctx,  AES Key schedule. Starts on a 16 byte boundary.
 * u8 *out, Ciphertext output. Encrypt in-place is allowed.
 * const u8 *in, Plaintext input
 * unsigned long plaintext_len, Length of data in bytes for encryption.
 * u8 *iv, Pre-counter block j0: 4 byte salt (from Security Association)
 *         concatenated with 8 byte Initialisation Vector (from IPSec ESP
 *         Payload) concatenated with 0x00000001. 16-byte aligned pointer.
 * u8 *hash_subkey, the Hash sub key input. Data starts on a 16-byte boundary.
 * const u8 *aad, Additional Authentication Data (AAD)
 * unsigned long aad_len, Length of AAD in bytes. With RFC4106 this
 *          is going to be 8 or 12 bytes
 * u8 *auth_tag, Authenticated Tag output.
 * unsigned long auth_tag_len), Authenticated Tag Length in bytes.
 *          Valid values are 16 (most likely), 12 or 8.
 */
asmlinkage void aesni_gcm_enc(void *ctx, u8 *out,
			const u8 *in, unsigned long plaintext_len, u8 *iv,
			u8 *hash_subkey, const u8 *aad, unsigned long aad_len,
			u8 *auth_tag, unsigned long auth_tag_len);

/* asmlinkage void aesni_gcm_dec()
 * void *ctx, AES Key schedule. Starts on a 16 byte boundary.
 * u8 *out, Plaintext output. Decrypt in-place is allowed.
 * const u8 *in, Ciphertext input
 * unsigned long ciphertext_len, Length of data in bytes for decryption.
 * u8 *iv, Pre-counter block j0: 4 byte salt (from Security Association)
 *         concatenated with 8 byte Initialisation Vector (from IPSec ESP
 *         Payload) concatenated with 0x00000001. 16-byte aligned pointer.
 * u8 *hash_subkey, the Hash sub key input. Data starts on a 16-byte boundary.
 * const u8 *aad, Additional Authentication Data (AAD)
 * unsigned long aad_len, Length of AAD in bytes. With RFC4106 this is going
 * to be 8 or 12 bytes
 * u8 *auth_tag, Authenticated Tag output.
 * unsigned long auth_tag_len) Authenticated Tag Length in bytes.
 * Valid values are 16 (most likely), 12 or 8.
 */
asmlinkage void aesni_gcm_dec(void *ctx, u8 *out,
			const u8 *in, unsigned long ciphertext_len, u8 *iv,
			u8 *hash_subkey, const u8 *aad, unsigned long aad_len,
			u8 *auth_tag, unsigned long auth_tag_len);


#ifdef CONFIG_AS_AVX
asmlinkage void aes_ctr_enc_128_avx_by8(const u8 *in, u8 *iv,
		void *keys, u8 *out, unsigned int num_bytes);
asmlinkage void aes_ctr_enc_192_avx_by8(const u8 *in, u8 *iv,
		void *keys, u8 *out, unsigned int num_bytes);
asmlinkage void aes_ctr_enc_256_avx_by8(const u8 *in, u8 *iv,
		void *keys, u8 *out, unsigned int num_bytes);
/*
 * asmlinkage void aesni_gcm_precomp_avx_gen2()
 * gcm_data *my_ctx_data, context data
 * u8 *hash_subkey,  the Hash sub key input. Data starts on a 16-byte boundary.
 */
asmlinkage void aesni_gcm_precomp_avx_gen2(void *my_ctx_data, u8 *hash_subkey);

asmlinkage void aesni_gcm_enc_avx_gen2(void *ctx, u8 *out,
			const u8 *in, unsigned long plaintext_len, u8 *iv,
			const u8 *aad, unsigned long aad_len,
			u8 *auth_tag, unsigned long auth_tag_len);

asmlinkage void aesni_gcm_dec_avx_gen2(void *ctx, u8 *out,
			const u8 *in, unsigned long ciphertext_len, u8 *iv,
			const u8 *aad, unsigned long aad_len,
			u8 *auth_tag, unsigned long auth_tag_len);

static void aesni_gcm_enc_avx(void *ctx, u8 *out,
			const u8 *in, unsigned long plaintext_len, u8 *iv,
			u8 *hash_subkey, const u8 *aad, unsigned long aad_len,
			u8 *auth_tag, unsigned long auth_tag_len)
{
        struct crypto_aes_ctx *aes_ctx = (struct crypto_aes_ctx*)ctx;
	if ((plaintext_len < AVX_GEN2_OPTSIZE) || (aes_ctx-> key_length != AES_KEYSIZE_128)){
		aesni_gcm_enc(ctx, out, in, plaintext_len, iv, hash_subkey, aad,
				aad_len, auth_tag, auth_tag_len);
	} else {
		aesni_gcm_precomp_avx_gen2(ctx, hash_subkey);
		aesni_gcm_enc_avx_gen2(ctx, out, in, plaintext_len, iv, aad,
					aad_len, auth_tag, auth_tag_len);
	}
}

static void aesni_gcm_dec_avx(void *ctx, u8 *out,
			const u8 *in, unsigned long ciphertext_len, u8 *iv,
			u8 *hash_subkey, const u8 *aad, unsigned long aad_len,
			u8 *auth_tag, unsigned long auth_tag_len)
{
        struct crypto_aes_ctx *aes_ctx = (struct crypto_aes_ctx*)ctx;
	if ((ciphertext_len < AVX_GEN2_OPTSIZE) || (aes_ctx-> key_length != AES_KEYSIZE_128)) {
		aesni_gcm_dec(ctx, out, in, ciphertext_len, iv, hash_subkey, aad,
				aad_len, auth_tag, auth_tag_len);
	} else {
		aesni_gcm_precomp_avx_gen2(ctx, hash_subkey);
		aesni_gcm_dec_avx_gen2(ctx, out, in, ciphertext_len, iv, aad,
					aad_len, auth_tag, auth_tag_len);
	}
}
#endif

#ifdef CONFIG_AS_AVX2
/*
 * asmlinkage void aesni_gcm_precomp_avx_gen4()
 * gcm_data *my_ctx_data, context data
 * u8 *hash_subkey,  the Hash sub key input. Data starts on a 16-byte boundary.
 */
asmlinkage void aesni_gcm_precomp_avx_gen4(void *my_ctx_data, u8 *hash_subkey);

asmlinkage void aesni_gcm_enc_avx_gen4(void *ctx, u8 *out,
			const u8 *in, unsigned long plaintext_len, u8 *iv,
			const u8 *aad, unsigned long aad_len,
			u8 *auth_tag, unsigned long auth_tag_len);

asmlinkage void aesni_gcm_dec_avx_gen4(void *ctx, u8 *out,
			const u8 *in, unsigned long ciphertext_len, u8 *iv,
			const u8 *aad, unsigned long aad_len,
			u8 *auth_tag, unsigned long auth_tag_len);

static void aesni_gcm_enc_avx2(void *ctx, u8 *out,
			const u8 *in, unsigned long plaintext_len, u8 *iv,
			u8 *hash_subkey, const u8 *aad, unsigned long aad_len,
			u8 *auth_tag, unsigned long auth_tag_len)
{
       struct crypto_aes_ctx *aes_ctx = (struct crypto_aes_ctx*)ctx;
	if ((plaintext_len < AVX_GEN2_OPTSIZE) || (aes_ctx-> key_length != AES_KEYSIZE_128)) {
		aesni_gcm_enc(ctx, out, in, plaintext_len, iv, hash_subkey, aad,
				aad_len, auth_tag, auth_tag_len);
	} else if (plaintext_len < AVX_GEN4_OPTSIZE) {
		aesni_gcm_precomp_avx_gen2(ctx, hash_subkey);
		aesni_gcm_enc_avx_gen2(ctx, out, in, plaintext_len, iv, aad,
					aad_len, auth_tag, auth_tag_len);
	} else {
		aesni_gcm_precomp_avx_gen4(ctx, hash_subkey);
		aesni_gcm_enc_avx_gen4(ctx, out, in, plaintext_len, iv, aad,
					aad_len, auth_tag, auth_tag_len);
	}
}

static void aesni_gcm_dec_avx2(void *ctx, u8 *out,
			const u8 *in, unsigned long ciphertext_len, u8 *iv,
			u8 *hash_subkey, const u8 *aad, unsigned long aad_len,
			u8 *auth_tag, unsigned long auth_tag_len)
{
       struct crypto_aes_ctx *aes_ctx = (struct crypto_aes_ctx*)ctx;
	if ((ciphertext_len < AVX_GEN2_OPTSIZE) || (aes_ctx-> key_length != AES_KEYSIZE_128)) {
		aesni_gcm_dec(ctx, out, in, ciphertext_len, iv, hash_subkey,
				aad, aad_len, auth_tag, auth_tag_len);
	} else if (ciphertext_len < AVX_GEN4_OPTSIZE) {
		aesni_gcm_precomp_avx_gen2(ctx, hash_subkey);
		aesni_gcm_dec_avx_gen2(ctx, out, in, ciphertext_len, iv, aad,
					aad_len, auth_tag, auth_tag_len);
	} else {
		aesni_gcm_precomp_avx_gen4(ctx, hash_subkey);
		aesni_gcm_dec_avx_gen4(ctx, out, in, ciphertext_len, iv, aad,
					aad_len, auth_tag, auth_tag_len);
	}
}
#endif

static void (*aesni_gcm_enc_tfm)(void *ctx, u8 *out,
			const u8 *in, unsigned long plaintext_len, u8 *iv,
			u8 *hash_subkey, const u8 *aad, unsigned long aad_len,
			u8 *auth_tag, unsigned long auth_tag_len);

static void (*aesni_gcm_dec_tfm)(void *ctx, u8 *out,
			const u8 *in, unsigned long ciphertext_len, u8 *iv,
			u8 *hash_subkey, const u8 *aad, unsigned long aad_len,
			u8 *auth_tag, unsigned long auth_tag_len);

static inline struct
aesni_rfc4106_gcm_ctx *aesni_rfc4106_gcm_ctx_get(struct crypto_aead *tfm)
{
	return
		(struct aesni_rfc4106_gcm_ctx *)
		PTR_ALIGN((u8 *)
		crypto_tfm_ctx(crypto_aead_tfm(tfm)), AESNI_ALIGN);
}
#endif

static inline struct crypto_aes_ctx *aes_ctx(void *raw_ctx)
{
	unsigned long addr = (unsigned long)raw_ctx;
	unsigned long align = AESNI_ALIGN;

	if (align <= crypto_tfm_ctx_alignment())
		align = 1;
	return (struct crypto_aes_ctx *)ALIGN(addr, align);
}

static int aes_set_key_common(struct crypto_tfm *tfm, void *raw_ctx,
			      const u8 *in_key, unsigned int key_len)
{
	struct crypto_aes_ctx *ctx = aes_ctx(raw_ctx);
	u32 *flags = &tfm->crt_flags;
	int err;

	if (key_len != AES_KEYSIZE_128 && key_len != AES_KEYSIZE_192 &&
	    key_len != AES_KEYSIZE_256) {
		*flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}

	if (!irq_fpu_usable())
		err = crypto_aes_expand_key(ctx, in_key, key_len);
	else {
		kernel_fpu_begin();
		err = aesni_set_key(ctx, in_key, key_len);
		kernel_fpu_end();
	}

	return err;
}

static int aes_set_key(struct crypto_tfm *tfm, const u8 *in_key,
		       unsigned int key_len)
{
	return aes_set_key_common(tfm, crypto_tfm_ctx(tfm), in_key, key_len);
}

static void aes_encrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	struct crypto_aes_ctx *ctx = aes_ctx(crypto_tfm_ctx(tfm));

	if (!irq_fpu_usable())
		crypto_aes_encrypt_x86(ctx, dst, src);
	else {
		kernel_fpu_begin();
		aesni_enc(ctx, dst, src);
		kernel_fpu_end();
	}
}

static void aes_decrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	struct crypto_aes_ctx *ctx = aes_ctx(crypto_tfm_ctx(tfm));

	if (!irq_fpu_usable())
		crypto_aes_decrypt_x86(ctx, dst, src);
	else {
		kernel_fpu_begin();
		aesni_dec(ctx, dst, src);
		kernel_fpu_end();
	}
}

static void __aes_encrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	struct crypto_aes_ctx *ctx = aes_ctx(crypto_tfm_ctx(tfm));

	aesni_enc(ctx, dst, src);
}

static void __aes_decrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	struct crypto_aes_ctx *ctx = aes_ctx(crypto_tfm_ctx(tfm));

	aesni_dec(ctx, dst, src);
}

static int ecb_encrypt(struct blkcipher_desc *desc,
		       struct scatterlist *dst, struct scatterlist *src,
		       unsigned int nbytes)
{
	struct crypto_aes_ctx *ctx = aes_ctx(crypto_blkcipher_ctx(desc->tfm));
	struct blkcipher_walk walk;
	int err;

	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_virt(desc, &walk);
	desc->flags &= ~CRYPTO_TFM_REQ_MAY_SLEEP;

	kernel_fpu_begin();
	while ((nbytes = walk.nbytes)) {
		aesni_ecb_enc(ctx, walk.dst.virt.addr, walk.src.virt.addr,
			      nbytes & AES_BLOCK_MASK);
		nbytes &= AES_BLOCK_SIZE - 1;
		err = blkcipher_walk_done(desc, &walk, nbytes);
	}
	kernel_fpu_end();

	return err;
}

static int ecb_decrypt(struct blkcipher_desc *desc,
		       struct scatterlist *dst, struct scatterlist *src,
		       unsigned int nbytes)
{
	struct crypto_aes_ctx *ctx = aes_ctx(crypto_blkcipher_ctx(desc->tfm));
	struct blkcipher_walk walk;
	int err;

	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_virt(desc, &walk);
	desc->flags &= ~CRYPTO_TFM_REQ_MAY_SLEEP;

	kernel_fpu_begin();
	while ((nbytes = walk.nbytes)) {
		aesni_ecb_dec(ctx, walk.dst.virt.addr, walk.src.virt.addr,
			      nbytes & AES_BLOCK_MASK);
		nbytes &= AES_BLOCK_SIZE - 1;
		err = blkcipher_walk_done(desc, &walk, nbytes);
	}
	kernel_fpu_end();

	return err;
}

static int cbc_encrypt(struct blkcipher_desc *desc,
		       struct scatterlist *dst, struct scatterlist *src,
		       unsigned int nbytes)
{
	struct crypto_aes_ctx *ctx = aes_ctx(crypto_blkcipher_ctx(desc->tfm));
	struct blkcipher_walk walk;
	int err;

	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_virt(desc, &walk);
	desc->flags &= ~CRYPTO_TFM_REQ_MAY_SLEEP;

	kernel_fpu_begin();
	while ((nbytes = walk.nbytes)) {
		aesni_cbc_enc(ctx, walk.dst.virt.addr, walk.src.virt.addr,
			      nbytes & AES_BLOCK_MASK, walk.iv);
		nbytes &= AES_BLOCK_SIZE - 1;
		err = blkcipher_walk_done(desc, &walk, nbytes);
	}
	kernel_fpu_end();

	return err;
}

static int cbc_decrypt(struct blkcipher_desc *desc,
		       struct scatterlist *dst, struct scatterlist *src,
		       unsigned int nbytes)
{
	struct crypto_aes_ctx *ctx = aes_ctx(crypto_blkcipher_ctx(desc->tfm));
	struct blkcipher_walk walk;
	int err;

	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_virt(desc, &walk);
	desc->flags &= ~CRYPTO_TFM_REQ_MAY_SLEEP;

	kernel_fpu_begin();
	while ((nbytes = walk.nbytes)) {
		aesni_cbc_dec(ctx, walk.dst.virt.addr, walk.src.virt.addr,
			      nbytes & AES_BLOCK_MASK, walk.iv);
		nbytes &= AES_BLOCK_SIZE - 1;
		err = blkcipher_walk_done(desc, &walk, nbytes);
	}
	kernel_fpu_end();

	return err;
}

#ifdef CONFIG_X86_64
static void ctr_crypt_final(struct crypto_aes_ctx *ctx,
			    struct blkcipher_walk *walk)
{
	u8 *ctrblk = walk->iv;
	u8 keystream[AES_BLOCK_SIZE];
	u8 *src = walk->src.virt.addr;
	u8 *dst = walk->dst.virt.addr;
	unsigned int nbytes = walk->nbytes;

	aesni_enc(ctx, keystream, ctrblk);
	crypto_xor(keystream, src, nbytes);
	memcpy(dst, keystream, nbytes);
	crypto_inc(ctrblk, AES_BLOCK_SIZE);
}

#ifdef CONFIG_AS_AVX
static void aesni_ctr_enc_avx_tfm(struct crypto_aes_ctx *ctx, u8 *out,
			      const u8 *in, unsigned int len, u8 *iv)
{
	/*
	 * based on key length, override with the by8 version
	 * of ctr mode encryption/decryption for improved performance
	 * aes_set_key_common() ensures that key length is one of
	 * {128,192,256}
	 */
	if (ctx->key_length == AES_KEYSIZE_128)
		aes_ctr_enc_128_avx_by8(in, iv, (void *)ctx, out, len);
	else if (ctx->key_length == AES_KEYSIZE_192)
		aes_ctr_enc_192_avx_by8(in, iv, (void *)ctx, out, len);
	else
		aes_ctr_enc_256_avx_by8(in, iv, (void *)ctx, out, len);
}
#endif

static int ctr_crypt(struct blkcipher_desc *desc,
		     struct scatterlist *dst, struct scatterlist *src,
		     unsigned int nbytes)
{
	struct crypto_aes_ctx *ctx = aes_ctx(crypto_blkcipher_ctx(desc->tfm));
	struct blkcipher_walk walk;
	int err;

	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_virt_block(desc, &walk, AES_BLOCK_SIZE);
	desc->flags &= ~CRYPTO_TFM_REQ_MAY_SLEEP;

	kernel_fpu_begin();
	while ((nbytes = walk.nbytes) >= AES_BLOCK_SIZE) {
		aesni_ctr_enc_tfm(ctx, walk.dst.virt.addr, walk.src.virt.addr,
			              nbytes & AES_BLOCK_MASK, walk.iv);
		nbytes &= AES_BLOCK_SIZE - 1;
		err = blkcipher_walk_done(desc, &walk, nbytes);
	}
	if (walk.nbytes) {
		ctr_crypt_final(ctx, &walk);
		err = blkcipher_walk_done(desc, &walk, 0);
	}
	kernel_fpu_end();

	return err;
}

static int __ccm_setkey(struct crypto_aead *tfm, const u8 *in_key,
		      unsigned int key_len)
{
	struct crypto_aes_ctx *ctx = crypto_aead_ctx(tfm);

	return aes_set_key_common(crypto_aead_tfm(tfm), ctx, in_key, key_len);
}

static int __ccm_setauthsize(struct crypto_aead *tfm, unsigned int authsize)
{
	if ((authsize & 1) || authsize < 4)
		return -EINVAL;
	return 0;
}

static int set_msg_len(u8 *block, unsigned int msglen, int csize)
{
	__be32 data;

	memset(block, 0, csize);
	block += csize;

	if (csize >= 4)
		csize = 4;
	else if (msglen > (1 << (8 * csize)))
		return -EOVERFLOW;

	data = cpu_to_be32(msglen);
	memcpy(block - csize, (u8 *)&data + 4 - csize, csize);

	return 0;
}

static int ccm_init_mac(struct aead_request *req, u8 maciv[], u32 msglen)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	__be32 *n = (__be32 *)&maciv[AES_BLOCK_SIZE - 8];
	u32 l = req->iv[0] + 1;

	/* verify that CCM dimension 'L' is set correctly in the IV */
	if (l < 2 || l > 8)
		return -EINVAL;

	/* verify that msglen can in fact be represented in L bytes */
	if (l < 4 && msglen >> (8 * l))
		return -EOVERFLOW;

	/*
	 * Even if the CCM spec allows L values of up to 8, the Linux cryptoapi
	 * uses a u32 type to represent msglen so the top 4 bytes are always 0.
	 */
	n[0] = 0;
	n[1] = cpu_to_be32(msglen);

	memcpy(maciv, req->iv, AES_BLOCK_SIZE - l);

	/*
	 * Meaning of byte 0 according to CCM spec (RFC 3610/NIST 800-38C)
	 * - bits 0..2	: max # of bytes required to represent msglen, minus 1
	 *                (already set by caller)
	 * - bits 3..5	: size of auth tag (1 => 4 bytes, 2 => 6 bytes, etc)
	 * - bit 6	: indicates presence of authenticate-only data
	 */
	maciv[0] |= (crypto_aead_authsize(aead) - 2) << 2;
	if (req->assoclen)
		maciv[0] |= 0x40;

	memset(&req->iv[AES_BLOCK_SIZE - l], 0, l);
	return set_msg_len(maciv + AES_BLOCK_SIZE - l, msglen, l);
}

static int compute_mac(struct crypto_aes_ctx *ctx, u8 mac[], u8 *data, int n,
		       unsigned int ilen, u8 *idata)
{
	unsigned int bs = AES_BLOCK_SIZE;
	u8 *odata = mac;
	int datalen, getlen;

	datalen = n;

	/* first time in here, block may be partially filled. */
	getlen = bs - ilen;
	if (datalen >= getlen) {
		memcpy(idata + ilen, data, getlen);
		crypto_xor(odata, idata, bs);

		aesni_enc(ctx, odata, odata);
		datalen -= getlen;
		data += getlen;
		ilen = 0;
	}

	/* now encrypt rest of data */
	while (datalen >= bs) {
		crypto_xor(odata, data, bs);

		aesni_enc(ctx, odata, odata);

		datalen -= bs;
		data += bs;
	}

	/* check and see if there's leftover data that wasn't
	 * enough to fill a block.
	 */
	if (datalen) {
		memcpy(idata + ilen, data, datalen);
		ilen += datalen;
	}
	return ilen;
}

static unsigned int get_data_to_compute(struct crypto_aes_ctx *ctx, u8 mac[],
					u8 *idata, struct scatterlist *sg,
					unsigned int len, unsigned int ilen)
{
	struct scatter_walk walk;
	u8 *data_src;
	int n;

	scatterwalk_start(&walk, sg);

	while (len) {
		n = scatterwalk_clamp(&walk, len);
		if (!n) {
			scatterwalk_start(&walk, sg_next(walk.sg));
			n = scatterwalk_clamp(&walk, len);
		}
		data_src = scatterwalk_map(&walk);

		ilen = compute_mac(ctx, mac, data_src, n, ilen, idata);
		len -= n;

		scatterwalk_unmap(data_src);
		scatterwalk_advance(&walk, n);
		scatterwalk_done(&walk, 0, len);
	}

	/* any leftover needs padding and then encrypted */
	if (ilen) {
		int padlen;
		u8 *odata = mac;

		padlen = AES_BLOCK_SIZE - ilen;
		memset(idata + ilen, 0, padlen);
		crypto_xor(odata, idata, AES_BLOCK_SIZE);

		aesni_enc(ctx, odata, odata);
		ilen = 0;
	}
	return ilen;
}

static void ccm_calculate_auth_mac(struct aead_request *req,
				   struct crypto_aes_ctx *ctx, u8 mac[],
				   struct scatterlist *src,
				   unsigned int cryptlen)
{
	unsigned int ilen;
	u8 idata[AES_BLOCK_SIZE];
	u32 len = req->assoclen;

	aesni_enc(ctx, mac, mac);

	if (len) {
		struct __packed {
			__be16 l;
			__be32 h;
		} *ltag = (void *)idata;

		/* prepend the AAD with a length tag */
		if (len < 0xff00) {
			ltag->l = cpu_to_be16(len);
			ilen = 2;
		} else  {
			ltag->l = cpu_to_be16(0xfffe);
			ltag->h = cpu_to_be32(len);
			ilen = 6;
		}

		ilen = get_data_to_compute(ctx, mac, idata,
					   req->assoc, req->assoclen,
					   ilen);
	} else {
		ilen = 0;
	}

	/* compute plaintext into mac */
	if (cryptlen) {
		ilen = get_data_to_compute(ctx, mac, idata,
					   src, cryptlen, ilen);
	}
}

static int __ccm_encrypt(struct aead_request *req)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct crypto_aes_ctx *ctx = aes_ctx(crypto_aead_ctx(aead));
	struct blkcipher_desc desc = { .info = req->iv };
	struct blkcipher_walk walk;
	struct scatterlist src[2], dst[2], *pdst;
	u8 __aligned(8) mac[AES_BLOCK_SIZE];
	u32 len = req->cryptlen;
	int err;

	err = ccm_init_mac(req, mac, len);
	if (err)
		return err;

	ccm_calculate_auth_mac(req, ctx, mac, req->src, len);

	sg_init_table(src, 2);
	sg_set_buf(src, mac, sizeof(mac));
	scatterwalk_sg_chain(src, 2, req->src);

	pdst = src;
	if (req->src != req->dst) {
		sg_init_table(dst, 2);
		sg_set_buf(dst, mac, sizeof(mac));
		scatterwalk_sg_chain(dst, 2, req->dst);
		pdst = dst;
	}

	len += sizeof(mac);
	blkcipher_walk_init(&walk, pdst, src, len);
	err = blkcipher_aead_walk_virt_block(&desc, &walk, aead,
					     AES_BLOCK_SIZE);

	while ((len = walk.nbytes) >= AES_BLOCK_SIZE) {
		aesni_ctr_enc(ctx, walk.dst.virt.addr, walk.src.virt.addr,
			      len & AES_BLOCK_MASK, walk.iv);
		len &= AES_BLOCK_SIZE - 1;
		err = blkcipher_walk_done(&desc, &walk, len);
	}
	if (walk.nbytes) {
		ctr_crypt_final(ctx, &walk);
		err = blkcipher_walk_done(&desc, &walk, 0);
	}

	if (err)
		return err;

	/* copy authtag to end of dst */
	scatterwalk_map_and_copy(mac, req->dst, req->cryptlen,
				 crypto_aead_authsize(aead), 1);
	return 0;
}

static int __ccm_decrypt(struct aead_request *req)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct crypto_aes_ctx *ctx = aes_ctx(crypto_aead_ctx(aead));
	unsigned int authsize = crypto_aead_authsize(aead);
	struct blkcipher_desc desc = { .info = req->iv };
	struct blkcipher_walk walk;
	struct scatterlist src[2], dst[2], *pdst;
	u8 __aligned(8) authtag[AES_BLOCK_SIZE], mac[AES_BLOCK_SIZE];
	u32 len;
	int err;

	if (req->cryptlen < authsize)
		return -EINVAL;

	scatterwalk_map_and_copy(authtag, req->src,
				 req->cryptlen - authsize, authsize, 0);

	err = ccm_init_mac(req, mac, req->cryptlen - authsize);
	if (err)
		return err;

	sg_init_table(src, 2);
	sg_set_buf(src, authtag, sizeof(authtag));
	scatterwalk_sg_chain(src, 2, req->src);

	pdst = src;
	if (req->src != req->dst) {
		sg_init_table(dst, 2);
		sg_set_buf(dst, authtag, sizeof(authtag));
		scatterwalk_sg_chain(dst, 2, req->dst);
		pdst = dst;
	}

	blkcipher_walk_init(&walk, pdst, src,
			    req->cryptlen - authsize + sizeof(mac));
	err = blkcipher_aead_walk_virt_block(&desc, &walk, aead,
					     AES_BLOCK_SIZE);

	while ((len = walk.nbytes) >= AES_BLOCK_SIZE) {
		aesni_ctr_enc(ctx, walk.dst.virt.addr, walk.src.virt.addr,
			      len & AES_BLOCK_MASK, walk.iv);
		len &= AES_BLOCK_SIZE - 1;
		err = blkcipher_walk_done(&desc, &walk, len);
	}
	if (walk.nbytes) {
		ctr_crypt_final(ctx, &walk);
		err = blkcipher_walk_done(&desc, &walk, 0);
	}

	ccm_calculate_auth_mac(req, ctx, mac, req->dst,
			       req->cryptlen - authsize);
	if (err)
		return err;

	/* compare calculated auth tag with the stored one */
	if (crypto_memneq(mac, authtag, authsize))
		return -EBADMSG;
	return 0;
}

struct ccm_async_ctx {
	struct crypto_aes_ctx ctx;
	struct crypto_aead *fallback;
};

static inline struct
ccm_async_ctx *get_ccm_ctx(struct crypto_aead *aead)
{
	return (struct ccm_async_ctx *)
		PTR_ALIGN((u8 *)
		crypto_tfm_ctx(crypto_aead_tfm(aead)), AESNI_ALIGN);
}

static int ccm_init(struct crypto_tfm *tfm)
{
	struct crypto_aead *crypto_tfm;
	struct ccm_async_ctx *ctx = (struct ccm_async_ctx *)
		PTR_ALIGN((u8 *)crypto_tfm_ctx(tfm), AESNI_ALIGN);

	crypto_tfm = crypto_alloc_aead("ccm(aes)", 0,
		CRYPTO_ALG_ASYNC | CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(crypto_tfm))
		return PTR_ERR(crypto_tfm);

	ctx->fallback = crypto_tfm;
	return 0;
}

static void ccm_exit(struct crypto_tfm *tfm)
{
	struct ccm_async_ctx *ctx = (struct ccm_async_ctx *)
		PTR_ALIGN((u8 *)crypto_tfm_ctx(tfm), AESNI_ALIGN);

	if (!IS_ERR_OR_NULL(ctx->fallback))
		crypto_free_aead(ctx->fallback);
}

static int ccm_setkey(struct crypto_aead *aead, const u8 *in_key,
		      unsigned int key_len)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(aead);
	struct ccm_async_ctx *ctx = (struct ccm_async_ctx *)
		PTR_ALIGN((u8 *)crypto_tfm_ctx(tfm), AESNI_ALIGN);
	int err;

	err = __ccm_setkey(aead, in_key, key_len);
	if (err)
		return err;

	/*
	 * Set the fallback transform to use the same request flags as
	 * the hardware transform.
	 */
	ctx->fallback->base.crt_flags &= ~CRYPTO_TFM_REQ_MASK;
	ctx->fallback->base.crt_flags |=
			tfm->crt_flags & CRYPTO_TFM_REQ_MASK;
	return crypto_aead_setkey(ctx->fallback, in_key, key_len);
}

static int ccm_setauthsize(struct crypto_aead *aead, unsigned int authsize)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(aead);
	struct ccm_async_ctx *ctx = (struct ccm_async_ctx *)
		PTR_ALIGN((u8 *)crypto_tfm_ctx(tfm), AESNI_ALIGN);
	int err;

	err = __ccm_setauthsize(aead, authsize);
	if (err)
		return err;

	return crypto_aead_setauthsize(ctx->fallback, authsize);
}

static int ccm_encrypt(struct aead_request *req)
{
	int ret;

	if (!irq_fpu_usable()) {
		struct crypto_aead *aead = crypto_aead_reqtfm(req);
		struct ccm_async_ctx *ctx = get_ccm_ctx(aead);
		struct crypto_aead *fallback = ctx->fallback;

		char aead_req_data[sizeof(struct aead_request) +
				   crypto_aead_reqsize(fallback)]
		__aligned(__alignof__(struct aead_request));
		struct aead_request *aead_req = (void *) aead_req_data;

		memset(aead_req, 0, sizeof(aead_req_data));
		aead_request_set_tfm(aead_req, fallback);
		aead_request_set_assoc(aead_req, req->assoc, req->assoclen);
		aead_request_set_crypt(aead_req, req->src, req->dst,
				       req->cryptlen, req->iv);
		aead_request_set_callback(aead_req, req->base.flags,
					  req->base.complete, req->base.data);
		ret = crypto_aead_encrypt(aead_req);
	} else {
		kernel_fpu_begin();
		ret = __ccm_encrypt(req);
		kernel_fpu_end();
	}
	return ret;
}

static int ccm_decrypt(struct aead_request *req)
{
	int ret;

	if (!irq_fpu_usable()) {
		struct crypto_aead *aead = crypto_aead_reqtfm(req);
		struct ccm_async_ctx *ctx = get_ccm_ctx(aead);
		struct crypto_aead *fallback = ctx->fallback;

		char aead_req_data[sizeof(struct aead_request) +
				   crypto_aead_reqsize(fallback)]
		__aligned(__alignof__(struct aead_request));
		struct aead_request *aead_req = (void *) aead_req_data;

		memset(aead_req, 0, sizeof(aead_req_data));
		aead_request_set_tfm(aead_req, fallback);
		aead_request_set_assoc(aead_req, req->assoc, req->assoclen);
		aead_request_set_crypt(aead_req, req->src, req->dst,
				       req->cryptlen, req->iv);
		aead_request_set_callback(aead_req, req->base.flags,
					  req->base.complete, req->base.data);
		ret = crypto_aead_decrypt(aead_req);
	} else {
		kernel_fpu_begin();
		ret = __ccm_decrypt(req);
		kernel_fpu_end();
	}
	return ret;
}
#endif

static int ablk_ecb_init(struct crypto_tfm *tfm)
{
	return ablk_init_common(tfm, "__driver-ecb-aes-aesni");
}

static int ablk_cbc_init(struct crypto_tfm *tfm)
{
	return ablk_init_common(tfm, "__driver-cbc-aes-aesni");
}

#ifdef CONFIG_X86_64
static int ablk_ctr_init(struct crypto_tfm *tfm)
{
	return ablk_init_common(tfm, "__driver-ctr-aes-aesni");
}

#endif

#if IS_ENABLED(CONFIG_CRYPTO_PCBC)
static int ablk_pcbc_init(struct crypto_tfm *tfm)
{
	return ablk_init_common(tfm, "fpu(pcbc(__driver-aes-aesni))");
}
#endif

static void lrw_xts_encrypt_callback(void *ctx, u8 *blks, unsigned int nbytes)
{
	aesni_ecb_enc(ctx, blks, blks, nbytes);
}

static void lrw_xts_decrypt_callback(void *ctx, u8 *blks, unsigned int nbytes)
{
	aesni_ecb_dec(ctx, blks, blks, nbytes);
}

static int lrw_aesni_setkey(struct crypto_tfm *tfm, const u8 *key,
			    unsigned int keylen)
{
	struct aesni_lrw_ctx *ctx = crypto_tfm_ctx(tfm);
	int err;

	err = aes_set_key_common(tfm, ctx->raw_aes_ctx, key,
				 keylen - AES_BLOCK_SIZE);
	if (err)
		return err;

	return lrw_init_table(&ctx->lrw_table, key + keylen - AES_BLOCK_SIZE);
}

static void lrw_aesni_exit_tfm(struct crypto_tfm *tfm)
{
	struct aesni_lrw_ctx *ctx = crypto_tfm_ctx(tfm);

	lrw_free_table(&ctx->lrw_table);
}

static int lrw_encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	struct aesni_lrw_ctx *ctx = crypto_blkcipher_ctx(desc->tfm);
	be128 buf[8];
	struct lrw_crypt_req req = {
		.tbuf = buf,
		.tbuflen = sizeof(buf),

		.table_ctx = &ctx->lrw_table,
		.crypt_ctx = aes_ctx(ctx->raw_aes_ctx),
		.crypt_fn = lrw_xts_encrypt_callback,
	};
	int ret;

	desc->flags &= ~CRYPTO_TFM_REQ_MAY_SLEEP;

	kernel_fpu_begin();
	ret = lrw_crypt(desc, dst, src, nbytes, &req);
	kernel_fpu_end();

	return ret;
}

static int lrw_decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	struct aesni_lrw_ctx *ctx = crypto_blkcipher_ctx(desc->tfm);
	be128 buf[8];
	struct lrw_crypt_req req = {
		.tbuf = buf,
		.tbuflen = sizeof(buf),

		.table_ctx = &ctx->lrw_table,
		.crypt_ctx = aes_ctx(ctx->raw_aes_ctx),
		.crypt_fn = lrw_xts_decrypt_callback,
	};
	int ret;

	desc->flags &= ~CRYPTO_TFM_REQ_MAY_SLEEP;

	kernel_fpu_begin();
	ret = lrw_crypt(desc, dst, src, nbytes, &req);
	kernel_fpu_end();

	return ret;
}

static int xts_aesni_setkey(struct crypto_tfm *tfm, const u8 *key,
			    unsigned int keylen)
{
	struct aesni_xts_ctx *ctx = crypto_tfm_ctx(tfm);
	u32 *flags = &tfm->crt_flags;
	int err;

	/* key consists of keys of equal size concatenated, therefore
	 * the length must be even
	 */
	if (keylen % 2) {
		*flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}

	/* first half of xts-key is for crypt */
	err = aes_set_key_common(tfm, ctx->raw_crypt_ctx, key, keylen / 2);
	if (err)
		return err;

	/* second half of xts-key is for tweak */
	return aes_set_key_common(tfm, ctx->raw_tweak_ctx, key + keylen / 2,
				  keylen / 2);
}


static void aesni_xts_tweak(void *ctx, u8 *out, const u8 *in)
{
	aesni_enc(ctx, out, in);
}

#ifdef CONFIG_X86_64

static void aesni_xts_enc(void *ctx, u128 *dst, const u128 *src, le128 *iv)
{
	glue_xts_crypt_128bit_one(ctx, dst, src, iv, GLUE_FUNC_CAST(aesni_enc));
}

static void aesni_xts_dec(void *ctx, u128 *dst, const u128 *src, le128 *iv)
{
	glue_xts_crypt_128bit_one(ctx, dst, src, iv, GLUE_FUNC_CAST(aesni_dec));
}

static void aesni_xts_enc8(void *ctx, u128 *dst, const u128 *src, le128 *iv)
{
	aesni_xts_crypt8(ctx, (u8 *)dst, (const u8 *)src, true, (u8 *)iv);
}

static void aesni_xts_dec8(void *ctx, u128 *dst, const u128 *src, le128 *iv)
{
	aesni_xts_crypt8(ctx, (u8 *)dst, (const u8 *)src, false, (u8 *)iv);
}

static const struct common_glue_ctx aesni_enc_xts = {
	.num_funcs = 2,
	.fpu_blocks_limit = 1,

	.funcs = { {
		.num_blocks = 8,
		.fn_u = { .xts = GLUE_XTS_FUNC_CAST(aesni_xts_enc8) }
	}, {
		.num_blocks = 1,
		.fn_u = { .xts = GLUE_XTS_FUNC_CAST(aesni_xts_enc) }
	} }
};

static const struct common_glue_ctx aesni_dec_xts = {
	.num_funcs = 2,
	.fpu_blocks_limit = 1,

	.funcs = { {
		.num_blocks = 8,
		.fn_u = { .xts = GLUE_XTS_FUNC_CAST(aesni_xts_dec8) }
	}, {
		.num_blocks = 1,
		.fn_u = { .xts = GLUE_XTS_FUNC_CAST(aesni_xts_dec) }
	} }
};

static int xts_encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	struct aesni_xts_ctx *ctx = crypto_blkcipher_ctx(desc->tfm);

	return glue_xts_crypt_128bit(&aesni_enc_xts, desc, dst, src, nbytes,
				     XTS_TWEAK_CAST(aesni_xts_tweak),
				     aes_ctx(ctx->raw_tweak_ctx),
				     aes_ctx(ctx->raw_crypt_ctx));
}

static int xts_decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	struct aesni_xts_ctx *ctx = crypto_blkcipher_ctx(desc->tfm);

	return glue_xts_crypt_128bit(&aesni_dec_xts, desc, dst, src, nbytes,
				     XTS_TWEAK_CAST(aesni_xts_tweak),
				     aes_ctx(ctx->raw_tweak_ctx),
				     aes_ctx(ctx->raw_crypt_ctx));
}

#else

static int xts_encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	struct aesni_xts_ctx *ctx = crypto_blkcipher_ctx(desc->tfm);
	be128 buf[8];
	struct xts_crypt_req req = {
		.tbuf = buf,
		.tbuflen = sizeof(buf),

		.tweak_ctx = aes_ctx(ctx->raw_tweak_ctx),
		.tweak_fn = aesni_xts_tweak,
		.crypt_ctx = aes_ctx(ctx->raw_crypt_ctx),
		.crypt_fn = lrw_xts_encrypt_callback,
	};
	int ret;

	desc->flags &= ~CRYPTO_TFM_REQ_MAY_SLEEP;

	kernel_fpu_begin();
	ret = xts_crypt(desc, dst, src, nbytes, &req);
	kernel_fpu_end();

	return ret;
}

static int xts_decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	struct aesni_xts_ctx *ctx = crypto_blkcipher_ctx(desc->tfm);
	be128 buf[8];
	struct xts_crypt_req req = {
		.tbuf = buf,
		.tbuflen = sizeof(buf),

		.tweak_ctx = aes_ctx(ctx->raw_tweak_ctx),
		.tweak_fn = aesni_xts_tweak,
		.crypt_ctx = aes_ctx(ctx->raw_crypt_ctx),
		.crypt_fn = lrw_xts_decrypt_callback,
	};
	int ret;

	desc->flags &= ~CRYPTO_TFM_REQ_MAY_SLEEP;

	kernel_fpu_begin();
	ret = xts_crypt(desc, dst, src, nbytes, &req);
	kernel_fpu_end();

	return ret;
}

#endif

#ifdef CONFIG_X86_64
static int rfc4106_init(struct crypto_tfm *tfm)
{
	struct cryptd_aead *cryptd_tfm;
	struct aesni_rfc4106_gcm_ctx *ctx = (struct aesni_rfc4106_gcm_ctx *)
		PTR_ALIGN((u8 *)crypto_tfm_ctx(tfm), AESNI_ALIGN);
	struct crypto_aead *cryptd_child;
	struct aesni_rfc4106_gcm_ctx *child_ctx;
	cryptd_tfm = cryptd_alloc_aead("__driver-gcm-aes-aesni", 0, 0);
	if (IS_ERR(cryptd_tfm))
		return PTR_ERR(cryptd_tfm);

	cryptd_child = cryptd_aead_child(cryptd_tfm);
	child_ctx = aesni_rfc4106_gcm_ctx_get(cryptd_child);
	memcpy(child_ctx, ctx, sizeof(*ctx));
	ctx->cryptd_tfm = cryptd_tfm;
	tfm->crt_aead.reqsize = sizeof(struct aead_request)
		+ crypto_aead_reqsize(&cryptd_tfm->base);
	return 0;
}

static void rfc4106_exit(struct crypto_tfm *tfm)
{
	struct aesni_rfc4106_gcm_ctx *ctx =
		(struct aesni_rfc4106_gcm_ctx *)
		PTR_ALIGN((u8 *)crypto_tfm_ctx(tfm), AESNI_ALIGN);
	if (!IS_ERR(ctx->cryptd_tfm))
		cryptd_free_aead(ctx->cryptd_tfm);
	return;
}

static void
rfc4106_set_hash_subkey_done(struct crypto_async_request *req, int err)
{
	struct aesni_gcm_set_hash_subkey_result *result = req->data;

	if (err == -EINPROGRESS)
		return;
	result->err = err;
	complete(&result->completion);
}

static int
rfc4106_set_hash_subkey(u8 *hash_subkey, const u8 *key, unsigned int key_len)
{
	struct crypto_ablkcipher *ctr_tfm;
	struct ablkcipher_request *req;
	int ret = -EINVAL;
	struct aesni_hash_subkey_req_data *req_data;

	ctr_tfm = crypto_alloc_ablkcipher("ctr(aes)", 0, 0);
	if (IS_ERR(ctr_tfm))
		return PTR_ERR(ctr_tfm);

	crypto_ablkcipher_clear_flags(ctr_tfm, ~0);

	ret = crypto_ablkcipher_setkey(ctr_tfm, key, key_len);
	if (ret)
		goto out_free_ablkcipher;

	ret = -ENOMEM;
	req = ablkcipher_request_alloc(ctr_tfm, GFP_KERNEL);
	if (!req)
		goto out_free_ablkcipher;

	req_data = kmalloc(sizeof(*req_data), GFP_KERNEL);
	if (!req_data)
		goto out_free_request;

	memset(req_data->iv, 0, sizeof(req_data->iv));

	/* Clear the data in the hash sub key container to zero.*/
	/* We want to cipher all zeros to create the hash sub key. */
	memset(hash_subkey, 0, RFC4106_HASH_SUBKEY_SIZE);

	init_completion(&req_data->result.completion);
	sg_init_one(&req_data->sg, hash_subkey, RFC4106_HASH_SUBKEY_SIZE);
	ablkcipher_request_set_tfm(req, ctr_tfm);
	ablkcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP |
					CRYPTO_TFM_REQ_MAY_BACKLOG,
					rfc4106_set_hash_subkey_done,
					&req_data->result);

	ablkcipher_request_set_crypt(req, &req_data->sg,
		&req_data->sg, RFC4106_HASH_SUBKEY_SIZE, req_data->iv);

	ret = crypto_ablkcipher_encrypt(req);
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		ret = wait_for_completion_interruptible
			(&req_data->result.completion);
		if (!ret)
			ret = req_data->result.err;
	}
	kfree(req_data);
out_free_request:
	ablkcipher_request_free(req);
out_free_ablkcipher:
	crypto_free_ablkcipher(ctr_tfm);
	return ret;
}

static int rfc4106_set_key(struct crypto_aead *parent, const u8 *key,
						   unsigned int key_len)
{
	int ret = 0;
	struct crypto_tfm *tfm = crypto_aead_tfm(parent);
	struct aesni_rfc4106_gcm_ctx *ctx = aesni_rfc4106_gcm_ctx_get(parent);
	struct crypto_aead *cryptd_child = cryptd_aead_child(ctx->cryptd_tfm);
	struct aesni_rfc4106_gcm_ctx *child_ctx =
                                 aesni_rfc4106_gcm_ctx_get(cryptd_child);
	u8 *new_key_align, *new_key_mem = NULL;

	if (key_len < 4) {
		crypto_tfm_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}
	/*Account for 4 byte nonce at the end.*/
	key_len -= 4;
	if (key_len != AES_KEYSIZE_128 && key_len != AES_KEYSIZE_192 &&
	    key_len != AES_KEYSIZE_256) {
		crypto_tfm_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}

	memcpy(ctx->nonce, key + key_len, sizeof(ctx->nonce));
	/*This must be on a 16 byte boundary!*/
	if ((unsigned long)(&(ctx->aes_key_expanded.key_enc[0])) % AESNI_ALIGN)
		return -EINVAL;

	if ((unsigned long)key % AESNI_ALIGN) {
		/*key is not aligned: use an auxuliar aligned pointer*/
		new_key_mem = kmalloc(key_len+AESNI_ALIGN, GFP_KERNEL);
		if (!new_key_mem)
			return -ENOMEM;

		new_key_align = PTR_ALIGN(new_key_mem, AESNI_ALIGN);
		memcpy(new_key_align, key, key_len);
		key = new_key_align;
	}

	if (!irq_fpu_usable())
		ret = crypto_aes_expand_key(&(ctx->aes_key_expanded),
		key, key_len);
	else {
		kernel_fpu_begin();
		ret = aesni_set_key(&(ctx->aes_key_expanded), key, key_len);
		kernel_fpu_end();
	}
	/*This must be on a 16 byte boundary!*/
	if ((unsigned long)(&(ctx->hash_subkey[0])) % AESNI_ALIGN) {
		ret = -EINVAL;
		goto exit;
	}
	ret = rfc4106_set_hash_subkey(ctx->hash_subkey, key, key_len);
	memcpy(child_ctx, ctx, sizeof(*ctx));
exit:
	kfree(new_key_mem);
	return ret;
}

/* This is the Integrity Check Value (aka the authentication tag length and can
 * be 8, 12 or 16 bytes long. */
static int rfc4106_set_authsize(struct crypto_aead *parent,
				unsigned int authsize)
{
	struct aesni_rfc4106_gcm_ctx *ctx = aesni_rfc4106_gcm_ctx_get(parent);
	struct crypto_aead *cryptd_child = cryptd_aead_child(ctx->cryptd_tfm);

	switch (authsize) {
	case 8:
	case 12:
	case 16:
		break;
	default:
		return -EINVAL;
	}
	crypto_aead_crt(parent)->authsize = authsize;
	crypto_aead_crt(cryptd_child)->authsize = authsize;
	return 0;
}

static int rfc4106_encrypt(struct aead_request *req)
{
	int ret;
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct aesni_rfc4106_gcm_ctx *ctx = aesni_rfc4106_gcm_ctx_get(tfm);

	if (!irq_fpu_usable()) {
		struct aead_request *cryptd_req =
			(struct aead_request *) aead_request_ctx(req);
		memcpy(cryptd_req, req, sizeof(*req));
		aead_request_set_tfm(cryptd_req, &ctx->cryptd_tfm->base);
		return crypto_aead_encrypt(cryptd_req);
	} else {
		struct crypto_aead *cryptd_child = cryptd_aead_child(ctx->cryptd_tfm);
		kernel_fpu_begin();
		ret = cryptd_child->base.crt_aead.encrypt(req);
		kernel_fpu_end();
		return ret;
	}
}

static int rfc4106_decrypt(struct aead_request *req)
{
	int ret;
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct aesni_rfc4106_gcm_ctx *ctx = aesni_rfc4106_gcm_ctx_get(tfm);

	if (!irq_fpu_usable()) {
		struct aead_request *cryptd_req =
			(struct aead_request *) aead_request_ctx(req);
		memcpy(cryptd_req, req, sizeof(*req));
		aead_request_set_tfm(cryptd_req, &ctx->cryptd_tfm->base);
		return crypto_aead_decrypt(cryptd_req);
	} else {
		struct crypto_aead *cryptd_child = cryptd_aead_child(ctx->cryptd_tfm);
		kernel_fpu_begin();
		ret = cryptd_child->base.crt_aead.decrypt(req);
		kernel_fpu_end();
		return ret;
	}
}

static int __driver_rfc4106_encrypt(struct aead_request *req)
{
	u8 one_entry_in_sg = 0;
	u8 *src, *dst, *assoc;
	__be32 counter = cpu_to_be32(1);
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct aesni_rfc4106_gcm_ctx *ctx = aesni_rfc4106_gcm_ctx_get(tfm);
	u32 key_len = ctx->aes_key_expanded.key_length;
	void *aes_ctx = &(ctx->aes_key_expanded);
	unsigned long auth_tag_len = crypto_aead_authsize(tfm);
	u8 iv_tab[16+AESNI_ALIGN];
	u8* iv = (u8 *) PTR_ALIGN((u8 *)iv_tab, AESNI_ALIGN);
	struct scatter_walk src_sg_walk;
	struct scatter_walk assoc_sg_walk;
	struct scatter_walk dst_sg_walk;
	unsigned int i;

	/* Assuming we are supporting rfc4106 64-bit extended */
	/* sequence numbers We need to have the AAD length equal */
	/* to 8 or 12 bytes */
	if (unlikely(req->assoclen != 8 && req->assoclen != 12))
		return -EINVAL;
	if (unlikely(auth_tag_len != 8 && auth_tag_len != 12 && auth_tag_len != 16))
	        return -EINVAL;
	if (unlikely(key_len != AES_KEYSIZE_128 &&
	             key_len != AES_KEYSIZE_192 &&
	             key_len != AES_KEYSIZE_256))
	        return -EINVAL;

	/* IV below built */
	for (i = 0; i < 4; i++)
		*(iv+i) = ctx->nonce[i];
	for (i = 0; i < 8; i++)
		*(iv+4+i) = req->iv[i];
	*((__be32 *)(iv+12)) = counter;

	if ((sg_is_last(req->src)) && (sg_is_last(req->assoc))) {
		one_entry_in_sg = 1;
		scatterwalk_start(&src_sg_walk, req->src);
		scatterwalk_start(&assoc_sg_walk, req->assoc);
		src = scatterwalk_map(&src_sg_walk);
		assoc = scatterwalk_map(&assoc_sg_walk);
		dst = src;
		if (unlikely(req->src != req->dst)) {
			scatterwalk_start(&dst_sg_walk, req->dst);
			dst = scatterwalk_map(&dst_sg_walk);
		}

	} else {
		/* Allocate memory for src, dst, assoc */
		src = kmalloc(req->cryptlen + auth_tag_len + req->assoclen,
			GFP_ATOMIC);
		if (unlikely(!src))
			return -ENOMEM;
		assoc = (src + req->cryptlen + auth_tag_len);
		scatterwalk_map_and_copy(src, req->src, 0, req->cryptlen, 0);
		scatterwalk_map_and_copy(assoc, req->assoc, 0,
					req->assoclen, 0);
		dst = src;
	}

	aesni_gcm_enc_tfm(aes_ctx, dst, src, (unsigned long)req->cryptlen, iv,
		ctx->hash_subkey, assoc, (unsigned long)req->assoclen, dst
		+ ((unsigned long)req->cryptlen), auth_tag_len);

	/* The authTag (aka the Integrity Check Value) needs to be written
	 * back to the packet. */
	if (one_entry_in_sg) {
		if (unlikely(req->src != req->dst)) {
			scatterwalk_unmap(dst);
			scatterwalk_done(&dst_sg_walk, 0, 0);
		}
		scatterwalk_unmap(src);
		scatterwalk_unmap(assoc);
		scatterwalk_done(&src_sg_walk, 0, 0);
		scatterwalk_done(&assoc_sg_walk, 0, 0);
	} else {
		scatterwalk_map_and_copy(dst, req->dst, 0,
			req->cryptlen + auth_tag_len, 1);
		kfree(src);
	}
	return 0;
}

static int __driver_rfc4106_decrypt(struct aead_request *req)
{
	u8 one_entry_in_sg = 0;
	u8 *src, *dst, *assoc;
	unsigned long tempCipherLen = 0;
	__be32 counter = cpu_to_be32(1);
	int retval = 0;
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct aesni_rfc4106_gcm_ctx *ctx = aesni_rfc4106_gcm_ctx_get(tfm);
	u32 key_len = ctx->aes_key_expanded.key_length;
	void *aes_ctx = &(ctx->aes_key_expanded);
	unsigned long auth_tag_len = crypto_aead_authsize(tfm);
	u8 iv_and_authTag[32+AESNI_ALIGN];
	u8 *iv = (u8 *) PTR_ALIGN((u8 *)iv_and_authTag, AESNI_ALIGN);
	u8 *authTag = iv + 16;
	struct scatter_walk src_sg_walk;
	struct scatter_walk assoc_sg_walk;
	struct scatter_walk dst_sg_walk;
	unsigned int i;

	if (unlikely((req->cryptlen < auth_tag_len) ||
		(req->assoclen != 8 && req->assoclen != 12)))
		return -EINVAL;
	if (unlikely(auth_tag_len != 8 && auth_tag_len != 12 && auth_tag_len != 16))
	        return -EINVAL;
	if (unlikely(key_len != AES_KEYSIZE_128 &&
	             key_len != AES_KEYSIZE_192 &&
	             key_len != AES_KEYSIZE_256))
	        return -EINVAL;

	/* Assuming we are supporting rfc4106 64-bit extended */
	/* sequence numbers We need to have the AAD length */
	/* equal to 8 or 12 bytes */

	tempCipherLen = (unsigned long)(req->cryptlen - auth_tag_len);
	/* IV below built */
	for (i = 0; i < 4; i++)
		*(iv+i) = ctx->nonce[i];
	for (i = 0; i < 8; i++)
		*(iv+4+i) = req->iv[i];
	*((__be32 *)(iv+12)) = counter;

	if ((sg_is_last(req->src)) && (sg_is_last(req->assoc))) {
		one_entry_in_sg = 1;
		scatterwalk_start(&src_sg_walk, req->src);
		scatterwalk_start(&assoc_sg_walk, req->assoc);
		src = scatterwalk_map(&src_sg_walk);
		assoc = scatterwalk_map(&assoc_sg_walk);
		dst = src;
		if (unlikely(req->src != req->dst)) {
			scatterwalk_start(&dst_sg_walk, req->dst);
			dst = scatterwalk_map(&dst_sg_walk);
		}

	} else {
		/* Allocate memory for src, dst, assoc */
		src = kmalloc(req->cryptlen + req->assoclen, GFP_ATOMIC);
		if (!src)
			return -ENOMEM;
		assoc = (src + req->cryptlen);
		scatterwalk_map_and_copy(src, req->src, 0, req->cryptlen, 0);
		scatterwalk_map_and_copy(assoc, req->assoc, 0,
			req->assoclen, 0);
		dst = src;
	}

	aesni_gcm_dec_tfm(aes_ctx, dst, src, tempCipherLen, iv,
		ctx->hash_subkey, assoc, (unsigned long)req->assoclen,
		authTag, auth_tag_len);

	/* Compare generated tag with passed in tag. */
	retval = crypto_memneq(src + tempCipherLen, authTag, auth_tag_len) ?
		-EBADMSG : 0;

	if (one_entry_in_sg) {
		if (unlikely(req->src != req->dst)) {
			scatterwalk_unmap(dst);
			scatterwalk_done(&dst_sg_walk, 0, 0);
		}
		scatterwalk_unmap(src);
		scatterwalk_unmap(assoc);
		scatterwalk_done(&src_sg_walk, 0, 0);
		scatterwalk_done(&assoc_sg_walk, 0, 0);
	} else {
		scatterwalk_map_and_copy(dst, req->dst, 0, tempCipherLen, 1);
		kfree(src);
	}
	return retval;
}
#endif

static struct crypto_alg aesni_algs[] = { {
	.cra_name		= "aes",
	.cra_driver_name	= "aes-aesni",
	.cra_priority		= 300,
	.cra_flags		= CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct crypto_aes_ctx) +
				  AESNI_ALIGN - 1,
	.cra_alignmask		= 0,
	.cra_module		= THIS_MODULE,
	.cra_u	= {
		.cipher	= {
			.cia_min_keysize	= AES_MIN_KEY_SIZE,
			.cia_max_keysize	= AES_MAX_KEY_SIZE,
			.cia_setkey		= aes_set_key,
			.cia_encrypt		= aes_encrypt,
			.cia_decrypt		= aes_decrypt
		}
	}
}, {
	.cra_name		= "__aes-aesni",
	.cra_driver_name	= "__driver-aes-aesni",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct crypto_aes_ctx) +
				  AESNI_ALIGN - 1,
	.cra_alignmask		= 0,
	.cra_module		= THIS_MODULE,
	.cra_u	= {
		.cipher	= {
			.cia_min_keysize	= AES_MIN_KEY_SIZE,
			.cia_max_keysize	= AES_MAX_KEY_SIZE,
			.cia_setkey		= aes_set_key,
			.cia_encrypt		= __aes_encrypt,
			.cia_decrypt		= __aes_decrypt
		}
	}
}, {
	.cra_name		= "__ecb-aes-aesni",
	.cra_driver_name	= "__driver-ecb-aes-aesni",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct crypto_aes_ctx) +
				  AESNI_ALIGN - 1,
	.cra_alignmask		= 0,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_u = {
		.blkcipher = {
			.min_keysize	= AES_MIN_KEY_SIZE,
			.max_keysize	= AES_MAX_KEY_SIZE,
			.setkey		= aes_set_key,
			.encrypt	= ecb_encrypt,
			.decrypt	= ecb_decrypt,
		},
	},
}, {
	.cra_name		= "__cbc-aes-aesni",
	.cra_driver_name	= "__driver-cbc-aes-aesni",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct crypto_aes_ctx) +
				  AESNI_ALIGN - 1,
	.cra_alignmask		= 0,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_u = {
		.blkcipher = {
			.min_keysize	= AES_MIN_KEY_SIZE,
			.max_keysize	= AES_MAX_KEY_SIZE,
			.setkey		= aes_set_key,
			.encrypt	= cbc_encrypt,
			.decrypt	= cbc_decrypt,
		},
	},
}, {
	.cra_name		= "ecb(aes)",
	.cra_driver_name	= "ecb-aes-aesni",
	.cra_priority		= 400,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct async_helper_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= ablk_ecb_init,
	.cra_exit		= ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= AES_MIN_KEY_SIZE,
			.max_keysize	= AES_MAX_KEY_SIZE,
			.setkey		= ablk_set_key,
			.encrypt	= ablk_encrypt,
			.decrypt	= ablk_decrypt,
		},
	},
}, {
	.cra_name		= "cbc(aes)",
	.cra_driver_name	= "cbc-aes-aesni",
	.cra_priority		= 400,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct async_helper_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= ablk_cbc_init,
	.cra_exit		= ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= AES_MIN_KEY_SIZE,
			.max_keysize	= AES_MAX_KEY_SIZE,
			.ivsize		= AES_BLOCK_SIZE,
			.setkey		= ablk_set_key,
			.encrypt	= ablk_encrypt,
			.decrypt	= ablk_decrypt,
		},
	},
#ifdef CONFIG_X86_64
}, {
	.cra_name		= "__ctr-aes-aesni",
	.cra_driver_name	= "__driver-ctr-aes-aesni",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_blocksize		= 1,
	.cra_ctxsize		= sizeof(struct crypto_aes_ctx) +
				  AESNI_ALIGN - 1,
	.cra_alignmask		= 0,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_u = {
		.blkcipher = {
			.min_keysize	= AES_MIN_KEY_SIZE,
			.max_keysize	= AES_MAX_KEY_SIZE,
			.ivsize		= AES_BLOCK_SIZE,
			.setkey		= aes_set_key,
			.encrypt	= ctr_crypt,
			.decrypt	= ctr_crypt,
		},
	},
}, {
	.cra_name		= "ctr(aes)",
	.cra_driver_name	= "ctr-aes-aesni",
	.cra_priority		= 400,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= 1,
	.cra_ctxsize		= sizeof(struct async_helper_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= ablk_ctr_init,
	.cra_exit		= ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= AES_MIN_KEY_SIZE,
			.max_keysize	= AES_MAX_KEY_SIZE,
			.ivsize		= AES_BLOCK_SIZE,
			.setkey		= ablk_set_key,
			.encrypt	= ablk_encrypt,
			.decrypt	= ablk_encrypt,
			.geniv		= "chainiv",
		},
	},
}, {
	.cra_name		= "__ccm-aes-aesni",
	.cra_driver_name	= "__driver-ccm-aes-aesni",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_AEAD,
	.cra_blocksize		= 1,
	.cra_ctxsize		= sizeof(struct crypto_aes_ctx) +
				  AESNI_ALIGN - 1,
	.cra_alignmask		= 0,
	.cra_type		= &crypto_aead_type,
	.cra_module		= THIS_MODULE,
	.cra_aead = {
		.ivsize		= AES_BLOCK_SIZE,
		.maxauthsize	= AES_BLOCK_SIZE,
		.setkey		= __ccm_setkey,
		.setauthsize	= __ccm_setauthsize,
		.encrypt	= __ccm_encrypt,
		.decrypt	= __ccm_decrypt,
	},
}, {
	.cra_name		= "ccm(aes)",
	.cra_driver_name	= "ccm-aes-aesni",
	.cra_priority		= 700,
	.cra_flags		= CRYPTO_ALG_TYPE_AEAD |
				  CRYPTO_ALG_NEED_FALLBACK,
	.cra_blocksize		= 1,
	.cra_ctxsize		= AESNI_ALIGN - 1 +
				  sizeof(struct ccm_async_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_aead_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= ccm_init,
	.cra_exit		= ccm_exit,
	.cra_aead = {
		.ivsize		= AES_BLOCK_SIZE,
		.maxauthsize	= AES_BLOCK_SIZE,
		.setkey		= ccm_setkey,
		.setauthsize	= ccm_setauthsize,
		.encrypt	= ccm_encrypt,
		.decrypt	= ccm_decrypt,
	},
}, {
	.cra_name		= "__gcm-aes-aesni",
	.cra_driver_name	= "__driver-gcm-aes-aesni",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_AEAD,
	.cra_blocksize		= 1,
	.cra_ctxsize		= sizeof(struct aesni_rfc4106_gcm_ctx) +
				  AESNI_ALIGN,
	.cra_alignmask		= 0,
	.cra_type		= &crypto_aead_type,
	.cra_module		= THIS_MODULE,
	.cra_u = {
		.aead = {
			.encrypt	= __driver_rfc4106_encrypt,
			.decrypt	= __driver_rfc4106_decrypt,
		},
	},
}, {
	.cra_name		= "rfc4106(gcm(aes))",
	.cra_driver_name	= "rfc4106-gcm-aesni",
	.cra_priority		= 400,
	.cra_flags		= CRYPTO_ALG_TYPE_AEAD | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= 1,
	.cra_ctxsize		= sizeof(struct aesni_rfc4106_gcm_ctx) +
				  AESNI_ALIGN,
	.cra_alignmask		= 0,
	.cra_type		= &crypto_nivaead_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= rfc4106_init,
	.cra_exit		= rfc4106_exit,
	.cra_u = {
		.aead = {
			.setkey		= rfc4106_set_key,
			.setauthsize	= rfc4106_set_authsize,
			.encrypt	= rfc4106_encrypt,
			.decrypt	= rfc4106_decrypt,
			.geniv		= "seqiv",
			.ivsize		= 8,
			.maxauthsize	= 16,
		},
	},
#endif
#if IS_ENABLED(CONFIG_CRYPTO_PCBC)
}, {
	.cra_name		= "pcbc(aes)",
	.cra_driver_name	= "pcbc-aes-aesni",
	.cra_priority		= 400,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct async_helper_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= ablk_pcbc_init,
	.cra_exit		= ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= AES_MIN_KEY_SIZE,
			.max_keysize	= AES_MAX_KEY_SIZE,
			.ivsize		= AES_BLOCK_SIZE,
			.setkey		= ablk_set_key,
			.encrypt	= ablk_encrypt,
			.decrypt	= ablk_decrypt,
		},
	},
#endif
}, {
	.cra_name		= "__lrw-aes-aesni",
	.cra_driver_name	= "__driver-lrw-aes-aesni",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct aesni_lrw_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_exit		= lrw_aesni_exit_tfm,
	.cra_u = {
		.blkcipher = {
			.min_keysize	= AES_MIN_KEY_SIZE + AES_BLOCK_SIZE,
			.max_keysize	= AES_MAX_KEY_SIZE + AES_BLOCK_SIZE,
			.ivsize		= AES_BLOCK_SIZE,
			.setkey		= lrw_aesni_setkey,
			.encrypt	= lrw_encrypt,
			.decrypt	= lrw_decrypt,
		},
	},
}, {
	.cra_name		= "__xts-aes-aesni",
	.cra_driver_name	= "__driver-xts-aes-aesni",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct aesni_xts_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_u = {
		.blkcipher = {
			.min_keysize	= 2 * AES_MIN_KEY_SIZE,
			.max_keysize	= 2 * AES_MAX_KEY_SIZE,
			.ivsize		= AES_BLOCK_SIZE,
			.setkey		= xts_aesni_setkey,
			.encrypt	= xts_encrypt,
			.decrypt	= xts_decrypt,
		},
	},
}, {
	.cra_name		= "lrw(aes)",
	.cra_driver_name	= "lrw-aes-aesni",
	.cra_priority		= 400,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct async_helper_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= ablk_init,
	.cra_exit		= ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= AES_MIN_KEY_SIZE + AES_BLOCK_SIZE,
			.max_keysize	= AES_MAX_KEY_SIZE + AES_BLOCK_SIZE,
			.ivsize		= AES_BLOCK_SIZE,
			.setkey		= ablk_set_key,
			.encrypt	= ablk_encrypt,
			.decrypt	= ablk_decrypt,
		},
	},
}, {
	.cra_name		= "xts(aes)",
	.cra_driver_name	= "xts-aes-aesni",
	.cra_priority		= 400,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct async_helper_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= ablk_init,
	.cra_exit		= ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= 2 * AES_MIN_KEY_SIZE,
			.max_keysize	= 2 * AES_MAX_KEY_SIZE,
			.ivsize		= AES_BLOCK_SIZE,
			.setkey		= ablk_set_key,
			.encrypt	= ablk_encrypt,
			.decrypt	= ablk_decrypt,
		},
	},
} };


static const struct x86_cpu_id aesni_cpu_id[] = {
	X86_FEATURE_MATCH(X86_FEATURE_AES),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, aesni_cpu_id);

static int __init aesni_init(void)
{
	int err;

	if (!x86_match_cpu(aesni_cpu_id))
		return -ENODEV;
#ifdef CONFIG_X86_64
#ifdef CONFIG_AS_AVX2
	if (boot_cpu_has(X86_FEATURE_AVX2)) {
		pr_info("AVX2 version of gcm_enc/dec engaged.\n");
		aesni_gcm_enc_tfm = aesni_gcm_enc_avx2;
		aesni_gcm_dec_tfm = aesni_gcm_dec_avx2;
	} else
#endif
#ifdef CONFIG_AS_AVX
	if (boot_cpu_has(X86_FEATURE_AVX)) {
		pr_info("AVX version of gcm_enc/dec engaged.\n");
		aesni_gcm_enc_tfm = aesni_gcm_enc_avx;
		aesni_gcm_dec_tfm = aesni_gcm_dec_avx;
	} else
#endif
	{
		pr_info("SSE version of gcm_enc/dec engaged.\n");
		aesni_gcm_enc_tfm = aesni_gcm_enc;
		aesni_gcm_dec_tfm = aesni_gcm_dec;
	}
	aesni_ctr_enc_tfm = aesni_ctr_enc;
#ifdef CONFIG_AS_AVX
	if (cpu_has_avx) {
		/* optimize performance of ctr mode encryption transform */
		aesni_ctr_enc_tfm = aesni_ctr_enc_avx_tfm;
		pr_info("AES CTR mode by8 optimization enabled\n");
	}
#endif
#endif

	err = crypto_fpu_init();
	if (err)
		return err;

	return crypto_register_algs(aesni_algs, ARRAY_SIZE(aesni_algs));
}

static void __exit aesni_exit(void)
{
	crypto_unregister_algs(aesni_algs, ARRAY_SIZE(aesni_algs));

	crypto_fpu_exit();
}

module_init(aesni_init);
module_exit(aesni_exit);

MODULE_DESCRIPTION("Rijndael (AES) Cipher Algorithm, Intel AES-NI instructions optimized");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("aes");
