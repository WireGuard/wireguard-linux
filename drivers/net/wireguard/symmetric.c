// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2012 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "queueing.h"
#include "messages.h"
#include "timers.h"

static unsigned int calculate_skb_padding(struct sk_buff *skb)
{
	unsigned int padded_size, last_unit = skb->len;

	if (unlikely(!PACKET_CB(skb)->mtu))
		return ALIGN(last_unit, MESSAGE_PADDING_MULTIPLE) - last_unit;

	/* We do this modulo business with the MTU, just in case the networking
	 * layer gives us a packet that's bigger than the MTU. In that case, we
	 * wouldn't want the final subtraction to overflow in the case of the
	 * padded_size being clamped. Fortunately, that's very rarely the case,
	 * so we optimize for that not happening.
	 */
	if (unlikely(last_unit > PACKET_CB(skb)->mtu))
		last_unit %= PACKET_CB(skb)->mtu;

	padded_size = min(PACKET_CB(skb)->mtu,
			  ALIGN(last_unit, MESSAGE_PADDING_MULTIPLE));
	return padded_size - last_unit;
}

static bool encrypt_packet(struct sk_buff *skb, struct noise_keypair *keypair)
{
	unsigned int padding_len, plaintext_len, trailer_len;
	struct scatterlist sg[MAX_SKB_FRAGS + 8];
	struct message_data *header;
	struct sk_buff *trailer;
	int num_frags;

	/* Calculate lengths. */
	padding_len = calculate_skb_padding(skb);
	trailer_len = padding_len + noise_encrypted_len(0);
	plaintext_len = skb->len + padding_len;

	/* Expand data section to have room for padding and auth tag. */
	num_frags = skb_cow_data(skb, trailer_len, &trailer);
	if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg)))
		return false;

	/* Set the padding to zeros, and make sure it and the auth tag are part
	 * of the skb.
	 */
	memset(skb_tail_pointer(trailer), 0, padding_len);

	/* Expand head section to have room for our header and the network
	 * stack's headers.
	 */
	if (unlikely(skb_cow_head(skb, DATA_PACKET_HEAD_ROOM) < 0))
		return false;

	/* Finalize checksum calculation for the inner packet, if required. */
	if (unlikely(skb->ip_summed == CHECKSUM_PARTIAL &&
		     skb_checksum_help(skb)))
		return false;

	/* Only after checksumming can we safely add on the padding at the end
	 * and the header.
	 */
	skb_set_inner_network_header(skb, 0);
	header = (struct message_data *)skb_push(skb, sizeof(*header));
	header->header.type = cpu_to_le32(MESSAGE_DATA);
	header->key_idx = keypair->remote_index;
	header->counter = cpu_to_le64(PACKET_CB(skb)->nonce);
	pskb_put(skb, trailer, trailer_len);

	/* Now we can encrypt the scattergather segments */
	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, sizeof(struct message_data),
			 noise_encrypted_len(plaintext_len)) <= 0)
		return false;
	return chacha20poly1305_encrypt_sg_inplace(sg, plaintext_len, NULL, 0,
						   PACKET_CB(skb)->nonce,
						   keypair->sending.key);
}

static bool decrypt_packet(struct sk_buff *skb, struct noise_symmetric_key *key)
{
	struct scatterlist sg[MAX_SKB_FRAGS + 8];
	struct sk_buff *trailer;
	unsigned int offset;
	int num_frags;

	if (unlikely(!key))
		return false;

	if (unlikely(!READ_ONCE(key->is_valid) ||
		  wg_birthdate_has_expired(key->birthdate, REJECT_AFTER_TIME) ||
		  key->counter.receive.counter >= REJECT_AFTER_MESSAGES)) {
		WRITE_ONCE(key->is_valid, false);
		return false;
	}

	PACKET_CB(skb)->nonce =
		le64_to_cpu(((struct message_data *)skb->data)->counter);

	/* We ensure that the network header is part of the packet before we
	 * call skb_cow_data, so that there's no chance that data is removed
	 * from the skb, so that later we can extract the original endpoint.
	 */
	offset = skb->data - skb_network_header(skb);
	skb_push(skb, offset);
	num_frags = skb_cow_data(skb, 0, &trailer);
	offset += sizeof(struct message_data);
	skb_pull(skb, offset);
	if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg)))
		return false;

	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, 0, skb->len) <= 0)
		return false;

	if (!chacha20poly1305_decrypt_sg_inplace(sg, skb->len, NULL, 0,
						 PACKET_CB(skb)->nonce,
						 key->key))
		return false;

	/* Another ugly situation of pushing and pulling the header so as to
	 * keep endpoint information intact.
	 */
	skb_push(skb, offset);
	if (pskb_trim(skb, skb->len - noise_encrypted_len(0)))
		return false;
	skb_pull(skb, offset);

	return true;
}

void wg_packet_crypt_worker(struct work_struct *work)
{
	struct crypt_queue *queue = container_of(work, struct multicore_worker,
						 work)->ptr;
	struct sk_buff *first, *skb, *next;

	while ((first = ptr_ring_consume_bh(&queue->ring)) != NULL) {
		switch (atomic_read_acquire(&PACKET_CB(first)->state)) {
		case PACKET_STATE_NOT_ENCRYPTED: {
			enum packet_state state = PACKET_STATE_ENCRYPTED;

			skb_list_walk_safe(first, skb, next) {
				if (likely(encrypt_packet(skb,
						PACKET_CB(first)->keypair))) {
					wg_reset_packet(skb);
				} else {
					state = PACKET_STATE_DEAD;
					break;
				}
			}
			wg_queue_enqueue_per_peer(&PACKET_PEER(first)->tx_queue,
						  first, state);
			break;
		}
		case PACKET_STATE_NOT_DECRYPTED: {
			enum packet_state state = likely(decrypt_packet(first,
					&PACKET_CB(first)->keypair->receiving)) ?
					PACKET_STATE_DECRYPTED : PACKET_STATE_DEAD;
			wg_queue_enqueue_per_peer_napi(first, state);
			break;
		}
		}
	}
}
