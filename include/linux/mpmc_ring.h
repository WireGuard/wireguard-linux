/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2020-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _MPMC_RING_H
#define _MPMC_RING_H

#include <linux/kernel.h>

struct mpmc_ring {
	void **queue;
	unsigned int mask;
	atomic_t consumer_head ____cacheline_aligned_in_smp;
	atomic_t producer_head ____cacheline_aligned_in_smp;
	atomic_t producer_tail;
};

static inline bool mpmc_ring_empty(struct mpmc_ring *ring)
{
	smp_rmb();
	return atomic_read(&ring->producer_tail) == atomic_read(&ring->consumer_head);
}

static inline int mpmc_ring_produce(struct mpmc_ring *ring, void *val)
{
	int producer = atomic_read(&ring->producer_head), new_producer, consumer;
	const unsigned int mask = ring->mask;

	for (;;) {
		smp_rmb();
		consumer = atomic_read(&ring->consumer_head);
		if (likely((producer - consumer) < mask)) {
			if (atomic_try_cmpxchg_relaxed(&ring->producer_head, &producer, producer + 1))
				break;
		} else {
			smp_rmb();
			new_producer = atomic_read(&ring->producer_head);
			if (new_producer == producer)
				return -ENOSPC;
			producer = new_producer;
		}
	}
	WRITE_ONCE(ring->queue[producer & mask], val);
	while (atomic_read(&ring->producer_tail) != producer)
		cpu_relax();
	smp_wmb();
	atomic_set(&ring->producer_tail, producer + 1);
	return 0;
}

static inline void *mpmc_ring_consume(struct mpmc_ring *ring)
{
	int consumer = atomic_read(&ring->consumer_head), producer;
	const unsigned int mask = ring->mask;
	void *val;

	do {
		smp_rmb();
		producer = atomic_read(&ring->producer_tail);
		if (unlikely(consumer == producer))
			return NULL;
		val = READ_ONCE(ring->queue[consumer & mask]);
	} while (!atomic_try_cmpxchg_release(&ring->consumer_head, &consumer, consumer + 1));
	return val;
}

/* Single consumer only. */
static inline void *__mpmc_ring_peek(struct mpmc_ring *ring)
{
	unsigned int consumer = atomic_read(&ring->consumer_head), producer;
	const unsigned int mask = ring->mask;

	smp_rmb();
	producer = atomic_read(&ring->producer_tail);
	if (unlikely(consumer == producer))
		return NULL;
	smp_rmb();
	return READ_ONCE(ring->queue[consumer & mask]);
}

/* Single consumer only. */
static inline void __mpmc_ring_discard_one(struct mpmc_ring *ring)
{
	smp_mb__before_atomic();
	atomic_inc(&ring->consumer_head);
}

static inline int mpmc_ring_init(struct mpmc_ring *ring, unsigned int size, gfp_t gfp)
{
	if (size > KMALLOC_MAX_SIZE / sizeof(void *))
                return -EOVERFLOW;
	if (!is_power_of_2(size))
		return -EINVAL;
	if (size < nr_cpu_ids)
		return -EUSERS;
	ring->mask = size - 1;
	atomic_set(&ring->consumer_head, 0);
	atomic_set(&ring->producer_head, 0);
	atomic_set(&ring->producer_tail, 0);
	ring->queue = kvmalloc_array(size, sizeof(ring->queue[0]), gfp | __GFP_ZERO);
	if (!ring->queue)
		return -ENOMEM;
	return 0;
}

static inline void mpmc_ring_cleanup(struct mpmc_ring *ring, void (*destroy)(void *))
{
	void *val;

	if (destroy) {
		while ((val = mpmc_ring_consume(ring)))
			destroy(val);
	}
	kvfree(ring->queue);
}

#endif
