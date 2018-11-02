static struct bio_slab *bio_slabs;
static unsigned int bio_slab_nr, bio_slab_max;

static struct kmem_cache *bio_find_or_create_slab(unsigned int extra_size)
{
	unsigned int sz = sizeof(struct bio) + extra_size;
	struct kmem_cache *slab = NULL;
	struct bio_slab *bslab, *new_bio_slabs;
	unsigned int new_bio_slab_max;
	unsigned int i, entry = -1;

	mutex_lock(&bio_slab_lock);

	i = 0;
	while (i < bio_slab_nr) {
		bslab = &bio_slabs[i];

		if (!bslab->slab && entry == -1)
			entry = i;
		else if (bslab->slab_size == sz) {
			slab = bslab->slab;
			bslab->slab_ref++;
			break;
		}
		i++;
	}

	if (slab)
		goto out_unlock;

	if (bio_slab_nr == bio_slab_max && entry == -1) {
		new_bio_slab_max = bio_slab_max << 1;
		new_bio_slabs = krealloc(bio_slabs,
					 new_bio_slab_max * sizeof(struct bio_slab),
					 GFP_KERNEL);
		if (!new_bio_slabs)
			goto out_unlock;
		bio_slab_max = new_bio_slab_max;
		bio_slabs = new_bio_slabs;
	}
	if (entry == -1)
		entry = bio_slab_nr++;

	bslab = &bio_slabs[entry];

	snprintf(bslab->name, sizeof(bslab->name), "bio-%d", entry);
	slab = kmem_cache_create(bslab->name, sz, ARCH_KMALLOC_MINALIGN,
				 SLAB_HWCACHE_ALIGN, NULL);
	if (!slab)
		goto out_unlock;

	bslab->slab = slab;
	bslab->slab_ref = 1;
	bslab->slab_size = sz;
out_unlock:
	mutex_unlock(&bio_slab_lock);
	return slab;
}

static void bio_put_slab(struct bio_set *bs)
{
	struct bio_slab *bslab = NULL;
	unsigned int i;

	mutex_lock(&bio_slab_lock);

	for (i = 0; i < bio_slab_nr; i++) {
		if (bs->bio_slab == bio_slabs[i].slab) {
			bslab = &bio_slabs[i];
			break;
		}
	}

	if (WARN(!bslab, KERN_ERR "bio: unable to find slab!\n"))
		goto out;

	WARN_ON(!bslab->slab_ref);

	if (--bslab->slab_ref)
		goto out;

	kmem_cache_destroy(bslab->slab);
	bslab->slab = NULL;

out:
	mutex_unlock(&bio_slab_lock);
}

unsigned int bvec_nr_vecs(unsigned short idx)
{
	return bvec_slabs[--idx].nr_vecs;
}

void bvec_free(mempool_t *pool, struct bio_vec *bv, unsigned int idx)
{
	if (!idx)
		return;
	idx--;

	BIO_BUG_ON(idx >= BVEC_POOL_NR);

	if (idx == BVEC_POOL_MAX) {
		mempool_free(bv, pool);
	} else {
		struct biovec_slab *bvs = bvec_slabs + idx;

		kmem_cache_free(bvs->slab, bv);
	}
}

struct bio_vec *bvec_alloc(gfp_t gfp_mask, int nr, unsigned long *idx,
			   mempool_t *pool)
{
	struct bio_vec *bvl;


	switch (nr) {
	case 1:
		*idx = 0;
		break;
	case 2 ... 4:
		*idx = 1;
		break;
	case 5 ... 16:
		*idx = 2;
		break;
	case 17 ... 64:
		*idx = 3;
		break;
	case 65 ... 128:
		*idx = 4;
		break;
	case 129 ... BIO_MAX_PAGES:
		*idx = 5;
		break;
	default:
		return NULL;
	}

try pool is mempool backed.
	 
	if (*idx == BVEC_POOL_MAX) {
fallback:
		bvl = mempool_alloc(pool, gfp_mask);
	} else {
		struct biovec_slab *bvs = bvec_slabs + *idx;
		gfp_t __gfp_mask = gfp_mask & ~(__GFP_DIRECT_RECLAIM | __GFP_IO);

		
		__gfp_mask |= __GFP_NOMEMALLOC | __GFP_NORETRY | __GFP_NOWARN;

	
		bvl = kmem_cache_alloc(bvs->slab, __gfp_mask);
		if (unlikely(!bvl && (gfp_mask & __GFP_DIRECT_RECLAIM))) {
			*idx = BVEC_POOL_MAX;
			goto fallback;
		}
	}

	(*idx)++;
	return bvl;
}

void bio_uninit(struct bio *bio)
{
	bio_disassociate_task(bio);
}
EXPORT_SYMBOL(bio_uninit);

static void bio_free(struct bio *bio)
{
	struct bio_set *bs = bio->bi_pool;
	void *p;

	bio_uninit(bio);

	if (bs) {
		bvec_free(&bs->bvec_pool, bio->bi_io_vec, BVEC_POOL_IDX(bio));

		
		p = bio;
		p -= bs->front_pad;

		mempool_free(p, &bs->bio_pool);
	} else {
		kfree(bio);
	}
}



void bio_init(struct bio *bio, struct bio_vec *table,
	      unsigned short max_vecs)
{
	memset(bio, 0, sizeof(*bio));
	atomic_set(&bio->__bi_remaining, 1);
	atomic_set(&bio->__bi_cnt, 1);

	bio->bi_io_vec = table;
	bio->bi_max_vecs = max_vecs;
}
EXPORT_SYMBOL(bio_init);

void bio_reset(struct bio *bio)
{
	unsigned long flags = bio->bi_flags & (~0UL << BIO_RESET_BITS);

	bio_uninit(bio);

	memset(bio, 0, BIO_RESET_BYTES);
	bio->bi_flags = flags;
	atomic_set(&bio->__bi_remaining, 1);
}
EXPORT_SYMBOL(bio_reset);

static struct bio *__bio_chain_endio(struct bio *bio)
{
	struct bio *parent = bio->bi_private;

	if (!parent->bi_status)
		parent->bi_status = bio->bi_status;
	bio_put(bio);
	return parent;
}

static void bio_chain_endio(struct bio *bio)
{
	bio_endio(__bio_chain_endio(bio));
}

void bio_chain(struct bio *bio, struct bio *parent)
{
	BUG_ON(bio->bi_private || bio->bi_end_io);

	bio->bi_private = parent;
	bio->bi_end_io	= bio_chain_endio;
	bio_inc_remaining(parent);
}
EXPORT_SYMBOL(bio_chain);

static void bio_alloc_rescue(struct work_struct *work)
{
	struct bio_set *bs = container_of(work, struct bio_set, rescue_work);
	struct bio *bio;

	while (1) {
		spin_lock(&bs->rescue_lock);
		bio = bio_list_pop(&bs->rescue_list);
		spin_unlock(&bs->rescue_lock);

		if (!bio)
			break;

		generic_make_request(bio);
	}
}

static void punt_bios_to_rescuer(struct bio_set *bs)
{
	struct bio_list punt, nopunt;
	struct bio *bio;

	if (WARN_ON_ONCE(!bs->rescue_workqueue))
		return;


	bio_list_init(&punt);
	bio_list_init(&nopunt);

	while ((bio = bio_list_pop(&current->bio_list[0])))
		bio_list_add(bio->bi_pool == bs ? &punt : &nopunt, bio);
	current->bio_list[0] = nopunt;

	bio_list_init(&nopunt);
	while ((bio = bio_list_pop(&current->bio_list[1])))
		bio_list_add(bio->bi_pool == bs ? &punt : &nopunt, bio);
	current->bio_list[1] = nopunt;

	spin_lock(&bs->rescue_lock);
	bio_list_merge(&bs->rescue_list, &punt);
	spin_unlock(&bs->rescue_lock);

	queue_work(bs->rescue_workqueue, &bs->rescue_work);
}


struct bio *bio_alloc_bioset(gfp_t gfp_mask, unsigned int nr_iovecs,
			     struct bio_set *bs)
{
	gfp_t saved_gfp = gfp_mask;
	unsigned front_pad;
	unsigned inline_vecs;
	struct bio_vec *bvl = NULL;
	struct bio *bio;
	void *p;

	if (!bs) {
		if (nr_iovecs > UIO_MAXIOV)
			return NULL;

		p = kmalloc(sizeof(struct bio) +
			    nr_iovecs * sizeof(struct bio_vec),
			    gfp_mask);
		front_pad = 0;
		inline_vecs = nr_iovecs;
	} else {
		if (WARN_ON_ONCE(!mempool_initialized(&bs->bvec_pool) &&
				 nr_iovecs > 0))
			return NULL;


		if (current->bio_list &&
		    (!bio_list_empty(&current->bio_list[0]) ||
		     !bio_list_empty(&current->bio_list[1])) &&
		    bs->rescue_workqueue)
			gfp_mask &= ~__GFP_DIRECT_RECLAIM;

		p = mempool_alloc(&bs->bio_pool, gfp_mask);
		if (!p && gfp_mask != saved_gfp) {
			punt_bios_to_rescuer(bs);
			gfp_mask = saved_gfp;
			p = mempool_alloc(&bs->bio_pool, gfp_mask);
		}

		front_pad = bs->front_pad;
		inline_vecs = BIO_INLINE_VECS;
	}

	if (unlikely(!p))
		return NULL;

	bio = p + front_pad;
	bio_init(bio, NULL, 0);

	if (nr_iovecs > inline_vecs) {
		unsigned long idx = 0;

		bvl = bvec_alloc(gfp_mask, nr_iovecs, &idx, &bs->bvec_pool);
		if (!bvl && gfp_mask != saved_gfp) {
			punt_bios_to_rescuer(bs);
			gfp_mask = saved_gfp;
			bvl = bvec_alloc(gfp_mask, nr_iovecs, &idx, &bs->bvec_pool);
		}

		if (unlikely(!bvl))
			goto err_free;

		bio->bi_flags |= idx << BVEC_POOL_OFFSET;
	} else if (nr_iovecs) {
		bvl = bio->bi_inline_vecs;
	}

	bio->bi_pool = bs;
	bio->bi_max_vecs = nr_iovecs;
	bio->bi_io_vec = bvl;
	return bio;

err_free:
	mempool_free(p, &bs->bio_pool);
	return NULL;
}
EXPORT_SYMBOL(bio_alloc_bioset);

void zero_fill_bio_iter(struct bio *bio, struct bvec_iter start)
{
	unsigned long flags;
	struct bio_vec bv;
	struct bvec_iter iter;

	__bio_for_each_segment(bv, bio, iter, start) {
		char *data = bvec_kmap_irq(&bv, &flags);
		memset(data, 0, bv.bv_len);
		flush_dcache_page(bv.bv_page);
		bvec_kunmap_irq(data, &flags);
	}
}
EXPORT_SYMBOL(zero_fill_bio_iter);


void bio_put(struct bio *bio)
{
	if (!bio_flagged(bio, BIO_REFFED))
		bio_free(bio);
	else {
		BIO_BUG_ON(!atomic_read(&bio->__bi_cnt));

		
		if (atomic_dec_and_test(&bio->__bi_cnt))
			bio_free(bio);
	}
}
EXPORT_SYMBOL(bio_put);

inline int bio_phys_segments(struct request_queue *q, struct bio *bio)
{
	if (unlikely(!bio_flagged(bio, BIO_SEG_VALID)))
		blk_recount_segments(q, bio);

	return bio->bi_phys_segments;
}
EXPORT_SYMBOL(bio_phys_segments);


void __bio_clone_fast(struct bio *bio, struct bio *bio_src)
{
	BUG_ON(bio->bi_pool && BVEC_POOL_IDX(bio));


	bio->bi_disk = bio_src->bi_disk;
	bio->bi_partno = bio_src->bi_partno;
	bio_set_flag(bio, BIO_CLONED);
	if (bio_flagged(bio_src, BIO_THROTTLED))
		bio_set_flag(bio, BIO_THROTTLED);
	bio->bi_opf = bio_src->bi_opf;
	bio->bi_write_hint = bio_src->bi_write_hint;
	bio->bi_iter = bio_src->bi_iter;
	bio->bi_io_vec = bio_src->bi_io_vec;

	bio_clone_blkcg_association(bio, bio_src);
}
EXPORT_SYMBOL(__bio_clone_fast);


struct bio *bio_clone_fast(struct bio *bio, gfp_t gfp_mask, struct bio_set *bs)
{
	struct bio *b;

	b = bio_alloc_bioset(gfp_mask, 0, bs);
	if (!b)
		return NULL;

	__bio_clone_fast(b, bio);

	if (bio_integrity(bio)) {
		int ret;

		ret = bio_integrity_clone(b, bio, gfp_mask);

		if (ret < 0) {
			bio_put(b);
			return NULL;
		}
	}

	return b;
}
EXPORT_SYMBOL(bio_clone_fast);

int bio_add_pc_page(struct request_queue *q, struct bio *bio, struct page
		    *page, unsigned int len, unsigned int offset)
{
	int retried_segments = 0;
	struct bio_vec *bvec;

	if (unlikely(bio_flagged(bio, BIO_CLONED)))
		return 0;

	if (((bio->bi_iter.bi_size + len) >> 9) > queue_max_hw_sectors(q))
		return 0;

	
	if (bio->bi_vcnt > 0) {
		struct bio_vec *prev = &bio->bi_io_vec[bio->bi_vcnt - 1];

		if (page == prev->bv_page &&
		    offset == prev->bv_offset + prev->bv_len) {
			prev->bv_len += len;
			bio->bi_iter.bi_size += len;
			goto done;
		}

		if (bvec_gap_to_prev(q, prev, offset))
			return 0;
	}

	if (bio_full(bio))
		return 0;

	bvec = &bio->bi_io_vec[bio->bi_vcnt];
	bvec->bv_page = page;
	bvec->bv_len = len;
	bvec->bv_offset = offset;
	bio->bi_vcnt++;
	bio->bi_phys_segments++;
	bio->bi_iter.bi_size += len;

	
	while (bio->bi_phys_segments > queue_max_segments(q)) {

		if (retried_segments)
			goto failed;

		retried_segments = 1;
		blk_recount_segments(q, bio);
}
