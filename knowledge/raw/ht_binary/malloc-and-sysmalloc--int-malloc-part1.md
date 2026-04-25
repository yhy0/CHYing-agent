# malloc & sysmalloc - Int Malloc

## \_int_malloc <a href="#int_malloc" id="int_malloc"></a>


This is the function that allocates memory using the other bins and top chunk.

- Start

It starts defining some vars and getting the real size the request memory space need to have:

<details>

<summary>_int_malloc start</summary>

```c
// From https://github.com/bminor/glibc/blob/f942a732d37a96217ef828116ebe64a644db18d7/malloc/malloc.c#L3847
static void *
_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* normalized request size */
  unsigned int idx;                 /* associated bin index */
  mbinptr bin;                      /* associated bin */

  mchunkptr victim;                 /* inspected/selected chunk */
  INTERNAL_SIZE_T size;             /* its size */
  int victim_index;                 /* its bin index */

  mchunkptr remainder;              /* remainder from a split */
  unsigned long remainder_size;     /* its size */

  unsigned int block;               /* bit map traverser */
  unsigned int bit;                 /* bit map traverser */
  unsigned int map;                 /* current word of binmap */

  mchunkptr fwd;                    /* misc temp for linking */
  mchunkptr bck;                    /* misc temp for linking */

#if USE_TCACHE
  size_t tcache_unsorted_count;	    /* count of unsorted chunks processed */
#endif

  /*
     Convert request size to internal form by adding SIZE_SZ bytes
     overhead plus possibly more to obtain necessary alignment and/or
     to obtain a size of at least MINSIZE, the smallest allocatable
     size. Also, checked_request2size returns false for request sizes
     that are so large that they wrap around zero when padded and
     aligned.
   */

  nb = checked_request2size (bytes);
  if (nb == 0)
    {
      __set_errno (ENOMEM);
      return NULL;
    }
```

</details>

### Arena

In the unlikely event that there aren't usable arenas, it uses `sysmalloc` to get a chunk from `mmap`:

<details>

<summary>_int_malloc not arena</summary>

```c
// From https://github.com/bminor/glibc/blob/f942a732d37a96217ef828116ebe64a644db18d7/malloc/malloc.c#L3885C3-L3893C6
/* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
  if (__glibc_unlikely (av == NULL))
    {
      void *p = sysmalloc (nb, av);
      if (p != NULL)
	alloc_perturb (p, bytes);
      return p;
    }
```

</details>

### Fast Bin

If the needed size is inside the Fast Bins sizes, try to use a chunk from the fast bin. Basically, based on the size, it'll find the fast bin index where valid chunks should be located, and if any, it'll return one of those.\
Moreover, if tcache is enabled, it'll **fill the tcache bin of that size with fast bins**.

While performing these actions, some security checks are executed in here:

- If the chunk is misaligned: `malloc(): unaligned fastbin chunk detected 2`
- If the forward chunk is misaligned: `malloc(): unaligned fastbin chunk detected`
- If the returned chunk has a size that isn't correct because of it's index in the fast bin: `malloc(): memory corruption (fast)`
- If any chunk used to fill the tcache is misaligned: `malloc(): unaligned fastbin chunk detected 3`

<details>

<summary>_int_malloc fast bin</summary>

```c
// From https://github.com/bminor/glibc/blob/f942a732d37a96217ef828116ebe64a644db18d7/malloc/malloc.c#L3895C3-L3967C6
/*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

#define REMOVE_FB(fb, victim, pp)			\
  do							\
    {							\
      victim = pp;					\
      if (victim == NULL)				\
	break;						\
      pp = REVEAL_PTR (victim->fd);                                     \
      if (__glibc_unlikely (pp != NULL && misaligned_chunk (pp)))       \
	malloc_printerr ("malloc(): unaligned fastbin chunk detected"); \
    }							\
  while ((pp = catomic_compare_and_exchange_val_acq (fb, pp, victim)) \
	 != victim);					\

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp;
      victim = *fb;

      if (victim != NULL)
	{
	  if (__glibc_unlikely (misaligned_chunk (victim)))
	    malloc_printerr ("malloc(): unaligned fastbin chunk detected 2");

	  if (SINGLE_THREAD_P)
	    *fb = REVEAL_PTR (victim->fd);
	  else
	    REMOVE_FB (fb, pp, victim);
	  if (__glibc_likely (victim != NULL))
	    {
	      size_t victim_idx = fastbin_index (chunksize (victim));
	      if (__builtin_expect (victim_idx != idx, 0))
		malloc_printerr ("malloc(): memory corruption (fast)");
	      check_remalloced_chunk (av, victim, nb);
#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache != NULL && tc_idx < mp_.tcache_bins)
		{
		  mchunkptr tc_victim;

		  /* While bin not empty and tcache not full, copy chunks.  */
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
		    {
		      if (__glibc_unlikely (misaligned_chunk (tc_victim)))
			malloc_printerr ("malloc(): unaligned fastbin chunk detected 3");
		      if (SINGLE_THREAD_P)
			*fb = REVEAL_PTR (tc_victim->fd);
		      else
			{
			  REMOVE_FB (fb, pp, tc_victim);
			  if (__glibc_unlikely (tc_victim == NULL))
			    break;
			}
		      tcache_put (tc_victim, tc_idx);
		    }
		}
#endif
	      void *p = chunk2mem (victim);
	      alloc_perturb (p, bytes);
	      return p;
	    }
	}
    }
```

</details>

### Small Bin

As indicated in a comment, small bins hold one size per index, therefore checking if a valid chunk is available is super fast, so after fast bins, small bins are checked.

The first check is to find out if the requested size could be inside a small bin. In that case, get the corresponded **index** inside the smallbin and see if there is **any available chunk**.

Then, a security check is performed checking:

- if `victim->bk->fd = victim`. To see that both chunks are correctly linked.

In that case, the chunk **gets the `inuse` bit,** the doubled linked list is fixed so this chunk disappears from it (as it's going to be used), and the non main arena bit is set if needed.

Finally, **fill the tcache index of the requested size** with other chunks inside the small bin (if any).

<details>

<summary>_int_malloc small bin</summary>

```c
// From https://github.com/bminor/glibc/blob/f942a732d37a96217ef828116ebe64a644db18d7/malloc/malloc.c#L3895C3-L3967C6

/*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
   */

  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;

          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache != NULL && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```

</details>

### malloc_consolidate

If it wasn't a small chunk, it's a large chunk, and in this case **`malloc_consolidate`** is called to avoid memory fragmentation.

<details>

<summary>malloc_consolidate call</summary>

```c
/*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
   */

  else
    {
      idx = largebin_index (nb);
      if (atomic_load_relaxed (&av->have_fastchunks))
        malloc_consolidate (av);
    }

```

</details>

The malloc consolidate function basically removes chunks from the fast bin and places them into the unsorted bin. After the next malloc these chunks will be organized in their respective small/fast bins.

Note that if while removing these chunks, if they are found with previous or next chunks that aren't in use they will be **unliked and merged** before placing the final chunk in the **unsorted** bin.

For each fast bin chunk a couple of security checks are performed:

- If the chunk is unaligned trigger: `malloc_consolidate(): unaligned fastbin chunk detected`
- If the chunk has a different size that the one it should because of the index it's in: `malloc_consolidate(): invalid chunk size`
- If the previous chunk is not in use and the previous chunk has a size different of the one indicated by `prev_chunk`: `corrupted size vs. prev_size in fastbins`

<details>

<summary>malloc_consolidate function</summary>

```c
// https://github.com/bminor/glibc/blob/f942a732d37a96217ef828116ebe64a644db18d7/malloc/malloc.c#L4810C1-L4905C2

static void malloc_consolidate(mstate av)
{
  mfastbinptr*    fb;                 /* current fastbin being consolidated */
  mfastbinptr*    maxfb;              /* last fastbin (for loop control) */
  mchunkptr       p;                  /* current chunk being consolidated */
  mchunkptr       nextp;              /* next chunk to consolidate */
  mchunkptr       unsorted_bin;       /* bin header */
  mchunkptr       first_unsorted;     /* chunk to link to */

  /* These have same use as in free() */
  mchunkptr       nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int             nextinuse;

  atomic_store_relaxed (&av->have_fastchunks, false);

  unsorted_bin = unsorted_chunks(av);

  /*
    Remove each chunk from fast bin and consolidate it, placing it
    then in unsorted bin. Among other reasons for doing this,
    placing in unsorted bin avoids needing to calculate actual bins
    until malloc is sure that chunks aren't immediately going to be
    reused anyway.
  */

  maxfb = &fastbin (av, NFASTBINS - 1);
  fb = &fastbin (av, 0);
  do {
    p = atomic_exchange_acquire (fb, NULL);
    if (p != 0) {
      do {
	{
	  if (__glibc_unlikely (misaligned_chunk (p)))
	    malloc_printerr ("malloc_consolidate(): "
			     "unaligned fastbin chunk detected");

	  unsigned int idx = fastbin_index (chunksize (p));
	  if ((&fastbin (av, idx)) != fb)
	    malloc_printerr ("malloc_consolidate(): invalid chunk size");
	}

	check_inuse_chunk(av, p);
	nextp = REVEAL_PTR (p->fd);

	/* Slightly streamlined version of consolidation code in free() */
	size = chunksize (p);
	nextchunk = chunk_at_offset(p, size);
	nextsize = chunksize(nextchunk);

	if (!prev_inuse(p)) {
	  prevsize = prev_size (p);
	  size += prevsize;
	  p = chunk_at_offset(p, -((long) prevsize));
	  if (__glibc_unlikely (chunksize(p) != prevsize))
	    malloc_printerr ("corrupted size vs. prev_size in fastbins");
	  unlink_chunk (av, p);
	}

	if (nextchunk != av->top) {
	  nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

	  if (!nextinuse) {
	    size += nextsize;
	    unlink_chunk (av, nextchunk);
	  } else
	    clear_inuse_bit_at_offset(nextchunk, 0);

	  first_unsorted = unsorted_bin->fd;
	  unsorted_bin->fd = p;
	  first_unsorted->bk = p;

	  if (!in_smallbin_range (size)) {
	    p->fd_nextsize = NULL;
	    p->bk_nextsize = NULL;
	  }

	  set_head(p, size | PREV_INUSE);
	  p->bk = unsorted_bin;
	  p->fd = first_unsorted;
	  set_foot(p, size);
	}

	else {
	  size += nextsize;
	  set_head(p, size | PREV_INUSE);
	  av->top = p;
	}

      } while ( (p = nextp) != 0);

    }
  } while (fb++ != maxfb);
}
```

</details>

### Unsorted bin

It's time to check the unsorted bin for a potential valid chunk to use.

#### Start

This starts with a big for look that will be traversing the unsorted bin in the `bk` direction until it arrives til the end (the arena struct) with `while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))`

Moreover, some security checks are perform every time a new chunk is considered:

- If the chunk size is weird (too small or too big): `malloc(): invalid size (unsorted)`
- If the next chunk size is weird (too small or too big): `malloc(): invalid next size (unsorted)`
- If the previous size indicated by the next chunk differs from the size of the chunk: `malloc(): mismatching next->prev_size (unsorted)`
- If not `victim->bck->fd == victim` or not `victim->fd == av` (arena): `malloc(): unsorted double linked list corrupted`
  - As we are always checking the las one, it's `fd` should be pointing always to the arena struct.
- If the next chunk isn't indicating that the previous is in use: `malloc(): invalid next->prev_inuse (unsorted)`

<details>

<summary><code>_int_malloc</code> unsorted bin start</summary>

```c
/*
     Process recently freed or remaindered chunks, taking one only if
     it is exact fit, or, if this a small request, the chunk is remainder from
     the most recent non-exact fit.  Place other traversed chunks in
     bins.  Note that this step is the only place in any routine where
     chunks are placed in bins.

     The outer loop here is needed because we might not realize until
     near the end of malloc that we should have consolidated, so must
     do so and retry. This happens at most once, and only when we would
     otherwise need to expand memory to service a "small" request.
   */

#if USE_TCACHE
  INTERNAL_SIZE_T tcache_nb = 0;
  size_t tc_idx = csize2tidx (nb);
  if (tcache != NULL && tc_idx < mp_.tcache_bins)
    tcache_nb = nb;
  int return_cached = 0;

  tcache_unsorted_count = 0;
#endif

  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          size = chunksize (victim);
          mchunkptr next = chunk_at_offset (victim, size);

          if (__glibc_unlikely (size <= CHUNK_HDR_SZ)
              || __glibc_unlikely (size > av->system_mem))
            malloc_printerr ("malloc(): invalid size (unsorted)");
          if (__glibc_unlikely (chunksize_nomask (next) < CHUNK_HDR_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");

```

</details>

#### if `in_smallbin_range`

If the chunk is bigger than the requested size use it, and set the rest of the chunk space into the unsorted list and update the `last_remainder` with it.

<details>

<summary><code>_int_malloc</code> unsorted bin <code>in_smallbin_range</code></summary>

```c
// From https://github.com/bminor/glibc/blob/master/malloc/malloc.c#L4090C11-L4124C14

/*
             If a small request, try to use last remainder if it is the
             only chunk in unsorted bin.  This helps promote locality for
             runs of consecutive small requests. This is the only
             exception to best-fit, and applies only when there is
             no exact fit for a small chunk.
           */

          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
