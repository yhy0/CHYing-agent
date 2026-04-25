# malloc & sysmalloc - Sysmalloc

## sysmalloc


### sysmalloc start

If arena is null or the requested size is too big (and there are mmaps left permitted) use `sysmalloc_mmap` to allocate space and return it.

<details>

<summary>sysmalloc start</summary>

```c
// From https://github.com/bminor/glibc/blob/f942a732d37a96217ef828116ebe64a644db18d7/malloc/malloc.c#L2531

/*
   sysmalloc handles malloc cases requiring more memory from the system.
   On entry, it is assumed that av->top does not have enough
   space to service request for nb bytes, thus requiring that av->top
   be extended or replaced.
 */

 static void *
sysmalloc (INTERNAL_SIZE_T nb, mstate av)
{
  mchunkptr old_top;              /* incoming value of av->top */
  INTERNAL_SIZE_T old_size;       /* its size */
  char *old_end;                  /* its end address */

  long size;                      /* arg to first MORECORE or mmap call */
  char *brk;                      /* return value from MORECORE */

  long correction;                /* arg to 2nd MORECORE call */
  char *snd_brk;                  /* 2nd return val */

  INTERNAL_SIZE_T front_misalign; /* unusable bytes at front of new space */
  INTERNAL_SIZE_T end_misalign;   /* partial page left at end of new space */
  char *aligned_brk;              /* aligned offset into brk */

  mchunkptr p;                    /* the allocated/returned chunk */
  mchunkptr remainder;            /* remainder from allocation */
  unsigned long remainder_size;   /* its size */

  size_t pagesize = GLRO (dl_pagesize);
  bool tried_mmap = false;

  /*
     If have mmap, and the request size meets the mmap threshold, and
     the system supports mmap, and there are few enough currently
     allocated mmapped regions, try to directly map this request
     rather than expanding top.
   */

  if (av == NULL
      || ((unsigned long) (nb) >= (unsigned long) (mp_.mmap_threshold)
	  && (mp_.n_mmaps < mp_.n_mmaps_max)))
    {
      char *mm;
      if (mp_.hp_pagesize > 0 && nb >= mp_.hp_pagesize)
	{
	  /* There is no need to issue the THP madvise call if Huge Pages are
	     used directly.  */
	  mm = sysmalloc_mmap (nb, mp_.hp_pagesize, mp_.hp_flags, av);
	  if (mm != MAP_FAILED)
	    return mm;
	}
      mm = sysmalloc_mmap (nb, pagesize, 0, av);
      if (mm != MAP_FAILED)
	return mm;
      tried_mmap = true;
    }

  /* There are no usable arenas and mmap also failed.  */
  if (av == NULL)
    return 0;
```

</details>

### sysmalloc checks

It starts by getting old top chunk information and checking that some of the following condations are true:

- The old heap size is 0 (new heap)
- The size of the previous heap is greater and MINSIZE and the old Top is in use
- The heap is aligned to page size (0x1000 so the lower 12 bits need to be 0)

Then it also checks that:

- The old size hasn't enough space to create a chunk for the requested size

<details>

<summary>sysmalloc checks</summary>

```c
/* Record incoming configuration of top */

  old_top = av->top;
  old_size = chunksize (old_top);
  old_end = (char *) (chunk_at_offset (old_top, old_size));

  brk = snd_brk = (char *) (MORECORE_FAILURE);

  /*
     If not the first time through, we require old_size to be
     at least MINSIZE and to have prev_inuse set.
   */

  assert ((old_top == initial_top (av) && old_size == 0) ||
          ((unsigned long) (old_size) >= MINSIZE &&
           prev_inuse (old_top) &&
           ((unsigned long) old_end & (pagesize - 1)) == 0));

  /* Precondition: not enough current space to satisfy nb request */
  assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));
```

</details>

### sysmalloc not main arena

It'll first try to **extend** the previous heap for this heap. If not possible try to **allocate a new heap** and update the pointers to be able to use it.\
Finally if that didn't work, try calling **`sysmalloc_mmap`**.

<details>

<summary>sysmalloc not main arena</summary>

```c
if (av != &main_arena)
    {
      heap_info *old_heap, *heap;
      size_t old_heap_size;

      /* First try to extend the current heap. */
      old_heap = heap_for_ptr (old_top);
      old_heap_size = old_heap->size;
      if ((long) (MINSIZE + nb - old_size) > 0
          && grow_heap (old_heap, MINSIZE + nb - old_size) == 0)
        {
          av->system_mem += old_heap->size - old_heap_size;
          set_head (old_top, (((char *) old_heap + old_heap->size) - (char *) old_top)
                    | PREV_INUSE);
        }
      else if ((heap = new_heap (nb + (MINSIZE + sizeof (*heap)), mp_.top_pad)))
        {
          /* Use a newly allocated heap.  */
          heap->ar_ptr = av;
          heap->prev = old_heap;
          av->system_mem += heap->size;
          /* Set up the new top.  */
          top (av) = chunk_at_offset (heap, sizeof (*heap));
          set_head (top (av), (heap->size - sizeof (*heap)) | PREV_INUSE);

          /* Setup fencepost and free the old top chunk with a multiple of
             MALLOC_ALIGNMENT in size. */
          /* The fencepost takes at least MINSIZE bytes, because it might
             become the top chunk again later.  Note that a footer is set
             up, too, although the chunk is marked in use. */
          old_size = (old_size - MINSIZE) & ~MALLOC_ALIGN_MASK;
          set_head (chunk_at_offset (old_top, old_size + CHUNK_HDR_SZ),
		    0 | PREV_INUSE);
          if (old_size >= MINSIZE)
            {
              set_head (chunk_at_offset (old_top, old_size),
			CHUNK_HDR_SZ | PREV_INUSE);
              set_foot (chunk_at_offset (old_top, old_size), CHUNK_HDR_SZ);
              set_head (old_top, old_size | PREV_INUSE | NON_MAIN_ARENA);
              _int_free (av, old_top, 1);
            }
          else
            {
              set_head (old_top, (old_size + CHUNK_HDR_SZ) | PREV_INUSE);
              set_foot (old_top, (old_size + CHUNK_HDR_SZ));
            }
        }
      else if (!tried_mmap)
	{
	  /* We can at least try to use to mmap memory.  If new_heap fails
	     it is unlikely that trying to allocate huge pages will
	     succeed.  */
	  char *mm = sysmalloc_mmap (nb, pagesize, 0, av);
	  if (mm != MAP_FAILED)
	    return mm;
	}
    }
```

</details>

### sysmalloc main arena

It starts calculating the amount of memory needed. It'll start by requesting contiguous memory so in this case it'll be possible to use the old memory not used. Also some align operations are performed.

<details>

<summary>sysmalloc main arena</summary>

```c
// From https://github.com/bminor/glibc/blob/f942a732d37a96217ef828116ebe64a644db18d7/malloc/malloc.c#L2665C1-L2713C10

  else     /* av == main_arena */

    { /* Request enough space for nb + pad + overhead */
      size = nb + mp_.top_pad + MINSIZE;

      /*
         If contiguous, we can subtract out existing space that we hope to
         combine with new space. We add it back later only if
         we don't actually get contiguous space.
       */

      if (contiguous (av))
        size -= old_size;

      /*
         Round to a multiple of page size or huge page size.
         If MORECORE is not contiguous, this ensures that we only call it
         with whole-page arguments.  And if MORECORE is contiguous and
         this is not first time through, this preserves page-alignment of
         previous calls. Otherwise, we correct to page-align below.
       */

#ifdef MADV_HUGEPAGE
      /* Defined in brk.c.  */
      extern void *__curbrk;
      if (__glibc_unlikely (mp_.thp_pagesize != 0))
	{
	  uintptr_t top = ALIGN_UP ((uintptr_t) __curbrk + size,
				    mp_.thp_pagesize);
	  size = top - (uintptr_t) __curbrk;
	}
      else
#endif
	size = ALIGN_UP (size, GLRO(dl_pagesize));

      /*
         Don't try to call MORECORE if argument is so big as to appear
         negative. Note that since mmap takes size_t arg, it may succeed
         below even if we cannot call MORECORE.
       */

      if (size > 0)
        {
          brk = (char *) (MORECORE (size));
	  if (brk != (char *) (MORECORE_FAILURE))
	    madvise_thp (brk, size);
          LIBC_PROBE (memory_sbrk_more, 2, brk, size);
        }
```

</details>

### sysmalloc main arena previous error 1

If the previous returned `MORECORE_FAILURE`, try agin to allocate memory using `sysmalloc_mmap_fallback`

<details>

<summary><code>sysmalloc</code> main arena previous error 1</summary>

```c
// From https://github.com/bminor/glibc/blob/f942a732d37a96217ef828116ebe64a644db18d7/malloc/malloc.c#L2715C7-L2740C10

if (brk == (char *) (MORECORE_FAILURE))
        {
          /*
             If have mmap, try using it as a backup when MORECORE fails or
             cannot be used. This is worth doing on systems that have "holes" in
             address space, so sbrk cannot extend to give contiguous space, but
             space is available elsewhere.  Note that we ignore mmap max count
             and threshold limits, since the space will not be used as a
             segregated mmap region.
           */

	  char *mbrk = MAP_FAILED;
	  if (mp_.hp_pagesize > 0)
	    mbrk = sysmalloc_mmap_fallback (&size, nb, old_size,
					    mp_.hp_pagesize, mp_.hp_pagesize,
					    mp_.hp_flags, av);
	  if (mbrk == MAP_FAILED)
	    mbrk = sysmalloc_mmap_fallback (&size, nb, old_size, MMAP_AS_MORECORE_SIZE,
					    pagesize, 0, av);
	  if (mbrk != MAP_FAILED)
	    {
	      /* We do not need, and cannot use, another sbrk call to find end */
	      brk = mbrk;
	      snd_brk = brk + size;
	    }
        }
```

</details>

### sysmalloc main arena continue

If the previous didn't return `MORECORE_FAILURE`, if it worked create some alignments:

<details>

<summary>sysmalloc main arena previous error 2</summary>

```c
// From https://github.com/bminor/glibc/blob/f942a732d37a96217ef828116ebe64a644db18d7/malloc/malloc.c#L2742

if (brk != (char *) (MORECORE_FAILURE))
        {
          if (mp_.sbrk_base == 0)
            mp_.sbrk_base = brk;
          av->system_mem += size;

          /*
             If MORECORE extends previous space, we can likewise extend top size.
           */

          if (brk == old_end && snd_brk == (char *) (MORECORE_FAILURE))
            set_head (old_top, (size + old_size) | PREV_INUSE);

          else if (contiguous (av) && old_size && brk < old_end)
	    /* Oops!  Someone else killed our space..  Can't touch anything.  */
	    malloc_printerr ("break adjusted to free malloc space");

          /*
             Otherwise, make adjustments:

           * If the first time through or noncontiguous, we need to call sbrk
              just to find out where the end of memory lies.

           * We need to ensure that all returned chunks from malloc will meet
              MALLOC_ALIGNMENT

           * If there was an intervening foreign sbrk, we need to adjust sbrk
              request size to account for fact that we will not be able to
              combine new space with existing space in old_top.

           * Almost all systems internally allocate whole pages at a time, in
              which case we might as well use the whole last page of request.
              So we allocate enough more memory to hit a page boundary now,
              which in turn causes future contiguous calls to page-align.
           */

          else
            {
              front_misalign = 0;
              end_misalign = 0;
              correction = 0;
              aligned_brk = brk;

              /* handle contiguous cases */
              if (contiguous (av))
                {
                  /* Count foreign sbrk as system_mem.  */
                  if (old_size)
                    av->system_mem += brk - old_end;

                  /* Guarantee alignment of first new chunk made from this space */

                  front_misalign = (INTERNAL_SIZE_T) chunk2mem (brk) & MALLOC_ALIGN_MASK;
                  if (front_misalign > 0)
                    {
                      /*
                         Skip over some bytes to arrive at an aligned position.
                         We don't need to specially mark these wasted front bytes.
                         They will never be accessed anyway because
                         prev_inuse of av->top (and any chunk created from its start)
                         is always true after initialization.
                       */

                      correction = MALLOC_ALIGNMENT - front_misalign;
                      aligned_brk += correction;
                    }

                  /*
                     If this isn't adjacent to existing space, then we will not
                     be able to merge with old_top space, so must add to 2nd request.
                   */

                  correction += old_size;

                  /* Extend the end address to hit a page boundary */
                  end_misalign = (INTERNAL_SIZE_T) (brk + size + correction);
                  correction += (ALIGN_UP (end_misalign, pagesize)) - end_misalign;

                  assert (correction >= 0);
                  snd_brk = (char *) (MORECORE (correction));

                  /*
                     If can't allocate correction, try to at least find out current
                     brk.  It might be enough to proceed without failing.

                     Note that if second sbrk did NOT fail, we assume that space
                     is contiguous with first sbrk. This is a safe assumption unless
                     program is multithreaded but doesn't use locks and a foreign sbrk
                     occurred between our first and second calls.
                   */

                  if (snd_brk == (char *) (MORECORE_FAILURE))
                    {
                      correction = 0;
                      snd_brk = (char *) (MORECORE (0));
                    }
		  else
		    madvise_thp (snd_brk, correction);
                }

              /* handle non-contiguous cases */
              else
                {
                  if (MALLOC_ALIGNMENT == CHUNK_HDR_SZ)
                    /* MORECORE/mmap must correctly align */
                    assert (((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0);
                  else
                    {
                      front_misalign = (INTERNAL_SIZE_T) chunk2mem (brk) & MALLOC_ALIGN_MASK;
                      if (front_misalign > 0)
                        {
                          /*
                             Skip over some bytes to arrive at an aligned position.
                             We don't need to specially mark these wasted front bytes.
                             They will never be accessed anyway because
                             prev_inuse of av->top (and any chunk created from its start)
                             is always true after initialization.
                           */

                          aligned_brk += MALLOC_ALIGNMENT - front_misalign;
                        }
                    }

                  /* Find out current end of memory */
                  if (snd_brk == (char *) (MORECORE_FAILURE))
                    {
                      snd_brk = (char *) (MORECORE (0));
                    }
                }

              /* Adjust top based on results of second sbrk */
              if (snd_brk != (char *) (MORECORE_FAILURE))
                {
                  av->top = (mchunkptr) aligned_brk;
                  set_head (av->top, (snd_brk - aligned_brk + correction) | PREV_INUSE);
                  av->system_mem += correction;

                  /*
                     If not the first time through, we either have a
                     gap due to foreign sbrk or a non-contiguous region.  Insert a
                     double fencepost at old_top to prevent consolidation with space
                     we don't own. These fenceposts are artificial chunks that are
                     marked as inuse and are in any case too small to use.  We need
                     two to make sizes and alignments work out.
                   */

                  if (old_size != 0)
                    {
                      /*
                         Shrink old_top to insert fenceposts, keeping size a
                         multiple of MALLOC_ALIGNMENT. We know there is at least
                         enough space in old_top to do this.
                       */
                      old_size = (old_size - 2 * CHUNK_HDR_SZ) & ~MALLOC_ALIGN_MASK;
                      set_head (old_top, old_size | PREV_INUSE);

                      /*
                         Note that the following assignments completely overwrite
                         old_top when old_size was previously MINSIZE.  This is
                         intentional. We need the fencepost, even if old_top otherwise gets
                         lost.
                       */
		      set_head (chunk_at_offset (old_top, old_size),
				CHUNK_HDR_SZ | PREV_INUSE);
		      set_head (chunk_at_offset (old_top,
						 old_size + CHUNK_HDR_SZ),
				CHUNK_HDR_SZ | PREV_INUSE);

                      /* If possible, release the rest. */
                      if (old_size >= MINSIZE)
                        {
                          _int_free (av, old_top, 1);
                        }
                    }
                }
            }
        }
    } /* if (av !=  &main_arena) */
```

</details>

### sysmalloc finale

Finish the allocation updating the arena information

```c
// From https://github.com/bminor/glibc/blob/f942a732d37a96217ef828116ebe64a644db18d7/malloc/malloc.c#L2921C3-L2943C12

if ((unsigned long) av->system_mem > (unsigned long) (av->max_system_mem))
    av->max_system_mem = av->system_mem;
  check_malloc_state (av);

  /* finally, do the allocation */
  p = av->top;
  size = chunksize (p);

  /* check that one of the above allocation paths succeeded */
  if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
    {
      remainder_size = size - nb;
      remainder = chunk_at_offset (p, nb);
      av->top = remainder;
      set_head (p, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE);
      check_malloced_chunk (av, p, nb);
      return chunk2mem (p);
    }

  /* catch all failure paths */
  __set_errno (ENOMEM);
  return 0;
```
