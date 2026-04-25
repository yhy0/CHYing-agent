# malloc & sysmalloc - Sysmalloc Mmap

## sysmalloc_mmap


<details>

<summary>sysmalloc_mmap code</summary>

```c
// From https://github.com/bminor/glibc/blob/f942a732d37a96217ef828116ebe64a644db18d7/malloc/malloc.c#L2392C1-L2481C2

static void *
sysmalloc_mmap (INTERNAL_SIZE_T nb, size_t pagesize, int extra_flags, mstate av)
{
  long int size;

  /*
    Round up size to nearest page.  For mmapped chunks, the overhead is one
    SIZE_SZ unit larger than for normal chunks, because there is no
    following chunk whose prev_size field could be used.

    See the front_misalign handling below, for glibc there is no need for
    further alignments unless we have have high alignment.
   */
  if (MALLOC_ALIGNMENT == CHUNK_HDR_SZ)
    size = ALIGN_UP (nb + SIZE_SZ, pagesize);
  else
    size = ALIGN_UP (nb + SIZE_SZ + MALLOC_ALIGN_MASK, pagesize);

  /* Don't try if size wraps around 0.  */
  if ((unsigned long) (size) <= (unsigned long) (nb))
    return MAP_FAILED;

  char *mm = (char *) MMAP (0, size,
			    mtag_mmap_flags | PROT_READ | PROT_WRITE,
			    extra_flags);
  if (mm == MAP_FAILED)
    return mm;

#ifdef MAP_HUGETLB
  if (!(extra_flags & MAP_HUGETLB))
    madvise_thp (mm, size);
#endif

  __set_vma_name (mm, size, " glibc: malloc");

  /*
    The offset to the start of the mmapped region is stored in the prev_size
    field of the chunk.  This allows us to adjust returned start address to
    meet alignment requirements here and in memalign(), and still be able to
    compute proper address argument for later munmap in free() and realloc().
   */

  INTERNAL_SIZE_T front_misalign; /* unusable bytes at front of new space */

  if (MALLOC_ALIGNMENT == CHUNK_HDR_SZ)
    {
      /* For glibc, chunk2mem increases the address by CHUNK_HDR_SZ and
	 MALLOC_ALIGN_MASK is CHUNK_HDR_SZ-1.  Each mmap'ed area is page
	 aligned and therefore definitely MALLOC_ALIGN_MASK-aligned.  */
      assert (((INTERNAL_SIZE_T) chunk2mem (mm) & MALLOC_ALIGN_MASK) == 0);
      front_misalign = 0;
    }
  else
    front_misalign = (INTERNAL_SIZE_T) chunk2mem (mm) & MALLOC_ALIGN_MASK;

  mchunkptr p;                    /* the allocated/returned chunk */

  if (front_misalign > 0)
    {
      ptrdiff_t correction = MALLOC_ALIGNMENT - front_misalign;
      p = (mchunkptr) (mm + correction);
      set_prev_size (p, correction);
      set_head (p, (size - correction) | IS_MMAPPED);
    }
  else
    {
      p = (mchunkptr) mm;
      set_prev_size (p, 0);
      set_head (p, size | IS_MMAPPED);
    }

  /* update statistics */
  int new = atomic_fetch_add_relaxed (&mp_.n_mmaps, 1) + 1;
  atomic_max (&mp_.max_n_mmaps, new);

  unsigned long sum;
  sum = atomic_fetch_add_relaxed (&mp_.mmapped_mem, size) + size;
  atomic_max (&mp_.max_mmapped_mem, sum);

  check_chunk (av, p);

  return chunk2mem (p);
}
```

</details>
