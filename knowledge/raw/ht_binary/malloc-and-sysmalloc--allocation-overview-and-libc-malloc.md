# malloc & sysmalloc


## Allocation Order Summary <a href="#libc_malloc" id="libc_malloc"></a>


(No checks are explained in this summary and some case have been omitted for brevity)

1. `__libc_malloc` tries to get a chunk from the tcache, if not it calls `_int_malloc`
2. `_int_malloc` :
   1. Tries to generate the arena if there isn't any
   2. If any fast bin chunk of the correct size, use it
      1. Fill tcache with other fast chunks
   3. If any small bin chunk of the correct size, use it
      1. Fill tcache with other chunks of that size
   4. If the requested size isn't for small bins, consolidate fast bin into unsorted bin
   5. Check the unsorted bin, use the first chunk with enough space
      1. If the found chunk is bigger, divide it to return a part and add the reminder back to the unsorted bin
      2. If a chunk is of the same size as the size requested, use to to fill the tcache instead of returning it (until the tcache is full, then return the next one)
      3. For each chunk of smaller size checked, put it in its respective small or large bin
   6. Check the large bin in the index of the requested size
      1. Start looking from the first chunk that is bigger than the requested size, if any is found return it and add the reminders to the small bin
   7. Check the large bins from the next indexes until the end
      1. From the next bigger index check for any chunk, divide the first found chunk to use it for the requested size and add the reminder to the unsorted bin
   8. If nothing is found in the previous bins, get a chunk from the top chunk
   9. If the top chunk wasn't big enough enlarge it with `sysmalloc`


## \_\_libc_malloc <a href="#libc_malloc" id="libc_malloc"></a>


The `malloc` function actually calls `__libc_malloc`. This function will check the tcache to see if there is any available chunk of the desired size. If the re is it'll use it and if not it'll check if it's a single thread and in that case it'll call `_int_malloc` in the main arena, and if not it'll call `_int_malloc` in arena of the thread.

<details>

<summary>__libc_malloc code</summary>

```c
// From https://github.com/bminor/glibc/blob/master/malloc/malloc.c

#if IS_IN (libc)
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  _Static_assert (PTRDIFF_MAX <= SIZE_MAX / 2,
                  "PTRDIFF_MAX is not more than half of SIZE_MAX");

  if (!__malloc_initialized)
    ptmalloc_init ();
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes = checked_request2size (bytes);
  if (tbytes == 0)
    {
      __set_errno (ENOMEM);
      return NULL;
    }
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      && tcache != NULL
      && tcache->counts[tc_idx] > 0)
    {
      victim = tcache_get (tc_idx);
      return tag_new_usable (victim);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif

  if (SINGLE_THREAD_P)
    {
      victim = tag_new_usable (_int_malloc (&main_arena, bytes));
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
	      &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  victim = tag_new_usable (victim);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
```

</details>

Note how it'll always tag the returned pointer with `tag_new_usable`, from the code:

```c
 void *tag_new_usable (void *ptr)

   Allocate a new random color and use it to color the user region of
   a chunk; this may include data from the subsequent chunk's header
   if tagging is sufficiently fine grained.  Returns PTR suitably
   recolored for accessing the memory there.
```
