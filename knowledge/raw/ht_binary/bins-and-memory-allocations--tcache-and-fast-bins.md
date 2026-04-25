# Bins & Memory Allocations - Tcache and Fast Bins

## Basic Information

In order to improve the efficiency on how chunks are stored every chunk is not just in one linked list, but there are several types. These are the bins and there are 5 type of bins: [62](https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=blob;f=malloc/malloc.c;h=6e766d11bc85b6480fa5c9f2a76559f8acf9deb5;hb=HEAD#l1407) small bins, 63 large bins, 1 unsorted bin, 10 fast bins and 64 tcache bins per thread.

The initial address to each unsorted, small and large bins is inside the same array. The index 0 is unused, 1 is the unsorted bin, bins 2-64 are small bins and bins 65-127 are large bins.

### Tcache (Per-Thread Cache) Bins

Even though threads try to have their own heap (see [Arenas](bins-and-memory-allocations.md#arenas) and [Subheaps](bins-and-memory-allocations.md#subheaps)), there is the possibility that a process with a lot of threads (like a web server) **will end sharing the heap with another threads**. In this case, the main solution is the use of **lockers**, which might **slow down significantly the threads**.

Therefore, a tcache is similar to a fast bin per thread in the way that it's a **single linked list** that doesn't merge chunks. Each thread has **64 singly-linked tcache bins**. Each bin can have a maximum of [7 same-size chunks](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=2527e2504761744df2bdb1abdc02d936ff907ad2;hb=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc#l323) ranging from [24 to 1032B on 64-bit systems and 12 to 516B on 32-bit systems](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=2527e2504761744df2bdb1abdc02d936ff907ad2;hb=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc#l315).

**When a thread frees** a chunk, **if it isn't too big** to be allocated in the tcache and the respective tcache bin **isn't full** (already 7 chunks), **it'll be allocated in there**. If it cannot go to the tcache, it'll need to wait for the heap lock to be able to perform the free operation globally.

When a **chunk is allocated**, if there is a free chunk of the needed size in the **Tcache it'll use it**, if not, it'll need to wait for the heap lock to be able to find one in the global bins or create a new one.\
There's also an optimization, in this case, while having the heap lock, the thread **will fill his Tcache with heap chunks (7) of the requested size**, so in case it needs more, it'll find them in Tcache.

<details>

<summary>Add a tcache chunk example</summary>

```c
#include <stdlib.h>
#include <stdio.h>

int main(void)
{
  char *chunk;
  chunk = malloc(24);
  printf("Address of the chunk: %p\n", (void *)chunk);
  gets(chunk);
  free(chunk);
  return 0;
}
```

Compile it and debug it with a breakpoint in the ret opcode from main function. then with gef you can see the tcache bin in use:

```bash
gef➤  heap bins
──────────────────────────────────────────────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────────────────────────────────────────────
Tcachebins[idx=0, size=0x20, count=1] ←  Chunk(addr=0xaaaaaaac12a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
```

</details>

#### Tcache Structs & Functions

In the following code it's possible to see the **max bins** and **chunks per index**, the **`tcache_entry`** struct created to avoid double frees and **`tcache_perthread_struct`**, a struct that each thread uses to store the addresses to each index of the bin.

<details>

<summary><code>tcache_entry</code> and <code>tcache_perthread_struct</code></summary>

```c
// From https://github.com/bminor/glibc/blob/f942a732d37a96217ef828116ebe64a644db18d7/malloc/malloc.c

/* We want 64 entries.  This is an arbitrary limit, which tunables can reduce.  */
# define TCACHE_MAX_BINS		64
# define MAX_TCACHE_SIZE	tidx2usize (TCACHE_MAX_BINS-1)

/* Only used to pre-fill the tunables.  */
# define tidx2usize(idx)	(((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)

/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))

/* With rounding and alignment, the bins are...
   idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   idx 1   bytes 25..40 or 13..20
   idx 2   bytes 41..56 or 21..28
   etc.  */

/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7

/* Maximum chunks in tcache bins for tunables.  This value must fit the range
   of tcache->counts[] entries, else they may overflow.  */
# define MAX_TCACHE_COUNT UINT16_MAX

[...]

typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  uintptr_t key;
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  uint16_t counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

</details>

The function `__tcache_init` is the function that creates and allocates the space for the `tcache_perthread_struct` obj

<details>

<summary>tcache_init code</summary>

```c
// From https://github.com/bminor/glibc/blob/f942a732d37a96217ef828116ebe64a644db18d7/malloc/malloc.c#L3241C1-L3274C2

static void
tcache_init(void)
{
  mstate ar_ptr;
  void *victim = 0;
  const size_t bytes = sizeof (tcache_perthread_struct);

  if (tcache_shutting_down)
    return;

  arena_get (ar_ptr, bytes);
  victim = _int_malloc (ar_ptr, bytes);
  if (!victim && ar_ptr != NULL)
    {
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  /* In a low memory situation, we may not be able to allocate memory
     - in which case, we just keep trying later.  However, we
     typically do this very early, so either there is sufficient
     memory, or there isn't enough memory to do non-trivial
     allocations anyway.  */
  if (victim)
    {
      tcache = (tcache_perthread_struct *) victim;
      memset (tcache, 0, sizeof (tcache_perthread_struct));
    }

}
```

</details>

#### Tcache Indexes

The tcache have several bins depending on the size an the initial pointers to the **first chunk of each index and the amount of chunks per index are located inside a chunk**. This means that locating the chunk with this information (usually the first), it's possible to find all the tcache initial points and the amount of Tcache chunks.

### Fast bins

Fast bins are designed to **speed up memory allocation for small chunks** by keeping recently freed chunks in a quick-access structure. These bins use a Last-In, First-Out (LIFO) approach, which means that the **most recently freed chunk is the first** to be reused when there's a new allocation request. This behaviour is advantageous for speed, as it's faster to insert and remove from the top of a stack (LIFO) compared to a queue (FIFO).

Additionally, **fast bins use singly linked lists**, not double linked, which further improves speed. Since chunks in fast bins aren't merged with neighbours, there's no need for a complex structure that allows removal from the middle. A singly linked list is simpler and quicker for these operations.

Basically, what happens here is that the header (the pointer to the first chunk to check) is always pointing to the latest freed chunk of that size. So:

- When a new chunk is allocated of that size, the header is pointing to a free chunk to use. As this free chunk is pointing to the next one to use, this address is stored in the header so the next allocation knows where to get an available chunk
- When a chunk is freed, the free chunk will save the address to the current available chunk and the address to this newly freed chunk will be put in the header

The maximum size of a linked list is `0x80` and they are organized so a chunk of size `0x20` will be in index `0`, a chunk of size `0x30` would be in index `1`...

> [!CAUTION]
> Chunks in fast bins aren't set as available so they are keep as fast bin chunks for some time instead of being able to merge with other free chunks surrounding them.

```c
// From https://github.com/bminor/glibc/blob/a07e000e82cb71238259e674529c37c12dc7d423/malloc/malloc.c#L1711

/*
   Fastbins

    An array of lists holding recently freed small chunks.  Fastbins
    are not doubly linked.  It is faster to single-link them, and
    since chunks are never removed from the middles of these lists,
    double linking is not necessary. Also, unlike regular bins, they
    are not even processed in FIFO order (they use faster LIFO) since
    ordering doesn't much matter in the transient contexts in which
    fastbins are normally used.

    Chunks in fastbins keep their inuse bit set, so they cannot
    be consolidated with other free chunks. malloc_consolidate
    releases all chunks in fastbins and consolidates them with
    other free chunks.
 */

typedef struct malloc_chunk *mfastbinptr;
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])

/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)

/* The maximum fastbin request size we support */
#define MAX_FAST_SIZE     (80 * SIZE_SZ / 4)

#define NFASTBINS  (fastbin_index (request2size (MAX_FAST_SIZE)) + 1)
```

<details>

<summary>Add a fastbin chunk example</summary>

```c
#include <stdlib.h>
#include <stdio.h>

int main(void)
{
  char *chunks[8];
  int i;

  // Loop to allocate memory 8 times
  for (i = 0; i < 8; i++) {
    chunks[i] = malloc(24);
    if (chunks[i] == NULL) { // Check if malloc failed
      fprintf(stderr, "Memory allocation failed at iteration %d\n", i);
      return 1;
    }
    printf("Address of chunk %d: %p\n", i, (void *)chunks[i]);
  }

  // Loop to free the allocated memory
  for (i = 0; i < 8; i++) {
    free(chunks[i]);
  }

  return 0;
}
```

Note how we allocate and free 8 chunks of the same size so they fill the tcache and the eight one is stored in the fast chunk.

Compile it and debug it with a breakpoint in the `ret` opcode from `main` function. then with `gef` you can see that the tcache bin is full and one chunk is in the fast bin:

```bash
gef➤  heap bins
──────────────────────────────────────────────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────────────────────────────────────────────
Tcachebins[idx=0, size=0x20, count=7] ←  Chunk(addr=0xaaaaaaac1770, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac1750, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac1730, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac1710, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac16f0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac16d0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac12a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
───────────────────────────────────────────────────────────────────────── Fastbins for arena at 0xfffff7f90b00 ─────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0xaaaaaaac1790, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Fastbins[idx=1, size=0x30] 0x00
```

</details>
