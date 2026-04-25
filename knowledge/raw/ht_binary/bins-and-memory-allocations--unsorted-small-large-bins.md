# Bins & Memory Allocations - Unsorted, Small, and Large Bins

### Unsorted bin

The unsorted bin is a **cache** used by the heap manager to make memory allocation quicker. Here's how it works: When a program frees a chunk, and if this chunk cannot be allocated in a tcache or fast bin and is not colliding with the top chunk, the heap manager doesn't immediately put it in a specific small or large bin. Instead, it first tries to **merge it with any neighbouring free chunks** to create a larger block of free memory. Then, it places this new chunk in a general bin called the "unsorted bin."

When a program **asks for memory**, the heap manager **checks the unsorted bin** to see if there's a chunk of enough size. If it finds one, it uses it right away. If it doesn't find a suitable chunk in the unsorted bin, it moves all the chunks in this list to their corresponding bins, either small or large, based on their size.

Note that if a larger chunk is split in 2 halves and the rest is larger than MINSIZE, it'll be paced back into the unsorted bin.

So, the unsorted bin is a way to speed up memory allocation by quickly reusing recently freed memory and reducing the need for time-consuming searches and merges.

> [!CAUTION]
> Note that even if chunks are of different categories, if an available chunk is colliding with another available chunk (even if they belong originally to different bins), they will be merged.

<details>

<summary>Add a unsorted chunk example</summary>

```c
#include <stdlib.h>
#include <stdio.h>

int main(void)
{
  char *chunks[9];
  int i;

  // Loop to allocate memory 8 times
  for (i = 0; i < 9; i++) {
    chunks[i] = malloc(0x100);
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

Note how we allocate and free 9 chunks of the same size so they **fill the tcache** and the eight one is stored in the unsorted bin because it's **too big for the fastbin** and the nineth one isn't freed so the nineth and the eighth **don't get merged with the top chunk**.

Compile it and debug it with a breakpoint in the `ret` opcode from `main` function. Then with `gef` you can see that the tcache bin is full and one chunk is in the unsorted bin:

```bash
gef➤  heap bins
──────────────────────────────────────────────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────────────────────────────────────────────
Tcachebins[idx=15, size=0x110, count=7] ←  Chunk(addr=0xaaaaaaac1d10, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac1c00, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac1af0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac19e0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac18d0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac17c0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac12a0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
───────────────────────────────────────────────────────────────────────── Fastbins for arena at 0xfffff7f90b00 ─────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────────────────────────────────────────────── Unsorted Bin for arena at 0xfffff7f90b00 ───────────────────────────────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0xaaaaaaac1e10, bk=0xaaaaaaac1e10
 →   Chunk(addr=0xaaaaaaac1e20, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
```

</details>

### Small Bins

Small bins are faster than large bins but slower than fast bins.

Each bin of the 62 will have **chunks of the same size**: 16, 24, ... (with a max size of 504 bytes in 32bits and 1024 in 64bits). This helps in the speed on finding the bin where a space should be allocated and inserting and removing of entries on these lists.

This is how the size of the small bin is calculated according to the index of the bin:

- Smallest size: 2\*4\*index (e.g. index 5 -> 40)
- Biggest size: 2\*8\*index (e.g. index 5 -> 80)

```c
// From https://github.com/bminor/glibc/blob/a07e000e82cb71238259e674529c37c12dc7d423/malloc/malloc.c#L1711
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > CHUNK_HDR_SZ)
#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)

#define in_smallbin_range(sz)  \
  ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)

#define smallbin_index(sz) \
  ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))\
   + SMALLBIN_CORRECTION)
```

Function to choose between small and large bins:

```c
#define bin_index(sz) \
  ((in_smallbin_range (sz)) ? smallbin_index (sz) : largebin_index (sz))
```

<details>

<summary>Add a small chunk example</summary>

```c
#include <stdlib.h>
#include <stdio.h>

int main(void)
{
  char *chunks[10];
  int i;

  // Loop to allocate memory 8 times
  for (i = 0; i < 9; i++) {
    chunks[i] = malloc(0x100);
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

  chunks[9] = malloc(0x110);

  return 0;
}
```

Note how we allocate and free 9 chunks of the same size so they **fill the tcache** and the eight one is stored in the unsorted bin because it's **too big for the fastbin** and the ninth one isn't freed so the ninth and the eights **don't get merged with the top chunk**. Then we allocate a bigger chunk of 0x110 which makes **the chunk in the unsorted bin goes to the small bin**.

Compile it and debug it with a breakpoint in the `ret` opcode from `main` function. then with `gef` you can see that the tcache bin is full and one chunk is in the small bin:

```bash
gef➤  heap bins
──────────────────────────────────────────────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────────────────────────────────────────────
Tcachebins[idx=15, size=0x110, count=7] ←  Chunk(addr=0xaaaaaaac1d10, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac1c00, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac1af0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac19e0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac18d0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac17c0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0xaaaaaaac12a0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
───────────────────────────────────────────────────────────────────────── Fastbins for arena at 0xfffff7f90b00 ─────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────────────────────────────────────────────── Unsorted Bin for arena at 0xfffff7f90b00 ───────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────────────────────────────────────────────────────────── Small Bins for arena at 0xfffff7f90b00 ────────────────────────────────────────────────────────────────────────
[+] small_bins[16]: fw=0xaaaaaaac1e10, bk=0xaaaaaaac1e10
 →   Chunk(addr=0xaaaaaaac1e20, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in 1 small non-empty bins.
```

</details>

### Large bins

Unlike small bins, which manage chunks of fixed sizes, each **large bin handle a range of chunk sizes**. This is more flexible, allowing the system to accommodate **various sizes** without needing a separate bin for each size.

In a memory allocator, large bins start where small bins end. The ranges for large bins grow progressively larger, meaning the first bin might cover chunks from 512 to 576 bytes, while the next covers 576 to 640 bytes. This pattern continues, with the largest bin containing all chunks above 1MB.

Large bins are slower to operate compared to small bins because they must **sort and search through a list of varying chunk sizes to find the best fit** for an allocation. When a chunk is inserted into a large bin, it has to be sorted, and when memory is allocated, the system must find the right chunk. This extra work makes them **slower**, but since large allocations are less common than small ones, it's an acceptable trade-off.

There are:

- 32 bins of 64B range (collide with small bins)
- 16 bins of 512B range (collide with small bins)
- 8bins of 4096B range (part collide with small bins)
- 4bins of 32768B range
- 2bins of 262144B range
- 1bin for remaining sizes

<details>

<summary>Large bin sizes code</summary>

```c
// From https://github.com/bminor/glibc/blob/a07e000e82cb71238259e674529c37c12dc7d423/malloc/malloc.c#L1711

#define largebin_index_32(sz)                                                \
  (((((unsigned long) (sz)) >> 6) <= 38) ?  56 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

#define largebin_index_32_big(sz)                                            \
  (((((unsigned long) (sz)) >> 6) <= 45) ?  49 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

// XXX It remains to be seen whether it is good to keep the widths of
// XXX the buckets the same or whether it should be scaled by a factor
// XXX of two as well.
#define largebin_index_64(sz)                                                \
  (((((unsigned long) (sz)) >> 6) <= 48) ?  48 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

#define largebin_index(sz) \
  (SIZE_SZ == 8 ? largebin_index_64 (sz)                                     \
   : MALLOC_ALIGNMENT == 16 ? largebin_index_32_big (sz)                     \
   : largebin_index_32 (sz))
```

</details>

<details>

<summary>Add a large chunk example</summary>

```c
#include <stdlib.h>
#include <stdio.h>

int main(void)
{
  char *chunks[2];

  chunks[0] = malloc(0x1500);
  chunks[1] = malloc(0x1500);
  free(chunks[0]);
  chunks[0] = malloc(0x2000);

  return 0;
}
```

2 large allocations are performed, then on is freed (putting it in the unsorted bin) and a bigger allocation in made (moving the free one from the usorted bin ro the large bin).

Compile it and debug it with a breakpoint in the `ret` opcode from `main` function. then with `gef` you can see that the tcache bin is full and one chunk is in the large bin:

```bash
gef➤  heap bin
──────────────────────────────────────────────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────────────────────────────────────────────
All tcachebins are empty
───────────────────────────────────────────────────────────────────────── Fastbins for arena at 0xfffff7f90b00 ─────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────────────────────────────────────────────── Unsorted Bin for arena at 0xfffff7f90b00 ───────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────────────────────────────────────────────────────────── Small Bins for arena at 0xfffff7f90b00 ────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────────────────────────────────────────────── Large Bins for arena at 0xfffff7f90b00 ────────────────────────────────────────────────────────────────────────
[+] large_bins[100]: fw=0xaaaaaaac1290, bk=0xaaaaaaac1290
 →   Chunk(addr=0xaaaaaaac12a0, size=0x1510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in 1 large non-empty bins.
```

</details>

### Top Chunk

```c
// From https://github.com/bminor/glibc/blob/a07e000e82cb71238259e674529c37c12dc7d423/malloc/malloc.c#L1711

/*
   Top

    The top-most available chunk (i.e., the one bordering the end of
    available memory) is treated specially. It is never included in
    any bin, is used only if no other chunk is available, and is
    released back to the system if it is very large (see
    M_TRIM_THRESHOLD).  Because top initially
    points to its own bin with initial zero size, thus forcing
    extension on the first malloc request, we avoid having any special
    code in malloc to check whether it even exists yet. But we still
    need to do so when getting memory from system, so we make
    initial_top treat the bin as a legal but unusable chunk during the
    interval between initialization and the first call to
    sysmalloc. (This is somewhat delicate, since it relies on
    the 2 preceding words to be zero during this interval as well.)
 */

/* Conveniently, the unsorted bin can be used as dummy top on first call */
#define initial_top(M)              (unsorted_chunks (M))
```

Basically, this is a chunk containing all the currently available heap. When a malloc is performed, if there isn't any available free chunk to use, this top chunk will be reducing its size giving the necessary space.\
The pointer to the Top Chunk is stored in the `malloc_state` struct.

Moreover, at the beginning, it's possible to use the unsorted chunk as the top chunk.

<details>

<summary>Observe the Top Chunk example</summary>

```c
#include <stdlib.h>
#include <stdio.h>

int main(void)
{
  char *chunk;
  chunk = malloc(24);
  printf("Address of the chunk: %p\n", (void *)chunk);
  gets(chunk);
  return 0;
}
```

After compiling and debugging it with a break point in the `ret` opcode of `main` I saw that the malloc returned the address `0xaaaaaaac12a0` and these are the chunks:

```bash
gef➤  heap chunks
Chunk(addr=0xaaaaaaac1010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000aaaaaaac1010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0xaaaaaaac12a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000aaaaaaac12a0     41 41 41 41 41 41 41 00 00 00 00 00 00 00 00 00    AAAAAAA.........]
Chunk(addr=0xaaaaaaac12c0, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000aaaaaaac12c0     41 64 64 72 65 73 73 20 6f 66 20 74 68 65 20 63    Address of the c]
Chunk(addr=0xaaaaaaac16d0, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000aaaaaaac16d0     41 41 41 41 41 41 41 0a 00 00 00 00 00 00 00 00    AAAAAAA.........]
Chunk(addr=0xaaaaaaac1ae0, size=0x20530, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```

Where it can be seen that the top chunk is at address `0xaaaaaaac1ae0`. This is no surprise because the last allocated chunk was in `0xaaaaaaac12a0` with a size of `0x410` and `0xaaaaaaac12a0 + 0x410 = 0xaaaaaaac1ae0` .\
It's also possible to see the length of the Top chunk on its chunk header:

```bash
gef➤  x/8wx 0xaaaaaaac1ae0 - 16
0xaaaaaaac1ad0:	0x00000000	0x00000000	0x00020531	0x00000000
0xaaaaaaac1ae0:	0x00000000	0x00000000	0x00000000	0x00000000
```

</details>

### Last Remainder

When malloc is used and a chunk is divided (from the unsorted bin or from the top chunk for example), the chunk created from the rest of the divided chunk is called Last Remainder and it's pointer is stored in the `malloc_state` struct.

## Allocation Flow

Check out:

## Free Flow

Check out:

## Heap Functions Security Checks

Check the security checks performed by heavily used functions in heap in:

## References

- [https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/](https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/)
- [https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)
- [https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/core_functions](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/core_functions)
- [https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/implementation/tcache/](https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/implementation/tcache/)
