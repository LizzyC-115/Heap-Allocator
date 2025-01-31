/*
  Lizzy Chanpaibool; CS107; Assignment 6; 
  Utilizing pointers to allocate, free, and reallocate memory on the heap
*/
#include "./allocator.h"
#include "./debug_break.h"
#include <stdio.h>
#include <string.h>

const int MIN_HEAP_SIZE = 16;
const int HEADER_SIZE = 8;  
const size_t USED = 0x1;
static void *segment_start;
static size_t segment_size;
static size_t nused;

/*
  Sets status inside a size_t variable holding payload size. If the status is
  true, least signficant 3 bits are '001' and block is signified as used. 
  Otherwise, the least significant 3 bits are '000' and the block is free.
  Returns a size_t value with status embedded within.
*/
size_t set_status(size_t block_size, bool status) {
    if (status) {
        return block_size | USED;
    }
    return block_size & ~USED;
}

/*
  Given a requested size for an allocation, round up to the nearest multiple
  of ALIGNMENT. Minimum is ALIGNMENT itself.
*/
size_t align(size_t requested_size, size_t multiple) {
    return ((requested_size + multiple - 1) / multiple) * multiple;
}

/*
  Using pointer arithmetic, loop through heap until a free block that
  matches the requested size from the client. If no such block it found,
  return NULL. Otherwise, return pointer to the header of free block.
  Follows a first-fit approach.
*/
void *search_implicit(void *ptr, size_t requested_size) {
    size_t status = *(size_t *)ptr & USED;
    size_t block_size = *(size_t *)ptr & ~USED;
    void *end = (char *)ptr + segment_size;
    while (ptr != end) {
        status = *(size_t *)ptr & USED;
        block_size = *(size_t *)ptr & ~USED;
        if (status == 0 && block_size >= requested_size) {  // find large enough free block
            return ptr;
        }
        ptr = (char *)ptr + block_size + HEADER_SIZE;
    }
    return NULL;
}

/*
  Takes in a pointer to a pointer on the heap and a block size.
  Creates a size_t value that represents the block size and a free status.
  Inserts the created size_t value into the heap. Only creates a new header
  if the passed in block size is non-zero and non-negative.
*/
void create_header(void *remain, size_t new_block_size) {
    if (new_block_size > 0) {
        *(size_t *)remain = set_status(new_block_size - HEADER_SIZE, false);
    }
}

/*
  Loops through each header in the heap and checks if the headers have a 
  well formed status and a valid block size. Returns false if any errors
  are found. Otherwise, returns true.
*/
bool check_headers() {
    void *ptr = segment_start;
    void *end = (char *)ptr + segment_size;
    while (ptr != end) {
        size_t status = *(size_t *)ptr & USED;
        if (status != 0 && status != 1) {
            printf("Address %p has incorect status.", ptr);
            return false;
        }
        size_t block_size = *(size_t *)ptr & ~USED;
        if ((block_size < ALIGNMENT && block_size != 0) || block_size > segment_size) {
            printf("Address %p has invalid block size", ptr);
            return false;
        }
        ptr = (char *)ptr + block_size + HEADER_SIZE;  // Move to next block
    }
    return true;
}

/*
  Only called when the heap is first initialized. Must ensure
  that the heap_start is not a NULL address and aligned to the ALIGNMENT
  constant. Heap size must be a multiple of ALIGNMENT constant. Returns
  false if the heap size is too small. Otherwise, returns true.
*/
bool myinit(void *heap_start, size_t heap_size) {
    if (heap_size < MIN_HEAP_SIZE) { 
        return false;
    }
    segment_start = heap_start;
    segment_size = heap_size;
    nused = 0;

    size_t payload_size = set_status(heap_size - HEADER_SIZE, false);
    *(size_t *) heap_start = payload_size;
    return true;
}

/*
  Takes in a requested size for an allocation. If the 
  request is valid, returns a pointer to the allocated memory.
  Request is not valid if the request is larger than the
  MAX_REQUEST_SIZE or if there is not a large enough block
  to fit the requested size. In invalid cases, returns NULL.
*/
void *mymalloc(size_t requested_size) {
    size_t needed = align(requested_size, ALIGNMENT);
    if (needed + nused > segment_size || requested_size == 0 || requested_size > MAX_REQUEST_SIZE) {
        return NULL;
    }
    void *ptr = search_implicit(segment_start, needed);
    if (ptr != NULL) {
        size_t old_size = *(size_t *)ptr;
        *(size_t *) ptr = set_status(needed, true);
        nused += (needed + HEADER_SIZE);
        void *remain = (char *)ptr + needed + HEADER_SIZE;
        create_header(remain, old_size - needed);
        return (char *)ptr + HEADER_SIZE;
    }
    return NULL;
}

/*
  Takes in a pointer to a segment on the heap. Finds
  the header associated with the segment and udpates
  the header status to represent a free block.
*/
void myfree(void *ptr) {
    if (ptr == NULL) {
        return;
    }
    void *header_start = (char *)ptr - HEADER_SIZE;
    size_t updated_free = *(size_t *)header_start - 1;
    *(size_t *)header_start = updated_free;
    nused -= (updated_free + HEADER_SIZE);
}

/*
  Takes in a pointer to the heap and a new requested size for memory.
  If the requested size fits into the already allocated block, the
  old pointer is returned. Otherwise if the the requested size is larger
  than the previously allocated space, old allocation is freed and
  new request is allocated elsewhere on the heap. Returns pointer
  to new allocation is request is successful, otherwise returns NULL.
*/
void *myrealloc(void *old_ptr, size_t new_size) {
    if (old_ptr == NULL) {
        return mymalloc(new_size);
    }
    if (new_size == 0) {
        myfree(old_ptr);
        return NULL;
    }
    void *old_header = (char *)old_ptr - HEADER_SIZE;
    size_t block_size = *(size_t *)old_header & ~USED;  // Turn off last bits to get just size
    if (block_size >= new_size) {
        return old_ptr;
    }
    void *new_block = mymalloc(new_size);
    memcpy(new_block, old_ptr, block_size);
    myfree(old_ptr);
    return new_block;
}

/* 
   Checks if myinit sets up the heap correctly. Checks
   if heap headers are well formed. Returns false is any errors are
   found, returns true otherwise.
 */
bool validate_heap() {
    if (segment_start == NULL) {  // Non-NULL start address
        return false;
    }
    if (segment_size < MIN_HEAP_SIZE) {  // Large enough heap space
        return false;
    }
    if (*(size_t *)segment_start <= 0) {  // Incorrect starting header
        return false;
    }
    return check_headers();
}

/* 
   Prints out information representing the heap.
   Starting address, heap size, and first free block is 
   printed once. Each block in the heap is then printed out
   with its header address, the information inside the header,
   the block size, and the status. If the status is free,
   then the pointers are printed out as well.
 */
void dump_heap() {
    void *ptr = segment_start;
    void *end = (char *)ptr + segment_size;
    printf("Starting Address: %p\n", segment_start);
    printf("Heap Size: %ld\n\n", segment_size);
    while (ptr != end) {
        size_t status = *(size_t *)ptr & USED;
        size_t block_size = *(size_t *)ptr & ~USED;

        printf("Address: %p\n", ptr);
        printf("Header: %ld\n", *(size_t *)ptr);
        printf("Block Size: %ld\n", block_size);
        printf("Status: %ld\n\n", status);
        
        ptr = (char *)ptr + block_size + HEADER_SIZE;  // Move to next block
    }
}
