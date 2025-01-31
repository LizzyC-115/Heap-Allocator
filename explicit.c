/*
  Lizzy Chanpaibool; CS107; Assignment 6; 
  Utilizing pointers to allocate, free, and reallocate memory on the heap explicitly
*/
#include "./allocator.h"
#include "./debug_break.h"
#include <stdio.h>
#include <string.h>

const int MIN_HEAP_SIZE = 24;  // 1 8-byte header + 1 16-byte payload
const int HEADER_SIZE = 8;
const int MIN_BLOCK_SIZE = 16;
const size_t USED = 0x1;

static void *segment_start;
static void *search_start;
static size_t segment_size;
static void *heap_end;
static size_t nused;

typedef struct Pointers {
    void *next;  // Next free block
    void *prev;  // Previous free block
} Pointers;

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
  of ALIGNMENT. Minimum is MIN_BLOCK_SIZE.
*/
size_t align(size_t requested_size, size_t multiple) {
    size_t block_size = ((requested_size + multiple - 1) / multiple) * multiple;
    if (block_size < MIN_BLOCK_SIZE) {
        return MIN_BLOCK_SIZE;
    }
    return block_size;
}

/*
  Takes in a pointer to a pointer on the heap and a block size.
  Creates a size_t value that represents the block size and a free status.
  Inserts the created size_t value into the heap. Only creates a new header
  if the passed in block size is non-zero and non-negative. If new header was
  created, returns true. Otherwise, return false.
*/
bool create_header(void *remain, size_t new_block_size) {
    if (new_block_size >= MIN_BLOCK_SIZE) {
        *(size_t *)remain = set_status(new_block_size - HEADER_SIZE, false);
        return true;
    }
    return false;
}

/*
  Takes in a pointer to the payload of a block.
  Returns the address of the header of the same block.
*/
void *find_header(Pointers *payload) {
    void *header = (char *)payload - HEADER_SIZE;
    return header;
}

/*
  Takes in a pointer to the header of a block.
  Returns a pointer to the payload of the same block.
*/
void *find_payload(void *header) {
    void *payload = (char *)header + HEADER_SIZE;
    return payload;
}

/*
  Takes in a header to a block and pointer to a Pointers struct.
  Inserts the Pointers struct into the payload of the header block.
*/
void insert_pointers(void *header, Pointers *pointers) {
    void *payload = (char *)header + HEADER_SIZE;
    *(Pointers *)payload = *pointers;
}

/*
  Takes in a pointer to a header of a block and a needed size.
  If the block has enough space for the needed size and at least 
  the MIN_BLOCK_SIZE, splits the block and returns the remaining half.
  Otherwise, returns NULL.
*/
void *split_block(void *header, size_t needed) {
    size_t size = *(size_t *)header & ~USED;
    long int remainder_size = size - needed - HEADER_SIZE;
    if (remainder_size < MIN_BLOCK_SIZE) {
        return NULL;
    } else {
        Pointers *header_pointers = (Pointers *)find_payload(header);
        void *remain_header = (char *)header + needed + HEADER_SIZE;
        insert_pointers(remain_header, header_pointers);
        return remain_header;
    }
}

/*
  Takes in a pointer to the payload of a free block.
  Using the pointers in inside the payload, removes the
  block from the heap by setting the previous free block's next
  block and next free block's previous to each other.
*/
void detatch_free_block(Pointers *free_payload) {
    void *prev_free = free_payload->prev;
    void *next_free = free_payload->next;
    if (prev_free != NULL) {
        Pointers *prev_pointers = (Pointers *)find_payload(prev_free);
        prev_pointers->next = next_free;
    }
    if (next_free != NULL) {
        Pointers *next_pointers = (Pointers *)find_payload(next_free);
        next_pointers->prev = prev_free;  
    }
    if (free_payload->prev == NULL && next_free != NULL) {
        search_start = next_free;
    }
}

/*
  Takes in a pointer the payload of a block. 
  Inserts the block back into heap by setting the
  previous free block's next block and the next free
  block's previous block to the passed in block.  
*/
void add_remainder(Pointers *new_free_payload) {
    void *new_header = find_header(new_free_payload);
    if (new_free_payload->prev != NULL) {
        Pointers *prev_pointers = (Pointers *)find_payload(new_free_payload->prev);
        prev_pointers->next = new_header;
    }
    if (new_free_payload->next != NULL) {
        Pointers *next_pointers = (Pointers *)find_payload(new_free_payload->next);
        next_pointers->prev = new_header;
    }
    if (new_free_payload->prev == NULL) {
        search_start = new_header;
    }
}

/*
  Using pointers within the payload space of free blocks,
  loops through all free blocks until a block that is 
  at least requested_size and is closet to the start
  of the heap. Returns the a pointer to the found block.
  If no such block is found, returns NULL.
*/
void *search_explicit(size_t requested_size) {
    void *cur = search_start;
    void *best_fit = NULL;
    while (cur != NULL) {
        size_t block_size = (*(size_t *)cur) & ~USED;
        Pointers *pointers = find_payload(cur);
        if (block_size >= requested_size && (best_fit == NULL || cur < best_fit)) {
            best_fit = cur;
        }
        cur = pointers->next;
    }
    return best_fit;
}

/*
  Takes in a pointer to the Pointers struct inside
  a freed block. Inserts free block into the front
  of the heap.
*/
void add_freed_block(Pointers *freed_payload) {
    void *header = find_header(freed_payload);
    Pointers *start_pointers = (Pointers *)find_payload(search_start);
    freed_payload->prev = NULL;
    freed_payload->next = search_start;
    start_pointers->prev = header;
    search_start = header;
}

/*
  Takes in the headers to 2 blocks. Combines
  their block sizes and returns the combined size.
*/
size_t combine(void *header1, void *header2) {
    size_t size1 = *(size_t *)header1;
    size_t size2 = *(size_t *)header2;

    return size1 + size2 + HEADER_SIZE;
}

/*
  Takes in a header to a block. Using block
  size, finds and returns the address of the 
  rightmost neighbor.
*/
void *find_right_neighbor(void *header) {
    size_t block_size = *(size_t *)header & ~USED;
    void *neighbor = (char *)header + HEADER_SIZE + block_size;
    return neighbor;
}

/*
  Takes in a header to a block. Checks the status
  of the block. If the block is free, returns true.
  If the block is used, returns false.
*/
bool is_free(void *header) {
    if (header == NULL) {
        return false;
    }
    size_t block_info = *(size_t *)header;
    int status = block_info & USED;
    if (status == 1) {
        return false;
    }
    return true;
}

/*
  Takes in a header to a block. Checks if the block
  has any free neighbors to combine payload sizes with.
  If so, block combines with neighbor to form one block.
*/
void coalesce(void *header) {
    Pointers *old_pointers = (Pointers *)find_payload(header);
    void *neighbor = find_right_neighbor(header);
    if (neighbor >= heap_end || !is_free(neighbor)) {
        return;
    }
    Pointers *neighbor_pointers = (Pointers *)find_payload(neighbor);
    detatch_free_block(neighbor_pointers);
    size_t new_size = combine(header, neighbor);
    *(size_t *)header = set_status(new_size, false);
    if (old_pointers->prev == NULL && old_pointers->next != NULL) {
        search_start = header;
    }
}

/*
  Takes in a pointer to the payload of the block and the needed size
  for a new, realloced block. Continuously combines block with its freed neighbors
  until the needed size can be satisfied.If old payload can coalesce with its neighbors,
  splits the combined block into another free block is possible. Returns
  the old_payload if coalescing was a success. Otherwise, returns NULL.
*/
void *coalesce_realloc(void *old_payload, size_t needed) {
    void *old_header = (char *)old_payload - HEADER_SIZE;
    void *neighbor = find_right_neighbor(old_header);
    while (neighbor != NULL && neighbor < heap_end && is_free(neighbor)) {
        Pointers *neighbor_pointers = (Pointers *)find_payload(neighbor);
        void *neighbor_next = neighbor_pointers->next;
        void *neighbor_prev = neighbor_pointers->prev;

        // Coalesce
        detatch_free_block(neighbor_pointers);
        size_t combo_size = combine(old_header, neighbor);
        *(size_t *)old_header = set_status(combo_size, true);
        
        if (combo_size >= needed) { 
            void *remainder = split_block(old_header, needed);
            if (remainder == NULL) {  // Just enough combined space   
                return old_payload;
            }
            // Split block if enough free space
            Pointers *remainder_payload = (Pointers *)find_payload(remainder);
            *(size_t *)old_header = set_status(needed, true);
            *(size_t *)remainder = set_status(combo_size - needed - HEADER_SIZE, false);
            if (neighbor == search_start) {
                remainder_payload->next = neighbor_next;
                remainder_payload->prev = neighbor_prev;
                search_start = remainder;
            } else  {
                myfree(remainder_payload);
            }
            return old_payload;        
        }
        neighbor = find_right_neighbor(old_header);
    }
    return NULL;
}

/*
  Given a status created by a bitmask, checks whether the status 
  is 0 (free) or 1 (used). If status is not either one of these choices, 
  returns false. Otherwise, return true.
*/
bool is_valid_status(size_t status) {
    return (status == 0 || status == 1);
}

/*
  Given a pointer to a free block header on the heap, checks
  whether the pointers in the payload lie within the heap space.
  If any pointer is invalid, returns false. Otherwise, returns true.
*/
bool has_valid_pointers(void *cur) {
    Pointers *cur_pointers = (Pointers *)((char *)cur + HEADER_SIZE);
    if (cur_pointers->next != NULL && (cur_pointers->next < segment_start || cur_pointers->next > heap_end)) {
        return false;
    }
    if (cur_pointers->prev != NULL && (cur_pointers->prev < segment_start || cur_pointers->prev > heap_end)) {
        return false;
    }
    return true;
}

/*
  Loops through each header in the heap and checks if the headers have a 
  well formed status, a valid block size, and well formed pointers if the
  block is free. Returns false if any errors are found. Otherwise, 
  returns true.
*/
bool check_headers() {
    void *ptr = segment_start;
    void *end = (char *)ptr + segment_size;
    while (ptr != end) {
        size_t status = *(size_t *)ptr & USED;
        if (!is_valid_status(status)) {
            printf("Address %p has incorect status.", ptr);
            breakpoint();
            return false;
        } else if (status == 0 && !has_valid_pointers(ptr)) {
            printf("Address %p invalid pointers", ptr);
            breakpoint();
            return false;
        }
        size_t block_size = *(size_t *)ptr & ~USED;
        if ((block_size < ALIGNMENT && block_size != 0) || block_size > segment_size) {
            printf("Address %p has invalid block size", ptr);
            breakpoint();
            return false;
        }
        ptr = (char *)ptr + block_size + HEADER_SIZE;  // Move to next block
    }
    return true;
}

/*
  Only run once when the program starts. Sets
  the variables segment_start, segment_size, and nused 
  to the heap start, heap_size, and 0 respectively.
  Sets search_start to the start of the heap.
  Inserts a Pointers struct inside first block.
  If the heap size or heap start is invalid, returns false.
  Otherwise, returns true after setup is finished.
*/
bool myinit(void *heap_start, size_t heap_size) {
    if (heap_size < MIN_HEAP_SIZE) { 
        return false;
    }
    segment_start = heap_start;
    segment_size = heap_size;
    search_start = heap_start;
    heap_end = (char *)segment_start + segment_size;

    nused = 0;
    
    Pointers *first_block = (Pointers *)((char *)heap_start + HEADER_SIZE);
    first_block->next = NULL;
    first_block->prev = NULL;

    size_t payload_size = set_status(heap_size - HEADER_SIZE, false);
    *(size_t *) heap_start = payload_size;
    
    return true;
}

/*
  Takes in requested_size for a block on heap. Searches through
  freed blocks to find a block to satisfy request. If a block is found,
  frees the excess space of the block if possible and returns the address of
  the payload of the block. Otherwise, returns NULL.
*/
void *mymalloc(size_t requested_size) {
    size_t needed = align(requested_size, ALIGNMENT);
    if (needed + nused + HEADER_SIZE > segment_size || requested_size == 0 || requested_size > MAX_REQUEST_SIZE) {
        return NULL;
    }
    void *ptr = search_explicit(needed);
    if (ptr != NULL) {
        Pointers *ptr_payload = (Pointers *)find_payload(ptr);
        detatch_free_block(ptr_payload);
        void *remainder = split_block(ptr, needed);
        // Set block to used
        size_t old_size = *(size_t *)ptr;
        *(size_t *)ptr = set_status(needed, true);
        nused += (needed + HEADER_SIZE);

        // Free extra space if possible
        if (remainder == NULL) {
            *(size_t *)ptr = set_status(old_size, true);
        } else {
            Pointers *remainder_payload = (Pointers *)find_payload(remainder);
            add_remainder(remainder_payload);
            void *remainder_header = find_header(remainder_payload);
            *(size_t *)remainder_header = set_status(old_size - needed - HEADER_SIZE, false);
        }
        return (char *)ptr + HEADER_SIZE;
    }
    return NULL;
}

/*
  Takes in a pointer to the payload of a block.
  Updates the status of the block to free and 
  inserts block back into heap. If block's neighbor
  is also free, will coalesce into a combined block.
*/
void myfree(void *ptr) {
    if (ptr == NULL) {
        return;
    }
    void *header = find_header(ptr);
    size_t size = *(size_t *)header;
    *(size_t *)header = set_status(size, false);
    add_freed_block((Pointers *)ptr);
    coalesce(header);
}

/*
  Takes in a pointer to the heap and a new requested size for memory.
  If the requested size fits into the already allocated block. Either
  reallocs in place or frees old pointer and moves to new space.
  Can realloc in place if any of the following 3 cases are satisfied:
  
  Case 1: Just enough default space inside old_ptr
  Case 2: Default space has more than enough space inside old_ptr
  Case 3: Default space can combine with free neigbor for enough space

  If new_size is 0, then returns NULL. Otherwise, mallocs into new space
  and returns new address. 
*/
void *myrealloc(void *old_ptr, size_t new_size) {
    if (old_ptr == NULL) {
        return mymalloc(new_size);
    }
    if (new_size == 0) {
        myfree(old_ptr);
        return NULL;
    }

    size_t needed = align(new_size, ALIGNMENT);
    void *old_header = (char *)old_ptr - HEADER_SIZE;
    size_t block_size = *(size_t *)old_header & ~USED;
    if (block_size >= new_size) {
        void *remainder = split_block(old_header, needed);
        void *remainder_payload = (char *)remainder + HEADER_SIZE;
        if (remainder == NULL) {  // Case 1
            return old_ptr;
        }
        // Case 2
        *(size_t *)old_header = set_status(needed, true);
        *(size_t *)remainder = set_status(block_size - needed - HEADER_SIZE, false);
        myfree(remainder_payload);
        return old_ptr;
    }

    // Case 3
    void *combination = coalesce_realloc(old_ptr, needed);

    if (combination == NULL) {
        void *new_block = mymalloc(new_size);
        memcpy(new_block, old_ptr, block_size);
        myfree(old_ptr);
        return new_block;
    }
    return combination;
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
    printf("Search Start: %p\n\n", search_start);
    while (ptr != end) {
        size_t status = *(size_t *)ptr & USED;
        size_t block_size = *(size_t *)ptr & ~USED;

        printf("Address: %p\n", ptr);
        printf("Header: %ld\n", *(size_t *)ptr);
        printf("Block Size: %ld\n", block_size);
        printf("Status: %ld\n", status);

        if (status == 0) {
            Pointers *free_block = (Pointers *)((char *)ptr + HEADER_SIZE);
            printf("Next: %p\n", free_block->next);
            printf("Previous: %p\n", free_block->prev);
        } 

        printf("\n");
        
        ptr = (char *)ptr + block_size + HEADER_SIZE;  // Move to next block
    }
}
