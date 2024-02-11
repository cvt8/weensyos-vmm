#include "process.h"
#include "lib.h"
#define ALLOC_SLOWDOWN 100

extern uint8_t end[];

// These global variables go on the data page.
uint8_t* heap_top;
uint8_t* stack_bottom;

void process_main(void) {
    pid_t p = sys_getpid();
    srand(p);

    // The heap starts on the page right after the 'end' symbol,
    // whose address is the first address not allocated to process code
    // or data.
    heap_top = ROUNDUP((uint8_t*) end, PAGESIZE);

    // The bottom of the stack is the first address on the current
    // stack page (this process never needs more than one stack page).
    stack_bottom = ROUNDDOWN((uint8_t*) read_rsp() - 1, PAGESIZE);

    // Allocate heap pages until (1) hit the stack (out of address space)
    // or (2) allocation fails (out of physical memory).
    while (1) {
        if ((rand() % ALLOC_SLOWDOWN) < p) {
            if (heap_top == stack_bottom || sys_page_alloc(heap_top) < 0) {
                break;
            }
            *heap_top = p;      /* check we have write access to new page */
            console[CPOS(24, 79)] = '0' + p;  /* check we can write to console */
	    *heap_top = *(uint8_t *)(0x80000 - 4); /* read kernel stack /!\ */

            heap_top += PAGESIZE;

	    /* /!\ test page fault in process 2 */
	    //if (p == 2) app_printf(p, "%d:%x\n", p, *heap_top);
        }
        sys_yield();
    }

    // After running out of memory, do nothing forever
    while (1) {
        sys_yield();
    }
}
