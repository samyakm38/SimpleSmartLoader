#include "loader.h"
#include <signal.h>

Elf32_Ehdr *ehdr; // ELF header
Elf32_Phdr *phdr; // Program header
int fd; // File descriptor
int page_faults=0; // Page fault counter
int total_pages=0; // Total pages counter
int bytes_lost=0; // Bytes lost counter
uintptr_t segfault_address_arr[128];
int segfault_address_arr_size=0;


// Signal handler for SIGSEGV
static void my_handler(int signum, siginfo_t* si, void* vcontext) {
    if (signum == SIGSEGV) { 
        segfault_address_arr[segfault_address_arr_size]=(uintptr_t) si->si_addr;;
        segfault_address_arr_size++;
        uintptr_t segfault_address = (uintptr_t) si->si_addr; // Get the address that caused the segfault
        Elf32_Phdr *reqPhdr = NULL; // Requested program header

        for (size_t i = 0; i < ehdr->e_phnum; ++i) {
            if (segfault_address >= phdr[i].p_vaddr && segfault_address < phdr[i].p_vaddr + phdr[i].p_memsz) {
                if(phdr[i].p_type!=PT_NULL){ 
                    reqPhdr=&phdr[i]; // Get the required program header
                    break;
                }
            }
        }
        void* reqAddr =(void *)((uintptr_t)ehdr + (reqPhdr->p_offset)); // Requested address

        size_t allocation_size=4096; // Allocation size = 4KB(page size)
        int multiple=1; 
        
        void *allocated_memory = mmap((void*)segfault_address,allocation_size,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_ANONYMOUS|MAP_PRIVATE,0,0);
        if (allocated_memory == MAP_FAILED) { 
            perror("mmap");
            exit(1); 
        }
        memcpy(allocated_memory,reqAddr,4096); // Copy the requested address to the allocated memory

        page_faults++; // Increment page fault counter
        
        // Calculate and increment bytes lost if allocation size is greater than program header memory size
        if(allocation_size>reqPhdr->p_memsz){ 
            bytes_lost+=(allocation_size-reqPhdr->p_memsz); 
        }
        total_pages+=multiple; 
    }
}                        

void load_and_run_elf(char** exe) {
    
    fd = open(exe[1], O_RDONLY); // Open the file
    if (fd == -1) { 
        perror("open");
        exit(1);
    }
    off_t elfSize = lseek(fd, 0, SEEK_END); // Get the size of the file
    if (elfSize == -1) { 
        perror("lseek");
        exit(1);
    }
    void *content = malloc(elfSize); // Allocate memory for the file content
    if (content == NULL) {
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }
    lseek(fd, 0, SEEK_SET); // Set the file offset to the beginning of the file
    ssize_t bytesread= read(fd, content, elfSize); 
    if (bytesread == -1) { 
        perror("read");
        exit(1);
    }
    ehdr = (Elf32_Ehdr *)content; // Set the ELF header
    unsigned char *elfData = (unsigned char *)content; 
    memcpy(ehdr,elfData,sizeof(Elf32_Ehdr)); // Copy the ELF data to the ELF header
    
    size_t numEntries = ehdr->e_phnum; // Number of program headers
    off_t phOffset = ehdr->e_phoff; // Program header offset
    size_t phEntrySize = ehdr->e_phentsize; // Program header entry size
    phdr = (Elf32_Phdr *)malloc(phEntrySize*numEntries); // Allocate memory for the program headers
    if (phdr == NULL) { 
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }
    ssize_t ph_read = pread(fd, phdr, phEntrySize*numEntries, phOffset); // Read the program headers
    if (ph_read == -1) { 
        perror("pread");
        exit(1);
    }
    //Define StartFunction type, set it and run it.
    typedef int (*StartFunction)(void); 
    StartFunction _start = (StartFunction)((uintptr_t)ehdr->e_entry); 
    int result =_start(); 
    printf("_start return value = %d\n", result); 
    
}

void loader_cleanup() {
    for(int i=0;i<segfault_address_arr_size;i++){
        munmap((void*)segfault_address_arr[i],4096);
    }
    if (phdr || ehdr) {
        free(phdr);
        free(ehdr);
    }
    if (fd != -1) {
        close(fd);
    }
}

int main(int argc, char** argv) 
{
    if(argc != 2) { 
        printf("Usage: %s <ELF Executable> \n",argv[0]); 
        exit(1);
    }
                                                                                                         
    struct sigaction sig; 
    memset(&sig, 0, sizeof(sig)); // Initialize signal action
    sig.sa_flags = SA_SIGINFO; // Set signal action flags
    sig.sa_sigaction = my_handler; // Set signal action handler
    sigaction(SIGSEGV, &sig, NULL); // Set signal action for SIGSEGV
  
    load_and_run_elf(argv); 

    loader_cleanup();

    // REPORT - Print page fault, total pages and total internal fragmentation
    printf("Page faults = %d\n",page_faults); 
    printf("Total pages = %d\n",total_pages); 
    printf("Total internal fragmentation = %f KB \n",(float)bytes_lost/1024.0);
  
    return 0; 
}
