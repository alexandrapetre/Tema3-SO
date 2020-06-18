/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <math.h>

#include "utils.h"
#include "exec_parser.h"

#define pageSize 4096

static so_exec_t *exec;
static struct sigaction oldAction;
static int fd;
static char *globalPath;

static void handler(int signum, siginfo_t *info, void *context)
{
	int i;
	int numberOfSegments;
	int rest;
	int pageNumber;
	int *data;
	int dif;
	int verify;
	int fill;
	int fileSize, memSize, offset, perms;
	uintptr_t vaddr;
	char  *pageFault_addr;
	char *p;
	so_seg_t *segment;

	numberOfSegments = exec->segments_no;
	segment = exec->segments;
	i = 0;
	verify = 0;
	pageFault_addr = (char *)info->si_addr;

	for (i = 0; i < numberOfSegments; i++) {

		vaddr = segment[i].vaddr;
		memSize = segment[i].mem_size;

		if (pageFault_addr <= (char *) memSize + vaddr &&
		pageFault_addr >= (char *) vaddr) {
			verify = 1;
			break;
		}
	}

	if (verify == 0) {
		oldAction.sa_sigaction(signum, info, context);
		return;
	}

	for (i = 0; i < numberOfSegments; i++) {

		vaddr = segment[i].vaddr;
		memSize = segment[i].mem_size;
		fileSize = segment[i].file_size;
		offset = segment[i].offset;
		perms = segment[i].perm;

		if (!(pageFault_addr <= (char *) memSize + vaddr &&
		pageFault_addr >= (char *) vaddr))
			continue;

		dif = (uintptr_t) (pageFault_addr - vaddr);
		pageNumber = dif / pageSize;

		data = (int *) segment[i].data;

		if (data[pageNumber] == 1) {
			oldAction.sa_sigaction(signum, info, context);
			return;
		}

		if (fileSize == memSize) {
			if (fileSize < pageSize) {
				p = mmap((char *)vaddr +
				pageNumber * pageSize, fileSize,
				perms, MAP_PRIVATE | MAP_FIXED,
				fd, pageNumber * pageSize +
				offset);
				DIE(p == (char *) -1, "mmap");
				data[pageNumber] = 1;
			} else if (fileSize >= pageSize) {
				p = mmap((char *)vaddr +
				pageNumber * pageSize, pageSize,
				perms, MAP_PRIVATE | MAP_FIXED,
				fd, pageNumber * pageSize +
				offset);
				DIE(p == (char *) -1, "mmap");
				data[pageNumber] = 1;
			}
			break;
		}


		if (fileSize < memSize) {
			if (pageNumber * pageSize < fileSize) {
				rest = fileSize - (pageSize * pageNumber);
				if (rest >= pageSize) {
					p = mmap((char *) vaddr +
					pageNumber * pageSize,
					pageSize, perms,
					MAP_PRIVATE | MAP_FIXED,
					fd, pageNumber * pageSize +
					offset);
					DIE(p == (char *) -1, "mmap");
					data[pageNumber] = 1;
				} else if (rest < pageSize) {
					p = mmap((char *) vaddr +
					pageNumber * pageSize,
					rest, perms,
					MAP_PRIVATE | MAP_FIXED,
					fd, pageNumber * pageSize +
					offset);
					DIE(p == (char *) -1, "mmap");
					data[pageNumber] = 1;
					fill = pageSize - rest;
					memset((char *) vaddr + pageSize *
					pageNumber + rest, 0, fill);
				}
			} else if (pageNumber * pageSize >= fileSize) {
				p = mmap((char *) vaddr +
				pageNumber * pageSize, pageSize,
				perms, MAP_PRIVATE | MAP_FIXED | MAP_ANON,
				-1, 0);
				DIE(p == (char *) -1, "mmap");
				data[pageNumber] = 1;
			}

			break;
		}
	}
}

int so_init_loader(void)
{
	struct sigaction action;
	int rc;

	action.sa_sigaction = handler;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;

	rc = sigaction(SIGSEGV, &action, &oldAction);
	DIE(rc == -1, "sigaction");

	return 0;
}

int so_execute(char *path, char *argv[])
{
	so_seg_t *segment;
	int noSeg;
	int i;
	int numberOfPages;
	float float_num;
	int *pointer;

	globalPath = calloc(strlen(path) + 1, sizeof(path));
	memcpy(globalPath, path, strlen(path) + 1);

	fd = open(globalPath, O_RDONLY, 0644);
	DIE(fd < 0, "open");

	exec = malloc(sizeof(so_exec_t));
	exec = so_parse_exec(path);
	noSeg = exec->segments_no;
	segment = exec->segments;

	for (i = 0; i < noSeg; i++) {
		float_num = (float) segment[i].mem_size / pageSize;
		numberOfPages = ceil(float_num);
		pointer = (int *) calloc(numberOfPages + 1, sizeof(int));
		segment[i].data = (int *) pointer;
	}

	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	return 0;
}
