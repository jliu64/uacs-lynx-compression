#ifndef __BUF_H_
#define __BUF_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "zlib.h"

#define BUF_SIZE 4096

typedef struct Buf_t {
    // The actual buffer that gets filled in
    uint8_t  buf[BUF_SIZE];
    // The size of the buffer
    uint16_t bufSize;
    // The number of bytes read so far
    uint64_t bytesRead;
    // The file to read from
    FILE *file;
    // The current position in the file
    uint64_t filePos;
    // how many bytes to read from the file before stopping
    uint64_t readLimit;
	// The buffer for compressed file input
	uint8_t compressedBuf[BUF_SIZE];
	// The size of the compressed data buffer
	uint16_t compressedBufSize;
	// The z_stream object used by zlib to decompress data
	z_stream *strm;
} Buf;

int reachedReadLimit(Buf *buf, uint8_t *pos);
uint8_t *loadN(Buf *buf, uint8_t *pos, uint16_t n);
Buf *createBuf(FILE *file, uint64_t filePos, uint64_t readLimit);
uint64_t getBytesRemaining(Buf *buf, uint8_t *pos);
void freeBuf(Buf *buf);

#endif
