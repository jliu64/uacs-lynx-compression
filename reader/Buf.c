/**
 * This file includes the implementation for a buffer. It is intended to interface with files so that they 
 *  are efficiently read. Note, all reads must be less than BUF_SIZE (hopefully significantly less).
 **/

#include <assert.h>
#include "Buf.h"
#include "ReaderUtils.h"

/**
 * Function: loadN
 * Description: Checks to see if n bytes can be read from the current position (pos) in the buffer. If 
 *  there is not enough space remaining in the buffer, the bytes before pos will be discarded and BUF_SIZE
 *  data will be read from the file with the data previously pointed to by pos now at the beginning of the
 *  buffer. If there is enough space in the buffer, nothing needs to be done.
 * Assumptions: Buf has been initialized and pos points to a memory location within buf->buf
 * Side effects: The state of the buffer is updated when more data is loaded from a file
 * Output: NULL if the readLimit has been reached. Otherwise the position of the data the user requested
 **/
uint8_t *loadN(Buf *buf, uint8_t *pos, uint16_t n) {
	uint16_t dataInd = pos - buf->buf;
	
	if ((dataInd + n) > buf->bufSize) {
		//determine how much we have left in the buffer
        uint16_t inBufAmt = BUF_SIZE - dataInd;
		
		//copy unused data from buffer to beginning of buffer
		int i;
		for (i = 0; i < inBufAmt; i++)
			buf->buf[i] = buf->buf[i + dataInd];
		
		//decompress data from compressed buffer into decompressed buffer until latter full
		buf->strm->avail_out = dataInd;
        buf->strm->next_out = &((buf->buf)[inBufAmt]);//TODO: Test this
		while (buf->strm->avail_out > 0) { // HERE; infinite loop, out = 2982, in = 189
			//printf("%d\n", buf->strm->avail_out);//DELETEME
			//printf("in: %d\n", buf->strm->avail_in);//DELETEME
			//reset buffer of compressed file data if empty
			if (buf->strm->avail_in <= 0) {
				//read size might not be BUF_SIZE if we are near the end of the read region
				uint16_t readSize = (BUF_SIZE < (buf->readLimit - buf->bytesRead)) 
					? BUF_SIZE : buf->readLimit - buf->bytesRead;
				//break if we've already read and decompressed everything from the read region
				if (readSize <= 0)
					break;
				//go to appropriate file position
				if (fseek(buf->file, buf->filePos, SEEK_SET))
					throwError("Invalid file read position");
				//read file data
				buf->compressedBufSize = fread(buf->compressedBuf, sizeof(uint8_t), readSize, buf->file);
				if (buf->compressedBufSize < readSize)
					throwError("Unable to read expected data size from file");
				if ((buf->filePos = ftell(buf->file)) == -1)
					throwError("Invalid file position after read");
				//reset zlib input stream
				buf->strm->avail_in = buf->compressedBufSize;
				buf->strm->next_in = buf->compressedBuf;
				//adjust our count
				buf->bytesRead += buf->compressedBufSize;
			}
			//decompression step
            int ret = inflate(buf->strm, Z_NO_FLUSH);// was Z_FINISH, is returning Z_STREAM_END
			if (ret == Z_STREAM_END)
				break;
			if (buf->strm->msg != NULL)
				printf("%s\n", buf->strm->msg);// it was a Z_DATA_ERROR; incorrect header check
            assert(ret != Z_STREAM_ERROR);
            switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                (void)inflateEnd(buf->strm);
                throwError("zlib decompression memory error");
            }
        }
		//update buffer size (avail_out is remaining space in zlib output buffer)
		buf->bufSize = BUF_SIZE - buf->strm->avail_out;
		
        return buf->buf;
    }

    return pos;
}

/**
 * Function: getBytesRemaining
 * Description: Calculates the number of bytes remaining in the buffered section of the file based on the
 *  current position (pos)
 * Assumptions: buf has been initialized and pos points to a location within buf->buf
 * Output: Number of bytes remaining in Buf until we reach limit
 **/
uint64_t getBytesRemaining(Buf *buf, uint8_t *pos) {
    return buf->readLimit - buf->bytesRead + buf->bufSize - (pos - buf->buf);
}

/**
 * Function: createBuf
 * Description: Creates a Buf, which is a buffered section of a file. It requires a file, a position in the
 *  file that marks the beginning of the buffered position and a limit on the amount of data to read from
 *  the file. Note, limit implies a limit on the number of byte to read, not an ending position.
 * Output: A buffer for the specified portion of the file
 **/
Buf *createBuf(FILE *file, uint64_t filePos, uint64_t readLimit) {
    Buf *buf = malloc(sizeof(Buf));

    if (buf == NULL) {
        return NULL;
    }

    //setup buf
    buf->file = file;
    buf->filePos = filePos;
    buf->bytesRead = 0;
    buf->readLimit = readLimit;
    buf->bufSize = 0;
	buf->strm = malloc(sizeof(z_stream));
	
	//allocate inflate state
    (buf->strm)->zalloc = Z_NULL;
    (buf->strm)->zfree = Z_NULL;
    (buf->strm)->opaque = Z_NULL;
    (buf->strm)->avail_in = 0;
    (buf->strm)->next_in = Z_NULL;
	int ret = inflateInit(buf->strm);
    //int ret = inflateInit2(buf->strm, -15);//invalid stored block lengths; starting at wrong position?
    assert(ret == Z_OK);
	
    //load initial information into buf
	if (fseek(file, filePos, SEEK_SET))
        throwError("Invalid file read position");
	buf->compressedBufSize = fread(buf->compressedBuf, sizeof(uint8_t), BUF_SIZE, file);
	assert(buf->compressedBufSize == BUF_SIZE);
	buf->strm->avail_in = buf->compressedBufSize;
	buf->strm->next_in = buf->compressedBuf;
    loadN(buf, buf->buf + BUF_SIZE, 1);

    return buf;
}

/**
 * Function: freeBuf
 * Description: Frees the memory from the buf, but does not close the file.
 * Output: None
 **/
void freeBuf(Buf *buf) {
    //free the data structure
	(void)inflateEnd(buf->strm);
	free(buf->strm);
    free(buf);
}
