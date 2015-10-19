#include "ungzip.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <zlib.h>

#define SEGMENT_SIZE 1460 //largest tcp data segment

int ungzip(char* dst, const char* src, int len)
{
    int ret, have;
    int offset = 0;
    z_stream strm;
    Byte compr[SEGMENT_SIZE]={0}, uncompr[SEGMENT_SIZE*4]={0};
    uLong comprLen, uncomprLen;

    memcpy(compr,(Byte*)src,len);
    comprLen =len;
    uncomprLen = SEGMENT_SIZE*4;
    strcpy((char*)uncompr, "garbage");

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    strm.next_in = Z_NULL;
    strm.avail_in = 0;

    ret = inflateInit2(&strm,47);
    if(ret != Z_OK){
       printf("inflateInit2 error:%d",ret);
       goto end;
    }

    strm.next_in=compr;
    strm.avail_in=comprLen;
    do
    {
        strm.next_out=uncompr;
        strm.avail_out=uncomprLen;
        ret = inflate(&strm,Z_NO_FLUSH);

        assert(ret != Z_STREAM_ERROR);

        switch (ret)
        {
        case Z_NEED_DICT:
                  ret = Z_DATA_ERROR;
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                  (void)inflateEnd(&strm);
                   goto end;
        }

        have = uncomprLen - strm.avail_out;
        memcpy(dst+offset,uncompr,have);
        offset += have;

    }while(strm.avail_out == 0);

    inflateEnd(&strm);

    memcpy(dst + offset,"\0",1);

end:
    return ret;
}
