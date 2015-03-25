#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include "centic-crypto.h"
#include <time.h>


int main(int argc, char **argv)
{
    char st[64];
    int page_size = getpagesize();
    int len = 128 * page_size;
    void *src = memalign(page_size,len);
    void *dest = memalign(page_size,len);
    CTCRYP_Ioctl_Test_Dma_t test_ioctl_data;

    test_ioctl_data.src = src;
    test_ioctl_data.dest = dest;
    test_ioctl_data.len = len;

    int count_times = 0;

    unsigned long time_spend;
    unsigned long size;

    printf("Src and Dest addresses %p - %p\n",src,dest);
    int filehd = open("/dev/centic-crypto",O_RDONLY);
    if (filehd == -1) {
        printf("Err Open device node: %d\n",errno);
        return -1;
    }

    snprintf((char *)src,len,"Hello every body ========= 01234567891012345678901234567890123456789012345678901234567890123456789");
    snprintf((char *)dest,len,"================ 012345678910");

//    if (ioctl(filehd,CTCRYP_IOC_TEST_DMA,&test_ioctl_data)) {
//       printf("Test DMA fail\n");
//    }
//    else {
//        //printf("[%d] Test DMA okie ===== \n",count_times);
//    }
    size = 0;
    time_spend = 0;
    do {
        if (ioctl(filehd,CTCRYP_IOC_TEST_DMA,&test_ioctl_data)) {
            printf("Test DMA fail\n");
        }
        else {
            size+=test_ioctl_data.data_size;
            time_spend += test_ioctl_data.time_spend;
            //printf("[%d] Test DMA okie ===== \n",count_times);
        }
        count_times++;
    }while(count_times < 100);

    printf("Time_spend: %d ms to transfer: %d Bytes\n",time_spend,size);

    if (time_spend) {
        float speed = ((float)(size)*1000)/(time_spend*1024*1024);
        snprintf(st,sizeof(st),"%2.2f MBps => %2.2f Mbps",speed,speed * 8);
    }
    else {
         snprintf(st,sizeof(st),"Undefined");
    }
    printf("Speed: %s\n",st);
    printf("Dest result: %s\n",(char *)dest);
    printf("Dest result: %s\n",(char *)src);

    if (filehd != -1)
        close(filehd);

    free(src);
    free(dest);
    return 0;
}

