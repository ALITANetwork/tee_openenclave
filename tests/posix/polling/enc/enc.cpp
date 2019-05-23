/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#include <openenclave/enclave.h>
#include <openenclave/internal/time.h>

// enclave.h must come before socket.h
#include <openenclave/corelibc/arpa/inet.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/netinet/in.h>
#include <openenclave/corelibc/sys/poll.h>
#include <openenclave/corelibc/sys/select.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/internal/tests.h>

#include <assert.h>
#include <epoll_test_t.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include "epoll_test_t.h"
#include "interface.h"

#define MAX_EVENTS 20

static char _path[OE_PATH_MAX];

extern "C" int ecall_device_init(const char* tmp_dir)
{
    OE_TEST(tmp_dir != NULL);
    OE_TEST(oe_load_module_host_file_system() == OE_OK);
    OE_TEST(oe_load_module_host_socket_interface() == OE_OK);
    OE_TEST(oe_load_module_host_epoll() == OE_OK);

    strlcpy(_path, tmp_dir, sizeof(_path));
    strlcat(_path, "/test", sizeof(_path));

    OE_TEST(mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) == 0);

    /* Create a file. */
    {
        int fd = oe_open(_path, OE_O_CREAT | OE_O_WRONLY | OE_O_TRUNC, 0666);
        if (fd < 0)
        {
            printf("could not open file %s.\n", _path);
        }
        OE_TEST(fd != -1);
        oe_close(fd);
        printf("Created %s\n", _path);
    }

    return 0;
}

extern "C" void ecall_device_shutdown(void)
{
    umount("/");
}

const char* print_socket_success(int numfds, int* fdlist)
{
    static const char* msg = "socket success";
    ssize_t n;
    char buff[1024] = {0};
    (void)numfds;

    printf("%s\n", msg);
    n = oe_read(fdlist[0], buff, sizeof(buff));
    buff[n] = 0;
    printf("received data %s from fd %d\n", buff, fdlist[0]);
    return msg;
}

const char* print_file_success(int numfds, int* fdlist)
{
    static const char* msg = "file success";
    printf("%s\n", msg);
    (void)numfds;
    (void)fdlist;
    return msg;
}

/* This client connects to an echo server, sends a text message,
 * and outputs the text reply.
 */
template <class INTERFACE>
static int _ecall_epoll_test(INTERFACE& x, size_t buff_len, char* recv_buff)
{
    typedef typename INTERFACE::SOCKADDR_IN_T SOCKADDR_IN_T;
    typedef typename INTERFACE::SOCKADDR_T SOCKADDR_T;
    typedef typename INTERFACE::EPOLL_EVENT_T EPOLL_EVENT_T;
    int sockfd = 0;
    SOCKADDR_IN_T serv_addr = {0};
    EPOLL_EVENT_T event = {0};
    EPOLL_EVENT_T events[MAX_EVENTS] = {{0}};
    int epoll_fd = x.epoll_create1(0);

    printf("--------------- epoll -------------\n");
    if (epoll_fd == -1)
    {
        printf("Failed to create epoll file descriptor\n");
        return OE_FAILURE;
    }

    memset(recv_buff, 0, buff_len);
    printf("create socket\n");
    if ((sockfd = x.socket(x.AF_INET_T, x.SOCK_STREAM_T, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return OE_FAILURE;
    }
    serv_addr.sin_family = x.AF_INET_T;
    serv_addr.sin_addr.s_addr = x.htonl(x.INADDR_LOOPBACK_T);
    serv_addr.sin_port = x.htons(1642);

    printf("socket fd = %d\n", sockfd);
    printf("Connecting...\n");
    int retries = 0;
    static const int max_retries = 4;

    while (x.connect(sockfd, (SOCKADDR_T*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        if (retries++ > max_retries)
        {
            printf("\n Error : Connect Failed \n");
            x.close(sockfd);
            return OE_FAILURE;
        }
        else
        {
            printf("Connect Failed. Retrying \n");
        }
    }

    printf("polling...\n");

    // ATTN: where does this magic value come from?
    event.events = OE_EPOLLIN;
    event.data.ptr = (void*)print_socket_success;
    if (x.epoll_ctl(epoll_fd, x.EPOLL_CTL_ADD_T, sockfd, &event))
    {
        fprintf(
            stderr,
            "Failed to add socket file descriptor to epoll errno = %d: %s %u\n",
            errno,
            __FILE__,
            __LINE__);
        x.close(epoll_fd);
        return 1;
    }

    size_t nevents = 0;
    int nfds = 0;
    do
    {
        if ((nfds = x.epoll_wait(epoll_fd, events, MAX_EVENTS, 30000)) < 0)
        {
            printf("error.\n");
            assert("x.epoll_wait() failed" == NULL);
        }
        else
        {
            printf("input from %d fds\n", nfds);

            nevents += (size_t)nfds;

            for (int i = 0; i < nfds; i++)
            {
                nevents++;

                const char* (*func)(int numfds, int* fdlist) =
                    (const char* (*)(int, int*))events[i].data.ptr;
                printf("func = %p\n", events[i].data.ptr);
                if (func)
                {
                    const char* rtn = (*func)(1, &sockfd);
                    if (rtn)
                    {
                        strncpy(recv_buff, rtn, buff_len);
                        nfds = -1; // to exit do/while
                        break;
                    }
                }
            }
        }

    } while (nfds >= 0);

    printf("nevents=%zu\n", nevents);
    OE_TEST(nevents > 0);

    if (sockfd != -1)
        x.close(sockfd);

    if (epoll_fd != -1)
        x.close(epoll_fd);

    oe_sleep_msec(3);

    printf("--------------- epoll done -------------\n");

    return OE_OK;
}

int ecall_epoll_test(size_t buff_len, char* recv_buff, bool use_libc)
{
    if (use_libc)
    {
        libc x;
        return _ecall_epoll_test(x, buff_len, recv_buff);
    }
    else
    {
        corelibc x;
        return _ecall_epoll_test(x, buff_len, recv_buff);
    }
}

template <class INTERFACE>
static int _ecall_select_test(
    INTERFACE& x,
    size_t buff_len,
    char* recv_buff,
    bool test_regular_files)
{
    typedef typename INTERFACE::SOCKADDR_IN_T SOCKADDR_IN_T;
    typedef typename INTERFACE::SOCKADDR_T SOCKADDR_T;
    typedef typename INTERFACE::FD_SET_T FD_SET_T;
    typedef typename INTERFACE::TIMEVAL_T TIMEVAL_T;
    int sockfd = 0;
    int file_fd = 0;
    SOCKADDR_IN_T serv_addr = {0};
    FD_SET_T readfds;
    FD_SET_T writefds;
    FD_SET_T exceptfds;
    TIMEVAL_T timeout = {0};
    int max_fd = 0;

    OE_UNUSED(x);

    x.FD_ZERO_F(&readfds);
    x.FD_ZERO_F(&writefds);
    x.FD_ZERO_F(&exceptfds);

    printf("--------------- select -------------\n");
    memset(recv_buff, 0, buff_len);
    printf("create socket\n");
    if ((sockfd = x.socket(x.AF_INET_T, x.SOCK_STREAM_T, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return OE_FAILURE;
    }
    serv_addr.sin_family = x.AF_INET_T;
    serv_addr.sin_addr.s_addr = x.htonl(x.INADDR_LOOPBACK_T);
    serv_addr.sin_port = x.htons(1642);

    printf("socket fd = %d\n", sockfd);
    printf("Connecting...\n");

    int retries = 0;
    static const int max_retries = 4;
    while (x.connect(sockfd, (SOCKADDR_T*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        if (retries++ > max_retries)
        {
            printf("\n Error : Connect Failed \n");
            x.close(sockfd);
            return OE_FAILURE;
        }
        else
        {
            printf("Connect Failed. Retrying \n");
        }
    }
    if (sockfd >= 0)
    {
        x.FD_SET_F(sockfd, &readfds);
        // x.FD_SET_F(sockfd, &writefds);
        // x.FD_SET_F(sockfd, &exceptfds);

        if (sockfd > max_fd)
            max_fd = sockfd;
    }

    const int flags = x.O_NONBLOCK_T | x.O_RDONLY_T;
    file_fd = x.open(_path, flags, 0);
    OE_TEST(file_fd >= 0);

    printf("polling...\n");
    if (file_fd >= 0 && test_regular_files)
    {
        x.FD_SET_F(file_fd, &readfds);
        x.FD_SET_F(file_fd, &writefds);
        x.FD_SET_F(file_fd, &exceptfds);

        if (file_fd > max_fd)
            max_fd = file_fd;
    }

    size_t nevents = 0;
    int nfds = 0;
    do
    {
        timeout.tv_sec = 30;
        if ((nfds = x.select(
                 max_fd + 1, &readfds, &writefds, &exceptfds, &timeout)) < 0)
        {
            printf("select error.\n");
        }
        else
        {
            printf("input from %d fds\n", nfds);
            nevents++;

            if (x.FD_ISSET_F(sockfd, &readfds))
            {
                printf("select: read event\n");

                ssize_t n;
                char buff[1024] = {0};

                printf("read sockfd:%d\n", sockfd);
                n = x.read(sockfd, buff, sizeof(buff));
                buff[n] = 0;
                if (n > 0)
                {
                    memcpy(
                        recv_buff,
                        buff,
                        ((size_t)n < buff_len) ? (size_t)n : buff_len);
                    nfds = -1;
                    break;
                }
            }
            else if (x.FD_ISSET_F(sockfd, &writefds))
            {
                printf("select: write event\n");
            }
            else if (x.FD_ISSET_F(sockfd, &exceptfds))
            {
                printf("select: exception event\n");
            }
        }

    } while (nfds >= 0);

    OE_TEST(nevents > 0);

    x.close(sockfd);
    x.close(file_fd);
    printf("--------------- select done -------------\n");
    return OE_OK;
}

int ecall_select_test(
    size_t buff_len,
    char* recv_buff,
    bool use_libc,
    bool test_regular_files)
{
    if (use_libc)
    {
        libc x;
        return _ecall_select_test(x, buff_len, recv_buff, test_regular_files);
    }
    else
    {
        corelibc x;
        return _ecall_select_test(x, buff_len, recv_buff, test_regular_files);
    }
}

template <class INTERFACE>
static int _ecall_poll_test(
    INTERFACE& x,
    size_t buff_len,
    char* recv_buff,
    bool test_regular_files)
{
    typedef typename INTERFACE::SOCKADDR_IN_T SOCKADDR_IN_T;
    typedef typename INTERFACE::SOCKADDR_T SOCKADDR_T;
    typedef typename INTERFACE::POLLFD_T POLLFD_T;
    int sockfd = 0;
    int file_fd = 0;
    SOCKADDR_IN_T serv_addr = {0};
    POLLFD_T pollfds[3] = {{0}};
    oe_nfds_t num_pollfds = 0;
    int timeout_ms = 30000; // in millis
    short events = 0;

    /* Set up mask of all poll events. */
    events |= POLLIN;
    events |= POLLPRI;
    events |= POLLOUT;
    events |= POLLRDNORM;
    events |= POLLRDBAND;
    events |= POLLWRNORM;
    events |= POLLWRBAND;
    events |= POLLRDHUP;

    OE_UNUSED(test_regular_files);

    printf("--------------- poll -------------\n");
    memset(recv_buff, 0, buff_len);
    printf("create socket\n");
    if ((sockfd = x.socket(OE_AF_INET, OE_SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return OE_FAILURE;
    }
    serv_addr.sin_family = OE_AF_INET;
    serv_addr.sin_addr.s_addr = x.htonl(OE_INADDR_LOOPBACK);
    serv_addr.sin_port = x.htons(1642);

    printf("socket fd = %d\n", sockfd);
    printf("Connecting...\n");
    int retries = 0;
    static const int max_retries = 4;
    while (x.connect(sockfd, (SOCKADDR_T*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        if (retries++ > max_retries)
        {
            printf("\n Error : Connect Failed \n");
            x.close(sockfd);
            return OE_FAILURE;
        }
        else
        {
            printf("Connect Failed. Retrying \n");
        }
    }

    if (sockfd >= 0)
    {
        pollfds[num_pollfds].fd = sockfd;
        pollfds[num_pollfds].events = events;
        pollfds[num_pollfds].revents = 0;
        num_pollfds++;
    }

    const int flags = OE_O_NONBLOCK | OE_O_RDONLY;
    file_fd = x.open(_path, flags, 0);
    OE_TEST(file_fd >= 0);

    if (file_fd >= 0 && test_regular_files)
    {
        pollfds[num_pollfds].fd = sockfd;
        pollfds[num_pollfds].events = events;
        pollfds[num_pollfds].revents = 0;
        num_pollfds++;
    }

    size_t nevents = 0;
    int nfds = 0;
    int ntries = 100;
    do
    {
        if ((nfds = x.poll(pollfds, num_pollfds, timeout_ms)) < 0)
        {
            printf("poll error.\n");
        }
        else
        {
            printf("input from %d fds\n", nfds);
            nevents++;

            printf("events from pollfds[0] = %x\n", pollfds[0].revents);
            printf("events from pollfds[1] = %x\n", pollfds[0].revents);
            if (pollfds[0].revents &
                (POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND))
            {
                ssize_t n;
                char buff[1024] = {0};

                printf("read sockfd:%d\n", sockfd);
                n = x.read(sockfd, buff, sizeof(buff));
                buff[n] = 0;
                if (n > 0)
                {
                    memcpy(
                        recv_buff,
                        buff,
                        ((size_t)n < buff_len) ? (size_t)n : buff_len);
                    nfds = -1;
                    break;
                }
                else
                {
                    sleep(1);
                }
            }
        }

    } while (nfds >= 0 && ntries-- > 0);

    OE_TEST(nevents > 0);

    x.close(sockfd);
    x.close(file_fd);
    printf("--------------- poll done -------------\n");
    return OE_OK;
}

int ecall_poll_test(
    size_t buff_len,
    char* recv_buff,
    bool use_libc,
    bool test_regular_files)
{
    if (use_libc)
    {
        libc x;
        return _ecall_poll_test(x, buff_len, recv_buff, test_regular_files);
    }
    else
    {
        corelibc x;
        return _ecall_poll_test(x, buff_len, recv_buff, test_regular_files);
    }
}

extern "C" int oe_epoll_wake(void);

int ecall_wait_test(void)
{
    int epfd;
    int nfds;
    struct oe_epoll_event events[MAX_EVENTS];
    const int TIMEOUT = 1000;
    size_t num_wakes = 0;

    printf("--------------- wake -------------\n");

    OE_TEST((epfd = oe_epoll_create1(0)) != -1);

    for (size_t i = 0; i < 8; i++)
    {
        nfds = oe_epoll_wait(epfd, events, MAX_EVENTS, TIMEOUT);
        int err = errno;

        printf("nfds=%d err=%d\n", nfds, err);

        if (nfds == -1)
        {
            OE_TEST((err == EINTR));
            num_wakes++;
        }
        else
        {
            OE_TEST(nfds == 0);
        }
    }

    OE_TEST(num_wakes == 3);

    oe_close(epfd);

    printf("--------------- wake done -------------\n");

    return 0;
}

int ecall_wake_test(void)
{
    printf("wake... \n");
    return oe_epoll_wake();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    256,  /* HeapPageCount */
    256,  /* StackPageCount */
    16);  /* TCSCount */
