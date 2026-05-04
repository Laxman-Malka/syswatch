#pragma once
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>   

inline std::string parse_sockaddr(void *addr_ptr)
{
    struct sockaddr *sa = (struct sockaddr *)addr_ptr;

    if (sa->sa_family == AF_INET)
    {
        struct sockaddr_in *in = (struct sockaddr_in *)sa;

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));

        return std::string(ip) + ":" + std::to_string(ntohs(in->sin_port));
    }
    else if (sa->sa_family == AF_INET6)
    {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;

        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));

        return std::string("[") + ip + "]:" +
               std::to_string(ntohs(in6->sin6_port));
    }
    else if (sa->sa_family == AF_UNIX)
    {
        struct sockaddr_un *un = (struct sockaddr_un *)sa;

        if (un->sun_path[0] == '\0')
        {
            // abstract socket (Linux-specific)
            return std::string("@") + (un->sun_path + 1);
        }

        return std::string(un->sun_path);
    }

    return "unknown";
}