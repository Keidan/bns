#ifndef __BNS_LOGGER_H__
  #define __BNS_LOGGER_H__

  #ifndef BNS_LOGGER_STD
    #define BNS_LOGGER_STD stderr
  #endif /* BNS_LOGGER_STD */

  #ifdef DEBUG
    #include <libgen.h>

    #define __LOG_FILE__       basename(__FILE__)
    #define __TMP_LOG__(...)   fprintf(BNS_LOGGER_STD, __VA_ARGS__)
    #define logger(fmt, ...)   __TMP_LOG__("[%s::%s(%d) -> " fmt, __LOG_FILE__, __func__, __LINE__, ##__VA_ARGS__)
  #else
    #define logger(fmt, ...) ({ })
  #endif

#endif /* __BNS_LOGGER_H__ */
