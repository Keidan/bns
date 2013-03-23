/**
 *******************************************************************************
 * @file bns_logger.h
 * @author Keidan
 * @date 03/01/2013
 * @par Project
 * bns
 *
 * @par Copyright
 * Copyright 2011-2013 Keidan, all right reserved
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY.
 *
 * Licence summary : 
 *    You can modify and redistribute the sources code and binaries.
 *    You can send me the bug-fix
 *
 * Term of the licence in in the file licence.txt.
 *
 *******************************************************************************
 */
#ifndef __BNS_LOGGER_H__
  #define __BNS_LOGGER_H__

  #ifndef BNS_LOGGER_STD
    #define BNS_LOGGER_STD stderr
  #endif /* BNS_LOGGER_STD */

  #ifdef LOGGER
    #include <libgen.h>

    #define __LOG_FILE__       basename(__FILE__)
    #define __TMP_LOG__(...)   fprintf(BNS_LOGGER_STD, __VA_ARGS__)
    #define logger(fmt, ...)   __TMP_LOG__("[%s::%s(%d) -> " fmt, __LOG_FILE__, __func__, __LINE__, ##__VA_ARGS__)
  #else
    #define logger(fmt, ...) ({ })
  #endif

#endif /* __BNS_LOGGER_H__ */
