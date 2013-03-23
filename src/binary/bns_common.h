/**
 *******************************************************************************
 * @file bns_common.c
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
#ifndef __BNS_COMMON_H__
  #define __BNS_COMMON_H__

  #include <stdio.h>
  #include <stdlib.h>
  #include <unistd.h>
  #include <errno.h>
  #include <string.h>
  #include <bns/bns.h>



  typedef void(*usage_fct)(int);

  /**
   * Fonction gerant le mode input.
   * @param input Fichier input.
   * @param payload_only Retire uniquement la payload.
   * @return 0 si succes sinon -1.
   */
  int bns_input(FILE* input, _Bool payload_only);

  /**
   * Fonction gerant le mode output et console.
   * @param output Fichier output ou NULL pour le mode console.
   * @param iname Interface ou NULL pour any.
   * @param filter Filtre.
   * @param usage Fonction usage.
   * @return 0 si succes sinon -1.
   */
  int bns_output(FILE* output, char iname[IF_NAMESIZE], struct bns_filter_s filter, usage_fct usage);

#endif /* __BNS_COMMON_H__ */