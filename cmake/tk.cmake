#tk.cmake

# Build TK env
exec_program(${CMAKE_COMMAND} lib/tk
  ARGS
  -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DDISTRIBUTION=${DISTRIBUTION} 
)
# Creation of tk targets
add_custom_target(libtk 
  COMMAND make -C lib/tk
)
add_custom_target(libtk_clean-all 
  COMMAND make -C lib/tk clean-all
)

add_dependencies(bns libtk)
add_dependencies(clean-all libtk_clean-all)
set(extra_clean 
  lib/tk/lib/${DISTRIBUTION}/${CMAKE_BUILD_TYPE}/libtk.so 
  lib/tk/src/tk/CMakeFiles/tk.dir/text/string.c.o
  lib/tk/src/tk/CMakeFiles/tk.dir/text/stringbuffer.c.o
  lib/tk/src/tk/CMakeFiles/tk.dir/text/stringtoken.c.o
  lib/tk/src/tk/CMakeFiles/tk.dir/sys/log.c.o
  lib/tk/src/tk/CMakeFiles/tk.dir/sys/sysutils.c.o
  lib/tk/src/tk/CMakeFiles/tk.dir/sys/z.c.o
  lib/tk/src/tk/CMakeFiles/tk.dir/shell/shell.c.o
  lib/tk/src/tk/CMakeFiles/tk.dir/shell/shell_term.c.o
  lib/tk/src/tk/CMakeFiles/tk.dir/sys/proc.c.o
  lib/tk/src/tk/CMakeFiles/tk.dir/io/net/netutils.c.o
  lib/tk/src/tk/CMakeFiles/tk.dir/io/net/netprint.c.o
  lib/tk/src/tk/CMakeFiles/tk.dir/io/sr.c.o
  lib/tk/src/zlib-minizip/CMakeFiles/zlib-minizip.dir/unzip.c.o
  lib/tk/src/zlib-minizip/CMakeFiles/zlib-minizip.dir/ioapi.c.o
)
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${extra_clean}")

