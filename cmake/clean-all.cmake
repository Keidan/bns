#clean-all.cmake
set(cmake_generated ${CMAKE_BINARY_DIR}/CMakeCache.txt
                    ${CMAKE_BINARY_DIR}/cmake_install.cmake  
                    ${CMAKE_BINARY_DIR}/Makefile
                    ${CMAKE_BINARY_DIR}/CMakeFiles
                    ${CMAKE_BINARY_DIR}/src/cmake_install.cmake  
                    ${CMAKE_BINARY_DIR}/src/Makefile
                    ${CMAKE_BINARY_DIR}/src/CMakeFiles
                    ${CMAKE_BINARY_DIR}/bin/x86
                    ${CMAKE_BINARY_DIR}/bin/x86_64
                    ${CMAKE_BINARY_DIR}/bin/xscale
		    ${CMAKE_BINARY_DIR}/doc
)

foreach(file ${cmake_generated})
  if (EXISTS ${file})
     file(REMOVE_RECURSE ${file})
  endif()
endforeach(file)


execute_process(
  COMMAND find . -type f -name "*~" -exec rm {} \;
) 
