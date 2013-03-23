#clean-all.cmake
set(cmake_generated ${CMAKE_BINARY_DIR}/CMakeCache.txt
                    ${CMAKE_BINARY_DIR}/cmake_install.cmake  
                    ${CMAKE_BINARY_DIR}/Makefile
                    ${CMAKE_BINARY_DIR}/CMakeFiles
                    ${CMAKE_BINARY_DIR}/src/library/cmake_install.cmake  
                    ${CMAKE_BINARY_DIR}/src/library/Makefile
                    ${CMAKE_BINARY_DIR}/src/library/CMakeFiles
                    ${CMAKE_BINARY_DIR}/src/binary/cmake_install.cmake  
                    ${CMAKE_BINARY_DIR}/src/binary/Makefile
                    ${CMAKE_BINARY_DIR}/src/binary/CMakeFiles
)

foreach(file ${cmake_generated})
  if (EXISTS ${file})
     file(REMOVE_RECURSE ${file})
  else (NOT EXISTS ${file})
     message("File ${file} not found")
  endif()

endforeach(file)


execute_process(
  COMMAND find . -type f -name "*~" -exec rm {} \;
) 
