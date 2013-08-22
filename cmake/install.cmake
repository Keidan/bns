
set(tmp_dir "/tmp/${NAME}")

file(COPY "${LIBRARIES}/libtk.so" DESTINATION "${tmp_dir}")
file(COPY "${LIBRARIES}/libzlib-minizip.so" DESTINATION "${tmp_dir}")
file(COPY "${BINARIES}/bns" DESTINATION "${tmp_dir}/")

execute_process(
  COMMAND /bin/tar -cpf "${BINARIES}/${NAME}.tar" -C /tmp "${NAME}"
)
file(REMOVE_RECURSE "/tmp/${NAME}")
