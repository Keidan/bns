SRC         	= ./src
OBJ         	= ./obj
DEST		= bns

CC         	= gcc
ECHO       	= @echo
MKDIR       	= @mkdir -p
CFLAG      	= -Wall -Werror -O3

#total:
#	make all
#	make clean
all: $(DEST)
clean:
	@rm -f $(OBJ)/*
	@rm -f $(DEST)

$(DEST): $(OBJ)/bns_utils.o $(OBJ)/bns.o
	$(CC) $(CFLAG) $^ -o $@

$(OBJ)/%.o:$(SRC)/%.c
	$(MKDIR) $(OBJ)
	$(MKDIR) `dirname $@`
	$(ECHO) 'Building target: $@'
	$(CC) $(CFLAG) -c $< -o $@


