CC:=cc
CFLAGS:=-g -Wall
LFLAGS:=-Iinclude -g -Wall

src:=$(addprefix src/, $(shell ls src))
obj:=$(src:.c=.o)

.PHONY: all procd mostlyclean clean

all: bin/procd

bin/procd: ${obj}
	${CC} ${CFLAGS} ${obj} -o $@

%.o: %.c
	${CC} ${LFLAGS} -c $< -o $@

clear: clean

mostlyclean:
	rm --recursive --force --verbose ${obj}

clean: mostlyclean
	rm --recursive --force --verbose bin/procd
