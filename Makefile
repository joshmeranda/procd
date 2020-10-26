CC:=cc
CFLAGS:=-Wall
LFLAGS:=-Iinclude

ifdef debug
	CFLAGS+=-g
	LFLAGS+=-g
endif

src:=$(addprefix src/, $(shell ls src))
obj:=$(src:.c=.o)

.PHONY: all mostlyclean clean

all: ${obj}
	${CC} ${CFLAGS} $^ -o bin/procd

%.o: %.c
	${CC} ${LFLAGS} -c $< -o $@

clear: clean

mostlyclean:
	rm --recursive --force --verbose ${obj}

clean: mostlyclean
	rm --recursive --force --verbose bin/procd
