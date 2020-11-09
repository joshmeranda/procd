CC:=cc
CFLAGS:=-Wall
LFLAGS:=-Iinclude

VERSION=0.1-rc
TAR=procd-${VERSION}.gz.tar

ifdef debug
	CFLAGS+=-g
	LFLAGS+=-g
endif

src:=$(addprefix src/, $(shell ls src))
obj:=$(src:.c=.o)

.PHONY: all dist mostlyclean clean

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Project compilation and linking                                             #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
all: ${obj}
	${CC} ${CFLAGS} $^ -o bin/procd

%.o: %.c
	${CC} ${LFLAGS} -c $< -o $@

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Package the project for distribution                                        #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
dist: all
	tar --exclude .gitkeep --verbose --gzip --create --file ${TAR} \
		LICENSE README.md bin

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Clean work tree of compiled / generated files                               #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
mostlyclean:
	rm --recursive --force --verbose ${obj} vgcore.* massif.*

clean: mostlyclean
	rm --recursive --force --verbose bin/procd ${TAR}
