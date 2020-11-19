# compiler info
CC:=gcc
CFLAGS:=-Wall
LFLAGS:=-Iinclude

ifdef debug
	CFLAGS+=-g
	LFLAGS+=-g
endif

# generic common names
PROG_NAME:=procd
UNIT_NAME:=${PROG_NAME}.service

# system installation destinations
INSTALL_DIR:=/usr/bin
INSTALL_BIN:=${INSTALL_DIR}/${PROG_NAME}

SERVICE_INSTALL:=/etc/systemd/system
SERVICE_INSTALL_UNIT:=${SERVICE_INSTALL}/${UNIT_NAME}

# local targets
BIN:=bin/${PROG_NAME}

# packaging info / targets
VERSION:=0.0.1-rc
TAR:=procd-${VERSION}.gz.tar

src:=$(addprefix src/, $(shell ls src))
obj:=$(src:.c=.o)

.PHONY: all dist install uninstall mostlyclean clean

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Project compilation and linking                                             #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
all: ${obj}
	${CC} ${CFLAGS} $^ -o ${BIN}

%.o: %.c
	${CC} ${LFLAGS} -c $< -o $@

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Package the project for distribution                                        #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
dist: all
	tar --exclude .gitkeep --verbose --gzip --create --file ${TAR} \
		LICENSE README.md bin

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Install and uninstall                                                       #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
LN=ln --symbolic --verbose --force
RM=rm --recursive --force --verbose

install: ${BIN}
	${LN} $(realpath $<) ${INSTALL_BIN}
	${LN} $(realpath ${UNIT_NAME}) ${SERVICE_INSTALL_UNIT}
	cp --update --verbose examples/procd.conf /etc

uninstall:
	${RM} ${INSTALL_BIN} ${SERVICE_INSTALL_UNIT}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Clean work tree of compiled / generated files                               #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
mostlyclean:
	 ${RM} ${obj} vgcore.* massif.*

clean: mostlyclean
	${RM} bin/procd ${TAR}
