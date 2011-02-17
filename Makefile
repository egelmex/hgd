SQL_CPPFLAGS=`pkg-config --cflags sqlite3`
SQL_LDFLAGS=`pkg-config --libs sqlite3`

SSL_LDFLAGS=-lssl -lcrypto

CFLAGS+=-Wall -Wextra -g

prefix?=/usr/local
mandir?=${prefix}/man/man1
sbindir?=${prefix}/sbin
bindir?=${prefix}/bin

.PHONY: all
all: hgd-playd hgd-netd hgd-admin hgdc

.PHONY: clean
clean:
	-rm hgd-playd hgd-netd hgdc common.o db.o

common.o: common.c hgd.h
	${CC} ${CPPFLAGS} ${CFLAGS} -c -o common.o common.c

db.o: db.c hgd.h
	${CC} ${CPPFLAGS} ${SQL_CPPFLAGS} ${CFLAGS} -c -o db.o db.c

hgd-playd: common.o db.o hgd-playd.c hgd.h
	${CC} ${CPPFLAGS} ${SQL_CPPFLAGS} ${CFLAGS} ${SQL_LDFLAGS} \
		${SSL_LDFLAGS} ${LDFLAGS} -o hgd-playd \
		db.o common.o hgd-playd.c

hgd-netd: common.o hgd-netd.c hgd.h db.o
	${CC} ${CPPFLAGS} ${SQL_CPPFLAGS} ${CFLAGS} ${SQL_LDFLAGS} \
		${SSL_LDFLAGS} ${LDFLAGS} -o hgd-netd \
		common.o db.o hgd-netd.c

hgdc: common.o hgdc.c hgd.h
	${CC} ${CPPFLAGS} ${CFLAGS} ${LDFLAGS} ${SSL_LDFLAGS} \
		-o hgdc common.o hgdc.c

hgd-admin: common.o db.o hgd.h hgd-admin.c
	${CC} ${CPPFLAGS} ${CFLAGS} ${SQL_CPPFLAGS} ${SQL_LDFLAGS} \
		${SSL_LDFLAGS} ${LDFLAGS} \
		-o hgd-admin common.o db.o hgd-admin.c


.PHONY: install
install: hgd-playd hgd-netd hgdc hgd-admin
	${INSTALL} hgd-netd ${DESTDIR}${sbindir}
	${INSTALL} hgd-playd ${DESTDIR}${sbindir}
	${INSTALL} hgd-admin ${DESTDIR}${sbindir}
	${INSTALL} hgdc ${DESTDIR}${bindir}
	${INSTALL} man/hgd-netd.1 ${DESTDIR}${mandir}
	${INSTALL} man/hgd-playd.1 ${DESTDIR}${mandir}
	${INSTALL} man/hgdc.1 ${DESTDIR}${mandir}
	#${INSTALL} man/hgd-admin.1 ${DESTDIR}${mandir}
