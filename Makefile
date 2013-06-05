SUBDIR=		snmpd snmpctl
MAKE_FLAGS=	BINDIR=/usr/sbin SUDO=sudo

.include <bsd.subdir.mk>
