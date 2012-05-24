/*	$OpenBSD: mib.c,v 1.64 2013/03/11 19:49:37 sthen Exp $	*/

/*
 * Copyright (c) 2012 Joel Knight <joel@openbsd.org>
 * Copyright (c) 2007, 2008, 2012 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/queue.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/tree.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <sys/sensors.h>
#include <sys/sched.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/disk.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/pfvar.h>
#include <net/if_pfsync.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_carp.h>
#include <netinet/ip_var.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <limits.h>
#include <kvm.h>

#include "snmpd.h"
#include "mib.h"

extern struct snmpd	*env;

/*
 * Defined in SNMPv2-MIB.txt (RFC 3418)
 */

int	 mib_getsys(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_getsnmp(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_sysor(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_setsnmp(struct oid *, struct ber_oid *, struct ber_element **);

static struct oid mib_tree[] = MIB_TREE;
static struct ber_oid zerodotzero = { { 0, 0 }, 2 };

#define sizeofa(_a) (sizeof(_a) / sizeof((_a)[0]))

/* base MIB tree */
static struct oid base_mib[] = {
	{ MIB(mib_2),			OID_MIB },
	{ MIB(sysDescr),		OID_RD, mib_getsys },
	{ MIB(sysOID),			OID_RD, mib_getsys },
	{ MIB(sysUpTime),		OID_RD, mib_getsys },
	{ MIB(sysContact),		OID_RW, mib_getsys, mps_setstr },
	{ MIB(sysName),			OID_RW, mib_getsys, mps_setstr },
	{ MIB(sysLocation),		OID_RW, mib_getsys, mps_setstr },
	{ MIB(sysServices),		OID_RS, mib_getsys },
	{ MIB(sysORLastChange),		OID_RD, mps_getts },
	{ MIB(sysORIndex),		OID_TRD, mib_sysor },
	{ MIB(sysORID),			OID_TRD, mib_sysor },
	{ MIB(sysORDescr),		OID_TRD, mib_sysor },
	{ MIB(sysORUpTime),		OID_TRD, mib_sysor },
	{ MIB(snmp),			OID_MIB },
	{ MIB(snmpInPkts),		OID_RD, mib_getsnmp },
	{ MIB(snmpOutPkts),		OID_RD, mib_getsnmp },
	{ MIB(snmpInBadVersions),	OID_RD, mib_getsnmp },
	{ MIB(snmpInBadCommunityNames),	OID_RD, mib_getsnmp },
	{ MIB(snmpInBadCommunityUses),	OID_RD, mib_getsnmp },
	{ MIB(snmpInASNParseErrs),	OID_RD, mib_getsnmp },
	{ MIB(snmpInTooBigs),		OID_RD,	mib_getsnmp },
	{ MIB(snmpInNoSuchNames),	OID_RD, mib_getsnmp },
	{ MIB(snmpInBadValues),		OID_RD, mib_getsnmp },
	{ MIB(snmpInReadOnlys),		OID_RD, mib_getsnmp },
	{ MIB(snmpInGenErrs),		OID_RD, mib_getsnmp },
	{ MIB(snmpInTotalReqVars),	OID_RD, mib_getsnmp },
	{ MIB(snmpInTotalSetVars),	OID_RD, mib_getsnmp },
	{ MIB(snmpInGetRequests),	OID_RD, mib_getsnmp },
	{ MIB(snmpInGetNexts),		OID_RD, mib_getsnmp },
	{ MIB(snmpInSetRequests),	OID_RD, mib_getsnmp },
	{ MIB(snmpInGetResponses),	OID_RD, mib_getsnmp },
	{ MIB(snmpInTraps),		OID_RD, mib_getsnmp },
	{ MIB(snmpOutTooBigs),		OID_RD, mib_getsnmp },
	{ MIB(snmpOutNoSuchNames),	OID_RD, mib_getsnmp },
	{ MIB(snmpOutBadValues),	OID_RD, mib_getsnmp },
	{ MIB(snmpOutGenErrs),		OID_RD, mib_getsnmp },
	{ MIB(snmpOutGetRequests),	OID_RD, mib_getsnmp },
	{ MIB(snmpOutGetNexts),		OID_RD, mib_getsnmp },
	{ MIB(snmpOutSetRequests),	OID_RD, mib_getsnmp },
	{ MIB(snmpOutGetResponses),	OID_RD, mib_getsnmp },
	{ MIB(snmpOutTraps),		OID_RD, mib_getsnmp },
	{ MIB(snmpEnableAuthenTraps),	OID_RW, mib_getsnmp, mib_setsnmp },
	{ MIB(snmpSilentDrops),		OID_RD, mib_getsnmp },
	{ MIB(snmpProxyDrops),		OID_RD, mib_getsnmp },
	{ MIBEND }
};

int
mib_getsys(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_oid		 sysoid = OID(MIB_SYSOID_DEFAULT);
	char			*s = oid->o_data;
	struct ber_oid		*so = oid->o_data;
	struct utsname		 u;
	long long		 ticks;

	if (uname(&u) == -1)
		return (-1);

	switch (oid->o_oid[OIDIDX_system]) {
	case 1:
		if (s == NULL) {
			if (asprintf(&s, "%s %s %s %s %s",
			    u.sysname, u.nodename, u.release,
			    u.version, u.machine) == -1)
				return (-1);
			oid->o_data = s;
			oid->o_val = strlen(s);
		}
		*elm = ber_add_string(*elm, s);
		break;
	case 2:
		if (so == NULL)
			so = &sysoid;
		smi_oidlen(so);
		*elm = ber_add_oid(*elm, so);
		break;
	case 3:
		ticks = smi_getticks();
		*elm = ber_add_integer(*elm, ticks);
		ber_set_header(*elm, BER_CLASS_APPLICATION, SNMP_T_TIMETICKS);
		break;
	case 4:
		if (s == NULL) {
			if (asprintf(&s, "root@%s", u.nodename) == -1)
				return (-1);
			oid->o_data = s;
			oid->o_val = strlen(s);
		}
		*elm = ber_add_string(*elm, s);
		break;
	case 5:
		if (s == NULL) {
			if ((s = strdup(u.nodename)) == NULL)
				return (-1);
			oid->o_data = s;
			oid->o_val = strlen(s);
		}
		*elm = ber_add_string(*elm, s);
		break;
	case 6:
		if (s == NULL)
			s = "";
		*elm = ber_add_string(*elm, s);
		break;
	case 7:
		*elm = ber_add_integer(*elm, oid->o_val);
		break;
	default:
		return (-1);
	}
	return (0);
}

int
mib_sysor(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_element	*ber = *elm;
	u_int32_t		 idx = 1, nmib = 0;
	struct oid		*next, *miboid;
	char			 buf[SNMPD_MAXSTRLEN];

	/* Count MIB root OIDs in the tree */
	for (next = NULL;
	    (next = smi_foreach(next, OID_MIB)) != NULL; nmib++);

	/* Get and verify the current row index */
	idx = o->bo_id[OIDIDX_sysOREntry];
	if (idx > nmib)
		return (1);

	/* Find the MIB root element for this Id */
	for (next = miboid = NULL, nmib = 1;
	    (next = smi_foreach(next, OID_MIB)) != NULL; nmib++) {
		if (nmib == idx)
			miboid = next;
	}
	if (miboid == NULL)
		return (-1);

	/* Tables need to prepend the OID on their own */
	ber = ber_add_oid(ber, o);

	switch (o->bo_id[OIDIDX_sysOR]) {
	case 1:
		ber = ber_add_integer(ber, idx);
		break;
	case 2:
		ber = ber_add_oid(ber, &miboid->o_id);
		break;
	case 3:
		/*
		 * This should be a description of the MIB.
		 * But we use the symbolic OID string for now, it may
		 * help to display names of internal OIDs.
		 */
		smi_oidstring(&miboid->o_id, buf, sizeof(buf));
		ber = ber_add_string(ber, buf);
		break;
	case 4:
		/*
		 * We do not support dynamic loading of MIB at runtime,
		 * the sysORUpTime value of 0 will indicate "loaded at
		 * startup".
		 */
		ber = ber_add_integer(ber, 0);
		ber_set_header(ber,
		    BER_CLASS_APPLICATION, SNMP_T_TIMETICKS);
		break;
	default:
		return (-1);
	}

	return (0);
}

int
mib_getsnmp(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct snmp_stats	*stats = &env->sc_stats;
	long long		 i;
	struct statsmap {
		u_int8_t	 m_id;
		u_int32_t	*m_ptr;
	}			 mapping[] = {
		{ 1, &stats->snmp_inpkts },
		{ 2, &stats->snmp_outpkts },
		{ 3, &stats->snmp_inbadversions },
		{ 4, &stats->snmp_inbadcommunitynames },
		{ 5, &stats->snmp_inbadcommunityuses },
		{ 6, &stats->snmp_inasnparseerrs },
		{ 8, &stats->snmp_intoobigs },
		{ 9, &stats->snmp_innosuchnames },
		{ 10, &stats->snmp_inbadvalues },
		{ 11, &stats->snmp_inreadonlys },
		{ 12, &stats->snmp_ingenerrs },
		{ 13, &stats->snmp_intotalreqvars },
		{ 14, &stats->snmp_intotalsetvars },
		{ 15, &stats->snmp_ingetrequests },
		{ 16, &stats->snmp_ingetnexts },
		{ 17, &stats->snmp_insetrequests },
		{ 18, &stats->snmp_ingetresponses },
		{ 19, &stats->snmp_intraps },
		{ 20, &stats->snmp_outtoobigs },
		{ 21, &stats->snmp_outnosuchnames },
		{ 22, &stats->snmp_outbadvalues },
		{ 24, &stats->snmp_outgenerrs },
		{ 25, &stats->snmp_outgetrequests },
		{ 26, &stats->snmp_outgetnexts },
		{ 27, &stats->snmp_outsetrequests },
		{ 28, &stats->snmp_outgetresponses },
		{ 29, &stats->snmp_outtraps },
		{ 31, &stats->snmp_silentdrops },
		{ 32, &stats->snmp_proxydrops }
	};

	switch (oid->o_oid[OIDIDX_snmp]) {
	case 30:
		i = stats->snmp_enableauthentraps == 1 ? 1 : 2;
		*elm = ber_add_integer(*elm, i);
		break;
	default:
		for (i = 0;
		    (u_int)i < (sizeof(mapping) / sizeof(mapping[0])); i++) {
			if (oid->o_oid[OIDIDX_snmp] == mapping[i].m_id) {
				*elm = ber_add_integer(*elm, *mapping[i].m_ptr);
				ber_set_header(*elm,
				    BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
				return (0);
			}
		}
		return (-1);
	}

	return (0);
}

int
mib_setsnmp(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct snmp_stats	*stats = &env->sc_stats;
	long long		 i;

	if (ber_get_integer(*elm, &i) == -1)
		return (-1);

	stats->snmp_enableauthentraps = i == 1 ? 1 : 0;

	return (0);
}

/*
 * Defined in SNMP-USER-BASED-SM-MIB.txt (RFC 3414)
 */
int	 mib_engine(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_usmstats(struct oid *, struct ber_oid *, struct ber_element **);

static struct oid usm_mib[] = {
	{ MIB(snmpEngine),			OID_MIB },
	{ MIB(snmpEngineID),			OID_RD, mib_engine },
	{ MIB(snmpEngineBoots),			OID_RD, mib_engine },
	{ MIB(snmpEngineTime),			OID_RD, mib_engine },
	{ MIB(snmpEngineMaxMsgSize),		OID_RD, mib_engine },
	{ MIB(usmStats),			OID_MIB },
	{ MIB(usmStatsUnsupportedSecLevels),	OID_RD, mib_usmstats },
	{ MIB(usmStatsNotInTimeWindow),		OID_RD, mib_usmstats },
	{ MIB(usmStatsUnknownUserNames),	OID_RD, mib_usmstats },
	{ MIB(usmStatsUnknownEngineId),		OID_RD, mib_usmstats },
	{ MIB(usmStatsWrongDigests),		OID_RD, mib_usmstats },
	{ MIB(usmStatsDecryptionErrors),	OID_RD, mib_usmstats },
	{ MIBEND }
};

int
mib_engine(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	switch (oid->o_oid[OIDIDX_snmpEngine]) {
	case 1:
		*elm = ber_add_nstring(*elm, env->sc_engineid,
		    env->sc_engineid_len);
		break;
	case 2:
		*elm = ber_add_integer(*elm, env->sc_engine_boots);
		break;
	case 3:
		*elm = ber_add_integer(*elm, snmpd_engine_time());
		break;
	case 4:
		*elm = ber_add_integer(*elm, READ_BUF_SIZE);
		break;
	default:
		return -1;
	}
	return 0;
}

int
mib_usmstats(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct snmp_stats	*stats = &env->sc_stats;
	long long		 i;
	struct statsmap {
		u_int8_t	 m_id;
		u_int32_t	*m_ptr;
	}			 mapping[] = {
		{ OIDVAL_usmErrSecLevel,	&stats->snmp_usmbadseclevel },
		{ OIDVAL_usmErrTimeWindow,	&stats->snmp_usmtimewindow },
		{ OIDVAL_usmErrUserName,	&stats->snmp_usmnosuchuser },
		{ OIDVAL_usmErrEngineId,	&stats->snmp_usmnosuchengine },
		{ OIDVAL_usmErrDigest,		&stats->snmp_usmwrongdigest },
		{ OIDVAL_usmErrDecrypt,		&stats->snmp_usmdecrypterr },
	};

	for (i = 0; (u_int)i < (sizeof(mapping) / sizeof(mapping[0])); i++) {
		if (oid->o_oid[OIDIDX_usmStats] == mapping[i].m_id) {
			*elm = ber_add_integer(*elm, *mapping[i].m_ptr);
			ber_set_header(*elm, BER_CLASS_APPLICATION,
			    SNMP_T_COUNTER32);
			return (0);
		}
	}
	return (-1);
}

/*
 * Defined in HOST-RESOURCES-MIB.txt (RFC 2790)
 */

int	 mib_hrsystemuptime(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_hrsystemdate(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_hrsystemprocs(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_hrmemory(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_hrstorage(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_hrdevice(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_hrprocessor(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_hrswrun(struct oid *, struct ber_oid *, struct ber_element **);

int	 kinfo_proc_comp(const void *, const void *);
int	 kinfo_proc(u_int32_t, struct kinfo_proc **);
int	 kinfo_args(struct kinfo_proc *, char **);

static struct oid hr_mib[] = {
	{ MIB(host),				OID_MIB },
	{ MIB(hrSystemUptime),			OID_RD, mib_hrsystemuptime },
	{ MIB(hrSystemDate),			OID_RD, mib_hrsystemdate },
	{ MIB(hrSystemProcesses),		OID_RD, mib_hrsystemprocs },
	{ MIB(hrSystemMaxProcesses),		OID_RD, mib_hrsystemprocs },
	{ MIB(hrMemorySize),			OID_RD,	mib_hrmemory },
	{ MIB(hrStorageIndex),			OID_TRD, mib_hrstorage },
	{ MIB(hrStorageType),			OID_TRD, mib_hrstorage },
	{ MIB(hrStorageDescr),			OID_TRD, mib_hrstorage },
	{ MIB(hrStorageAllocationUnits),	OID_TRD, mib_hrstorage },
	{ MIB(hrStorageSize),			OID_TRD, mib_hrstorage },
	{ MIB(hrStorageUsed),			OID_TRD, mib_hrstorage },
	{ MIB(hrStorageAllocationFailures),	OID_TRD, mib_hrstorage },
	{ MIB(hrDeviceIndex),			OID_TRD, mib_hrdevice },
	{ MIB(hrDeviceType),			OID_TRD, mib_hrdevice },
	{ MIB(hrDeviceDescr),			OID_TRD, mib_hrdevice },
	{ MIB(hrDeviceID),			OID_TRD, mib_hrdevice },
	{ MIB(hrDeviceStatus),			OID_TRD, mib_hrdevice },
	{ MIB(hrDeviceErrors),			OID_TRD, mib_hrdevice },
	{ MIB(hrProcessorFrwID),		OID_TRD, mib_hrprocessor },
	{ MIB(hrProcessorLoad),			OID_TRD, mib_hrprocessor },
	{ MIB(hrSWRunIndex),			OID_TRD, mib_hrswrun },
	{ MIB(hrSWRunName),			OID_TRD, mib_hrswrun },
	{ MIB(hrSWRunID),			OID_TRD, mib_hrswrun },
	{ MIB(hrSWRunPath),			OID_TRD, mib_hrswrun },
	{ MIB(hrSWRunParameters),		OID_TRD, mib_hrswrun },
	{ MIB(hrSWRunType),			OID_TRD, mib_hrswrun },
	{ MIB(hrSWRunStatus),			OID_TRD, mib_hrswrun },
	{ MIBEND }
};

int
mib_hrsystemuptime(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct timeval   boottime;
	int		 mib[] = { CTL_KERN, KERN_BOOTTIME };
	time_t		 now;
	size_t		 len;

	(void)time(&now);
	len = sizeof(boottime);

	if (sysctl(mib, 2, &boottime, &len, NULL, 0) == -1)
		return (-1);

	*elm = ber_add_integer(*elm, (now - boottime.tv_sec) * 100);
	ber_set_header(*elm, BER_CLASS_APPLICATION, SNMP_T_TIMETICKS);

	return (0);
}

int
mib_hrsystemdate(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct tm	*ptm;
	u_char		 s[11];
	time_t		 now;
	int		 tzoffset;
	unsigned short	 year;

	(void)time(&now);
	ptm = localtime(&now);

	year = htons(ptm->tm_year + 1900);
	memcpy(s, &year, 2);
	s[2] = ptm->tm_mon + 1;
	s[3] = ptm->tm_mday;
	s[4] = ptm->tm_hour;
	s[5] = ptm->tm_min;
	s[6] = ptm->tm_sec;
	s[7] = 0;

	tzoffset = ptm->tm_gmtoff;
	if (tzoffset < 0)
		s[8] = '-';
	else
		s[8] = '+';

	s[9] = abs(tzoffset) / 3600;
	s[10] = (abs(tzoffset) - (s[9] * 3600)) / 60;

	*elm = ber_add_nstring(*elm, s, sizeof(s));

	return (0);
}

int
mib_hrsystemprocs(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	char		 errbuf[_POSIX2_LINE_MAX];
	int		 val;
	int		 mib[] = { CTL_KERN, KERN_MAXPROC };
	kvm_t		*kd;
	size_t		 len;

	switch (oid->o_oid[OIDIDX_hrsystem]) {
	case 6:
		if ((kd = kvm_openfiles(NULL, NULL, NULL,
		    KVM_NO_FILES, errbuf)) == NULL)
			return (-1);

		if (kvm_getprocs(kd, KERN_PROC_ALL, 0,
		    sizeof(struct kinfo_proc), &val) == NULL)
			return (-1);

		*elm = ber_add_integer(*elm, val);
		ber_set_header(*elm, BER_CLASS_APPLICATION, SNMP_T_GAUGE32);

		kvm_close(kd);
		break;
	case 7:
		len = sizeof(val);
		if (sysctl(mib, 2, &val, &len, NULL, 0) == -1)
			return (-1);

		*elm = ber_add_integer(*elm, val);
		break;
	default:
		return (-1);
	}

	return (0);
}

int
mib_hrmemory(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_element	*ber = *elm;
	int			 mib[] = { CTL_HW, HW_PHYSMEM64 };
	u_int64_t		 physmem;
	size_t			 len = sizeof(physmem);

	if (sysctl(mib, sizeofa(mib), &physmem, &len, NULL, 0) == -1)
		return (-1);

	ber = ber_add_integer(ber, physmem / 1024);

	return (0);
}

int
mib_hrstorage(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_element	*ber = *elm;
	u_int32_t		 idx;
	struct statfs		*mntbuf, *mnt;
	int			 mntsize, maxsize;
	u_int32_t		 units, size, used, fail = 0;
	const char		*descr = NULL;
	int			 mib[] = { CTL_HW, 0 };
	u_int64_t		 physmem, realmem;
	struct uvmexp		 uvm;
	struct vmtotal		 vm;
	size_t			 len;
	static struct ber_oid	*sop, so[] = {
		{ { MIB_hrStorageOther } },
		{ { MIB_hrStorageRam } },
		{ { MIB_hrStorageVirtualMemory } },
		{ { MIB_hrStorageFixedDisk } }
	};

	/* Physical memory, real memory, swap */
	mib[1] = HW_PHYSMEM64;
	len = sizeof(physmem);
	if (sysctl(mib, sizeofa(mib), &physmem, &len, NULL, 0) == -1)
		return (-1);
	mib[1] = HW_USERMEM64;
	len = sizeof(realmem);
	if (sysctl(mib, sizeofa(mib), &realmem, &len, NULL, 0) == -1)
		return (-1);
	mib[0] = CTL_VM;
	mib[1] = VM_UVMEXP;
	len = sizeof(uvm);
	if (sysctl(mib, sizeofa(mib), &uvm, &len, NULL, 0) == -1)
		return (-1);
	mib[1] = VM_METER;
	len = sizeof(vm);
	if (sysctl(mib, sizeofa(mib), &vm, &len, NULL, 0) == -1)
		return (-1);
	maxsize = 10;

	/* Disks */
	mntsize = getmntinfo(&mntbuf, MNT_NOWAIT);
	if (mntsize)
		maxsize = 30 + mntsize;

	/*
	 * Get and verify the current row index.
	 *
	 * We use a special mapping here that is inspired by other SNMP
	 * agents: index 1 + 2 for RAM, index 10 for swap, index 31 and
	 * higher for disk storage.
	 */
	idx = o->bo_id[OIDIDX_hrStorageEntry];
	if (idx > (u_int)maxsize)
		return (1);
	else if (idx > 2 && idx < 10)
		idx = 10;
	else if (idx > 10 && idx < 31)
		idx = 31;

	sop = &so[0];
	switch (idx) {
	case 1:
		descr = "Physical memory";
		units = uvm.pagesize;
		size = physmem / uvm.pagesize;
		used = size - vm.t_free;
		sop = &so[1];
		break;
	case 2:
		descr = "Real memory";
		units = uvm.pagesize;
		size = realmem / uvm.pagesize;
		used = size - uvm.free;
		sop = &so[1];
		break;
	case 10:
		descr = "Swap space";
		units = uvm.pagesize;
		size = uvm.swpages;
		used = uvm.swpginuse;
		sop = &so[2];
		break;
	default:
		mnt = &mntbuf[idx - 31];
		descr = mnt->f_mntonname;
		units = mnt->f_bsize;
		size = mnt->f_blocks;
		used = mnt->f_blocks - mnt->f_bfree;
		sop = &so[3];
		break;
	}

	/* Tables need to prepend the OID on their own */
	o->bo_id[OIDIDX_hrStorageEntry] = idx;
	ber = ber_add_oid(ber, o);

	switch (o->bo_id[OIDIDX_hrStorage]) {
	case 1: /* hrStorageIndex */
		ber = ber_add_integer(ber, idx);
		break;
	case 2: /* hrStorageType */
		smi_oidlen(sop);
		ber = ber_add_oid(ber, sop);
		break;
	case 3: /* hrStorageDescr */
		ber = ber_add_string(ber, descr);
		break;
	case 4: /* hrStorageAllocationUnits */
		ber = ber_add_integer(ber, units);
		break;
	case 5: /* hrStorageSize */
		ber = ber_add_integer(ber, size);
		break;
	case 6: /* hrStorageUsed */
		ber = ber_add_integer(ber, used);
		break;
	case 7: /* hrStorageAllocationFailures */
		ber = ber_add_integer(ber, fail);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	default:
		return (-1);
	}

	return (0);
}

int
mib_hrdevice(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_element	*ber = *elm;
	u_int32_t		 idx, fail = 0;
	int			 status;
	int			 mib[] = { CTL_HW, HW_MODEL };
	size_t			 len;
	char			 descr[BUFSIZ];
	static struct ber_oid	*sop, so[] = {
		{ { MIB_hrDeviceProcessor } },
	};

	/* Get and verify the current row index */
	idx = o->bo_id[OIDIDX_hrDeviceEntry];
	if (idx > (u_int)env->sc_ncpu)
		return (1);

	/* Tables need to prepend the OID on their own */
	o->bo_id[OIDIDX_hrDeviceEntry] = idx;
	ber = ber_add_oid(ber, o);

	len = sizeof(descr);
	if (sysctl(mib, sizeofa(mib), &descr, &len, NULL, 0) == -1)
		return (-1);
	/* unknown(1), running(2), warning(3), testing(4), down(5) */
	status = 2;
	sop = &so[0];

	switch (o->bo_id[OIDIDX_hrDevice]) {
	case 1: /* hrDeviceIndex */
		ber = ber_add_integer(ber, idx);
		break;
	case 2: /* hrDeviceType */
		smi_oidlen(sop);
		ber = ber_add_oid(ber, sop);
		break;
	case 3: /* hrDeviceDescr */
		ber = ber_add_string(ber, descr);
		break;
	case 4: /* hrDeviceID */
		ber = ber_add_oid(ber, &zerodotzero);
		break;
	case 5: /* hrDeviceStatus */
		ber = ber_add_integer(ber, status);
		break;
	case 6: /* hrDeviceErrors */
		ber = ber_add_integer(ber, fail);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	default:
		return (-1);
	}

	return (0);
}

int
mib_hrprocessor(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_element	*ber = *elm;
	u_int32_t		 idx;
	int64_t			*cptime2, val;

	/* Get and verify the current row index */
	idx = o->bo_id[OIDIDX_hrDeviceEntry];
	if (idx > (u_int)env->sc_ncpu)
		return (1);
	else if (idx < 1)
		idx = 1;

	/* Tables need to prepend the OID on their own */
	o->bo_id[OIDIDX_hrDeviceEntry] = idx;
	ber = ber_add_oid(ber, o);

	switch (o->bo_id[OIDIDX_hrDevice]) {
	case 1: /* hrProcessorFrwID */
		ber = ber_add_oid(ber, &zerodotzero);
		break;
	case 2: /* hrProcessorLoad */
		/*
		 * The percentage of time that the system was not
		 * idle during the last minute.
		 */
		if (env->sc_cpustates == NULL)
			return (-1);
		cptime2 = env->sc_cpustates + (CPUSTATES * (idx - 1));
		val = 100 -
		    (cptime2[CP_IDLE] > 1000 ? 1000 : (cptime2[CP_IDLE] / 10));
		ber = ber_add_integer(ber, val);
		break;
	default:
		return (-1);
	}

	return (0);
}

int
mib_hrswrun(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_element	*ber = *elm;
	struct kinfo_proc	*kinfo;
	char			*s;

	/* Get and verify the current row index */
	if (kinfo_proc(o->bo_id[OIDIDX_hrSWRunEntry], &kinfo) == -1)
		return (1);

	if (kinfo == NULL)
		return (1);

	/* Tables need to prepend the OID on their own */
	o->bo_id[OIDIDX_hrSWRunEntry] = kinfo->p_pid;
	ber = ber_add_oid(ber, o);

	switch (o->bo_id[OIDIDX_hrSWRun]) {
	case 1: /* hrSWRunIndex */
		ber = ber_add_integer(ber, kinfo->p_pid);
		break;
	case 2: /* hrSWRunName */
	case 4: /* hrSWRunPath */
		ber = ber_add_string(ber, kinfo->p_comm);
		break;
	case 3: /* hrSWRunID */
		ber = ber_add_oid(ber, &zerodotzero);
		break;
	case 5: /* hrSWRunParameters */
		if (kinfo_args(kinfo, &s) == -1)
			return (-1);

		ber = ber_add_string(ber, s);
		break;
	case 6: /* hrSWRunType */
		if (kinfo->p_flag & P_SYSTEM) {
			/* operatingSystem(2) */
			ber = ber_add_integer(ber, 2);
		} else {
			/* application(4) */
			ber = ber_add_integer(ber, 4);
		}
		break;
	case 7: /* hrSWRunStatus */
		switch (kinfo->p_stat) {
		case SONPROC:
			/* running(1) */
			ber = ber_add_integer(ber, 1);
			break;
		case SIDL:
		case SRUN:
		case SSLEEP:
			/* runnable(2) */
			ber = ber_add_integer(ber, 2);
			break;
		case SSTOP:
			/* notRunnable(3) */
			ber = ber_add_integer(ber, 3);
			break;
		case SZOMB:
		case SDEAD:
		default:
			/* invalid(4) */
			ber = ber_add_integer(ber, 4);
			break;
		}
		break;
	default:
		return (-1);
	}

	return (0);
}

int
kinfo_proc_comp(const void *a, const void *b)
{
	struct kinfo_proc * const *k1 = a;
	struct kinfo_proc * const *k2 = b;

	return (((*k1)->p_pid > (*k2)->p_pid) ? 1 : -1);
}

int
kinfo_proc(u_int32_t idx, struct kinfo_proc **kinfo)
{
	static struct kinfo_proc *kp = NULL;
	static size_t		 nkp = 0;
	int			 mib[] = { CTL_KERN, KERN_PROC,
				    KERN_PROC_ALL, 0, sizeof(*kp), 0 };
	struct kinfo_proc	**klist;
	size_t			 size, count, i;

	for (;;) {
		size = nkp * sizeof(*kp);
		mib[5] = nkp;
		if (sysctl(mib, sizeofa(mib), kp, &size, NULL, 0) == -1) {
			if (errno == ENOMEM) {
				free(kp);
				kp = NULL;
				nkp = 0;
				continue;
			}

			return (-1);
		}

		count = size / sizeof(*kp);
		if (count <= nkp)
			break;

		kp = malloc(size);
		if (kp == NULL) {
			nkp = 0;
			return (-1);
		}
		nkp = count;
	}

	klist = calloc(count, sizeof(*klist));
	if (klist == NULL)
		return (-1);

	for (i = 0; i < count; i++)
		klist[i] = &kp[i];
	qsort(klist, count, sizeof(*klist), kinfo_proc_comp);

	*kinfo = NULL;
	for (i = 0; i < count; i++) {
		if (klist[i]->p_pid >= (int32_t)idx) {
			*kinfo = klist[i];
			break;
		}
	}
	free(klist);

	return (0);
}

int
kinfo_args(struct kinfo_proc *kinfo, char **s)
{
	static char		 str[128];
	static char		*buf = NULL;
	static size_t		 buflen = 128;

	int			 mib[] = { CTL_KERN, KERN_PROC_ARGS,
				    kinfo->p_pid, KERN_PROC_ARGV };
	char			*nbuf, **argv;

	if (buf == NULL) {
		buf = malloc(buflen);
		if (buf == NULL)
			return (-1);
	}

	str[0] = '\0';
	*s = str;

	while (sysctl(mib, sizeofa(mib), buf, &buflen, NULL, 0) == -1) {
		if (errno != ENOMEM) {
			/* some errors are expected, dont get too upset */
			return (0);
		}

		nbuf = realloc(buf, buflen + 128);
		if (nbuf == NULL)
			return (-1);

		buf = nbuf;
		buflen += 128;
	}

	argv = (char **)buf;
	if (argv[0] == NULL)
		return (0);

	argv++;
	while (*argv != NULL) {
		strlcat(str, *argv, sizeof(str));
		argv++;
		if (*argv != NULL)
			strlcat(str, " ", sizeof(str));
	}

	return (0);
}

/*
 * Defined in IF-MIB.txt (RFCs 1229, 1573, 2233, 2863)
 */

int	 mib_ifnumber(struct oid *, struct ber_oid *, struct ber_element **);
struct kif
	*mib_ifget(u_int);
int	 mib_iftable(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_ifxtable(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_ifstacklast(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_ifrcvtable(struct oid *, struct ber_oid *, struct ber_element **);

static u_int8_t ether_zeroaddr[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static struct oid if_mib[] = {
	{ MIB(ifMIB),			OID_MIB },
	{ MIB(ifName),			OID_TRD, mib_ifxtable },
	{ MIB(ifInMulticastPkts),	OID_TRD, mib_ifxtable },
	{ MIB(ifInBroadcastPkts),	OID_TRD, mib_ifxtable },
	{ MIB(ifOutMulticastPkts),	OID_TRD, mib_ifxtable },
	{ MIB(ifOutBroadcastPkts),	OID_TRD, mib_ifxtable },
	{ MIB(ifHCInOctets),		OID_TRD, mib_ifxtable },
	{ MIB(ifHCInUcastPkts),		OID_TRD, mib_ifxtable },
	{ MIB(ifHCInMulticastPkts),	OID_TRD, mib_ifxtable },
	{ MIB(ifHCInBroadcastPkts),	OID_TRD, mib_ifxtable },
	{ MIB(ifHCOutOctets),		OID_TRD, mib_ifxtable },
	{ MIB(ifHCOutUcastPkts),	OID_TRD, mib_ifxtable },
	{ MIB(ifHCOutMulticastPkts),	OID_TRD, mib_ifxtable },
	{ MIB(ifHCOutBroadcastPkts),	OID_TRD, mib_ifxtable },
	{ MIB(ifLinkUpDownTrapEnable),	OID_TRD, mib_ifxtable },
	{ MIB(ifHighSpeed),		OID_TRD, mib_ifxtable },
	{ MIB(ifPromiscuousMode),	OID_TRD, mib_ifxtable },
	{ MIB(ifConnectorPresent),	OID_TRD, mib_ifxtable },
	{ MIB(ifAlias),			OID_TRD, mib_ifxtable },
	{ MIB(ifCounterDiscontinuityTime), OID_TRD, mib_ifxtable },
	{ MIB(ifRcvAddressStatus),	OID_TRD, mib_ifrcvtable },
	{ MIB(ifRcvAddressType),	OID_TRD, mib_ifrcvtable },
	{ MIB(ifStackLastChange),	OID_RD, mib_ifstacklast },
	{ MIB(ifNumber),		OID_RD, mib_ifnumber },
	{ MIB(ifIndex),			OID_TRD, mib_iftable },
	{ MIB(ifDescr),			OID_TRD, mib_iftable },
	{ MIB(ifType),			OID_TRD, mib_iftable },
	{ MIB(ifMtu),			OID_TRD, mib_iftable },
	{ MIB(ifSpeed),			OID_TRD, mib_iftable },
	{ MIB(ifPhysAddress),		OID_TRD, mib_iftable },
	{ MIB(ifAdminStatus),		OID_TRD, mib_iftable },
	{ MIB(ifOperStatus),		OID_TRD, mib_iftable },
	{ MIB(ifLastChange),		OID_TRD, mib_iftable },
	{ MIB(ifInOctets),		OID_TRD, mib_iftable },
	{ MIB(ifInUcastPkts),		OID_TRD, mib_iftable },
	{ MIB(ifInNUcastPkts),		OID_TRD, mib_iftable },
	{ MIB(ifInDiscards),		OID_TRD, mib_iftable },
	{ MIB(ifInErrors),		OID_TRD, mib_iftable },
	{ MIB(ifInUnknownProtos),	OID_TRD, mib_iftable },
	{ MIB(ifOutOctets),		OID_TRD, mib_iftable },
	{ MIB(ifOutUcastPkts),		OID_TRD, mib_iftable },
	{ MIB(ifOutNUcastPkts),		OID_TRD, mib_iftable },
	{ MIB(ifOutDiscards),		OID_TRD, mib_iftable },
	{ MIB(ifOutErrors),		OID_TRD, mib_iftable },
	{ MIB(ifOutQLen),		OID_TRD, mib_iftable },
	{ MIB(ifSpecific),		OID_TRD, mib_iftable },
	{ MIBEND }
};

int
mib_ifnumber(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	*elm = ber_add_integer(*elm, kr_ifnumber());
	return (0);
}

struct kif *
mib_ifget(u_int idx)
{
	struct kif	*kif;

	if ((kif = kr_getif(idx)) == NULL) {
		/*
		 * It may happen that an interface with a specific index
		 * does not exist or has been removed. Jump to the next
		 * available interface index.
		 */
		for (kif = kr_getif(0); kif != NULL;
		    kif = kr_getnextif(kif->if_index))
			if (kif->if_index > idx)
				break;
		if (kif == NULL)
			return (NULL);
	}
	idx = kif->if_index;

	/* Update interface information */
	kr_updateif(idx);
	if ((kif = kr_getif(idx)) == NULL) {
		log_debug("mib_ifxtable: interface %d disappeared?", idx);
		return (NULL);
	}

	return (kif);
}

int
mib_iftable(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_element	*ber = *elm;
	u_int32_t		 idx = 0;
	struct kif		*kif;
	long long		 i;
	size_t			 len;
	int			 ifq;
	int			 mib[] = { CTL_NET, AF_INET, IPPROTO_IP, 0, 0 };

	/* Get and verify the current row index */
	idx = o->bo_id[OIDIDX_ifEntry];
	if ((kif = mib_ifget(idx)) == NULL)
		return (1);

	/* Tables need to prepend the OID on their own */
	o->bo_id[OIDIDX_ifEntry] = kif->if_index;
	ber = ber_add_oid(ber, o);

	switch (o->bo_id[OIDIDX_if]) {
	case 1:
		ber = ber_add_integer(ber, kif->if_index);
		break;
	case 2:
		/*
		 * The ifDescr should contain a vendor, product, etc.
		 * but we just use the interface name (like ifName).
		 * The interface name includes the driver name on OpenBSD.
		 */
		ber = ber_add_string(ber, kif->if_name);
		break;
	case 3:
		if (kif->if_type >= 0xf0) {
			/*
			 * It does not make sense to announce the private
			 * interface types for CARP, ENC, PFSYNC, etc.
			 */
			ber = ber_add_integer(ber, IFT_OTHER);
		} else
			ber = ber_add_integer(ber, kif->if_type);
		break;
	case 4:
		ber = ber_add_integer(ber, kif->if_mtu);
		break;
	case 5:
		ber = ber_add_integer(ber, kif->if_baudrate);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_GAUGE32);
		break;
	case 6:
		if (bcmp(kif->if_lladdr, ether_zeroaddr,
		    sizeof(kif->if_lladdr)) == 0) {
			ber = ber_add_string(ber, "");
		} else {
			ber = ber_add_nstring(ber, kif->if_lladdr,
			    sizeof(kif->if_lladdr));
		}
		break;
	case 7:
		/* ifAdminStatus up(1), down(2), testing(3) */
		i = (kif->if_flags & IFF_UP) ? 1 : 2;
		ber = ber_add_integer(ber, i);
		break;
	case 8:
		/* ifOperStatus */
		if ((kif->if_flags & IFF_UP) == 0)
			i = 2;	/* down(2) */
		else if (kif->if_link_state == LINK_STATE_UNKNOWN)
			i = 4;	/* unknown(4) */
		else if (LINK_STATE_IS_UP(kif->if_link_state))
			i = 1;	/* up(1) */
		else
			i = 7;	/* lowerLayerDown(7) or dormant(5)? */
		ber = ber_add_integer(ber, i);
		break;
	case 9:
		ber = ber_add_integer(ber, kif->if_ticks);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_TIMETICKS);
		break;
	case 10:
		ber = ber_add_integer(ber, (u_int32_t)kif->if_ibytes);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 11:
		ber = ber_add_integer(ber, (u_int32_t)kif->if_ipackets);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 12:
		ber = ber_add_integer(ber, (u_int32_t)kif->if_imcasts);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 13:
		mib[3] = IPCTL_IFQUEUE;
		mib[4] = IFQCTL_DROPS;
		len = sizeof(ifq);
		if (sysctl(mib, sizeofa(mib), &ifq, &len, 0, 0) == -1) {
			log_info("mib_iftable: %s: invalid ifq: %s",
			    kif->if_name, strerror(errno));
			return (-1);
		}
		ber = ber_add_integer(ber, ifq);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 14:
		ber = ber_add_integer(ber, (u_int32_t)kif->if_ierrors);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 15:
		ber = ber_add_integer(ber, (u_int32_t)kif->if_noproto);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 16:
		ber = ber_add_integer(ber, (u_int32_t)kif->if_obytes);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 17:
		ber = ber_add_integer(ber, (u_int32_t)kif->if_opackets);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 18:
		ber = ber_add_integer(ber, (u_int32_t)kif->if_omcasts);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 19:
		ber = ber_add_integer(ber, 0);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 20:
		ber = ber_add_integer(ber, (u_int32_t)kif->if_oerrors);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 21:
		mib[3] = IPCTL_IFQUEUE;
		mib[4] = IFQCTL_LEN;
		len = sizeof(ifq);
		if (sysctl(mib, sizeofa(mib), &ifq, &len, 0, 0) == -1) {
			log_info("mib_iftable: %s: invalid ifq: %s",
			    kif->if_name, strerror(errno));
			return (-1);
		}
		ber = ber_add_integer(ber, ifq);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_GAUGE32);
		break;
	case 22:
		ber = ber_add_oid(ber, &zerodotzero);
		break;
	default:
		return (-1);
	}

	return (0);
}

int
mib_ifxtable(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_element	*ber = *elm;
	u_int32_t		 idx = 0;
	struct kif		*kif;
	int			 i = 0;

	/* Get and verify the current row index */
	idx = o->bo_id[OIDIDX_ifXEntry];
	if ((kif = mib_ifget(idx)) == NULL)
		return (1);

	/* Tables need to prepend the OID on their own */
	o->bo_id[OIDIDX_ifXEntry] = kif->if_index;
	ber = ber_add_oid(ber, o);

	switch (o->bo_id[OIDIDX_ifX]) {
	case 1:
		ber = ber_add_string(ber, kif->if_name);
		break;
	case 2:
		ber = ber_add_integer(ber, (u_int32_t)kif->if_imcasts);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 3:
		ber = ber_add_integer(ber, 0);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 4:
		ber = ber_add_integer(ber, (u_int32_t)kif->if_omcasts);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 5:
		ber = ber_add_integer(ber, 0);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER32);
		break;
	case 6:
		ber = ber_add_integer(ber, (u_int64_t)kif->if_ibytes);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 7:
		ber = ber_add_integer(ber, (u_int64_t)kif->if_ipackets);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 8:
		ber = ber_add_integer(ber, (u_int64_t)kif->if_imcasts);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 9:
		ber = ber_add_integer(ber, 0);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 10:
		ber = ber_add_integer(ber, (u_int64_t)kif->if_obytes);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 11:
		ber = ber_add_integer(ber, (u_int64_t)kif->if_opackets);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 12:
		ber = ber_add_integer(ber, (u_int64_t)kif->if_omcasts);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 13:
		ber = ber_add_integer(ber, 0);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 14:
		ber = ber_add_integer(ber, 0);	/* enabled(1), disabled(2) */
		break;
	case 15:
		i = kif->if_baudrate >= 1000000 ?
		    kif->if_baudrate / 1000000 : 0;
		ber = ber_add_integer(ber, i);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_GAUGE32);
		break;
	case 16:
		/* ifPromiscuousMode: true(1), false(2) */
		i = kif->if_flags & IFF_PROMISC ? 1 : 2;
		ber = ber_add_integer(ber, i);
		break;
	case 17:
		/* ifConnectorPresent: false(2), true(1) */
		i = kif->if_type == IFT_ETHER ? 1 : 2;
		ber = ber_add_integer(ber, i);
		break;
	case 18:
		ber = ber_add_string(ber, kif->if_descr);
		break;
	case 19:
		ber = ber_add_integer(ber, 0);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_TIMETICKS);
		break;
	default:
		return (-1);
	}

	return (0);
}

int
mib_ifstacklast(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_element	*ber = *elm;
	ber = ber_add_integer(ber, kr_iflastchange());
	ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_TIMETICKS);
	return (0);
}

int
mib_ifrcvtable(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_element	*ber = *elm;
	u_int32_t		 idx = 0;
	struct kif		*kif;
	u_int			 i = 0;

	/* Get and verify the current row index */
	idx = o->bo_id[OIDIDX_ifRcvAddressEntry];
	if ((kif = mib_ifget(idx)) == NULL)
		return (1);

	/*
	 * The lladdr of the interface will be encoded in the returned OID
	 * ifRcvAddressX.ifindex.6.x.x.x.x.x.x = val
	 * Thanks to the virtual cloner interfaces, it is an easy 1:1
	 * mapping in OpenBSD; only one lladdr (MAC) address per interface.
	 */

	/* first set the base OID and caluculate the length */
	idx = 0;
	o->bo_id[OIDIDX_ifRcvAddressEntry + idx++] = kif->if_index;
	o->bo_id[OIDIDX_ifRcvAddressEntry + idx] = 0;
	smi_oidlen(o);

	/* extend the OID with the lladdr length and octets */
	o->bo_id[OIDIDX_ifRcvAddressEntry + idx++] = sizeof(kif->if_lladdr);
	o->bo_n++;
	for (i = 0; i < sizeof(kif->if_lladdr); i++, o->bo_n++)
		o->bo_id[OIDIDX_ifRcvAddressEntry + idx++] = kif->if_lladdr[i];

	/* write OID */
	ber = ber_add_oid(ber, o);

	switch (o->bo_id[OIDIDX_ifRcvAddress]) {
	case 2:
		/* ifRcvAddressStatus: RowStatus active(1), notInService(2) */
		i = kif->if_flags & IFF_UP ? 1 : 2;
		ber = ber_add_integer(ber, i);
		break;
	case 3:
		/* ifRcvAddressType: other(1), volatile(2), nonVolatile(3) */
		ber = ber_add_integer(ber, 1);
		break;
	default:
		return (-1);
	}

	return (0);
}

/*
 * Defined in 
 * - OPENBSD-PF-MIB.txt
 * - OPENBSD-SENSORS-MIB.txt
 * - OPENBSD-CARP-MIB.txt
 * (http://www.packetmischief.ca/openbsd-snmp-mibs/)
 */ 

struct carpif {
	struct carpreq	 carpr;
	struct kif	 kif;
};

int	 mib_pfinfo(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_pfcounters(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_pfscounters(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_pflogif(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_pfsrctrack(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_pflimits(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_pftimeouts(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_pfifnum(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_pfiftable(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_pftablenum(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_pftables(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_pftableaddrs(struct oid *, struct ber_oid *, struct ber_element **);
struct ber_oid *
	 mib_pftableaddrstable(struct oid *, struct ber_oid *, struct ber_oid *);
int	 mib_pflabelnum(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_pflabels(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_pfsyncstats(struct oid *, struct ber_oid *, struct ber_element **);

int	 mib_sensornum(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_sensors(struct oid *, struct ber_oid *, struct ber_element **);
const char *mib_sensorunit(struct sensor *);
char	*mib_sensorvalue(struct sensor *);

int	 mib_carpsysctl(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_carpstats(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_carpiftable(struct oid *, struct ber_oid *, struct ber_element **);
int	 mib_carpifnum(struct oid *, struct ber_oid *, struct ber_element **);
struct carpif
	*mib_carpifget(u_int);
int	 mib_memiftable(struct oid *, struct ber_oid *, struct ber_element **);

static struct oid openbsd_mib[] = {
	{ MIB(pfMIBObjects),		OID_MIB },
	{ MIB(pfRunning),		OID_RD, mib_pfinfo },
	{ MIB(pfRuntime),		OID_RD, mib_pfinfo },
	{ MIB(pfDebug),			OID_RD, mib_pfinfo },
	{ MIB(pfHostid),		OID_RD, mib_pfinfo },
	{ MIB(pfCntMatch),		OID_RD, mib_pfcounters },
	{ MIB(pfCntBadOffset),		OID_RD, mib_pfcounters },
	{ MIB(pfCntFragment),		OID_RD, mib_pfcounters },
	{ MIB(pfCntShort),		OID_RD, mib_pfcounters },
	{ MIB(pfCntNormalize),		OID_RD, mib_pfcounters },
	{ MIB(pfCntMemory),		OID_RD, mib_pfcounters },
	{ MIB(pfCntTimestamp),		OID_RD, mib_pfcounters },
	{ MIB(pfCntCongestion),		OID_RD, mib_pfcounters },
	{ MIB(pfCntIpOptions),		OID_RD, mib_pfcounters },
	{ MIB(pfCntProtoCksum),		OID_RD, mib_pfcounters },
	{ MIB(pfCntStateMismatch),	OID_RD, mib_pfcounters },
	{ MIB(pfCntStateInsert),	OID_RD, mib_pfcounters },
	{ MIB(pfCntStateLimit),		OID_RD, mib_pfcounters },
	{ MIB(pfCntSrcLimit),		OID_RD, mib_pfcounters },
	{ MIB(pfCntSynproxy),		OID_RD, mib_pfcounters },
	{ MIB(pfCntTranslate),		OID_RD, mib_pfcounters },
	{ MIB(pfStateCount),		OID_RD, mib_pfscounters },
	{ MIB(pfStateSearches),		OID_RD, mib_pfscounters },
	{ MIB(pfStateInserts),		OID_RD, mib_pfscounters },
	{ MIB(pfStateRemovals),		OID_RD, mib_pfscounters },
	{ MIB(pfLogIfName),		OID_RD, mib_pflogif },
	{ MIB(pfLogIfIpBytesIn),	OID_RD, mib_pflogif },
	{ MIB(pfLogIfIpBytesOut),	OID_RD, mib_pflogif },
	{ MIB(pfLogIfIpPktsInPass),	OID_RD, mib_pflogif },
	{ MIB(pfLogIfIpPktsInDrop),	OID_RD, mib_pflogif },
	{ MIB(pfLogIfIpPktsOutPass),	OID_RD, mib_pflogif },
	{ MIB(pfLogIfIpPktsOutDrop),	OID_RD, mib_pflogif },
	{ MIB(pfLogIfIp6BytesIn),	OID_RD, mib_pflogif },
	{ MIB(pfLogIfIp6BytesOut),	OID_RD, mib_pflogif },
	{ MIB(pfLogIfIp6PktsInPass),	OID_RD, mib_pflogif },
	{ MIB(pfLogIfIp6PktsInDrop),	OID_RD, mib_pflogif },
	{ MIB(pfLogIfIp6PktsOutPass),	OID_RD, mib_pflogif },
	{ MIB(pfLogIfIp6PktsOutDrop),	OID_RD, mib_pflogif },
	{ MIB(pfSrcTrackCount),		OID_RD, mib_pfsrctrack },
	{ MIB(pfSrcTrackSearches),	OID_RD, mib_pfsrctrack },
	{ MIB(pfSrcTrackInserts),	OID_RD, mib_pfsrctrack },
	{ MIB(pfSrcTrackRemovals),	OID_RD, mib_pfsrctrack },
	{ MIB(pfLimitStates),		OID_RD, mib_pflimits },
	{ MIB(pfLimitSourceNodes),	OID_RD, mib_pflimits },
	{ MIB(pfLimitFragments),	OID_RD, mib_pflimits },
	{ MIB(pfLimitMaxTables),	OID_RD, mib_pflimits },
	{ MIB(pfLimitMaxTableEntries),	OID_RD, mib_pflimits },
	{ MIB(pfTimeoutTcpFirst),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutTcpOpening),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutTcpEstablished),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutTcpClosing),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutTcpFinWait),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutTcpClosed),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutUdpFirst),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutUdpSingle),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutUdpMultiple),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutIcmpFirst),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutIcmpError),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutOtherFirst),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutOtherSingle),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutOtherMultiple),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutFragment),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutInterval),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutAdaptiveStart),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutAdaptiveEnd),	OID_RD, mib_pftimeouts },
	{ MIB(pfTimeoutSrcTrack),	OID_RD, mib_pftimeouts },
	{ MIB(pfIfNumber),		OID_RD, mib_pfifnum },
	{ MIB(pfIfIndex),		OID_TRD, mib_pfiftable },
	{ MIB(pfIfDescr),		OID_TRD, mib_pfiftable },
	{ MIB(pfIfType),		OID_TRD, mib_pfiftable },
	{ MIB(pfIfRefs),		OID_TRD, mib_pfiftable },
	{ MIB(pfIfRules),		OID_TRD, mib_pfiftable },
	{ MIB(pfIfIn4PassPkts),		OID_TRD, mib_pfiftable },
	{ MIB(pfIfIn4PassBytes),	OID_TRD, mib_pfiftable },
	{ MIB(pfIfIn4BlockPkts),	OID_TRD, mib_pfiftable },
	{ MIB(pfIfIn4BlockBytes),	OID_TRD, mib_pfiftable },
	{ MIB(pfIfOut4PassPkts),	OID_TRD, mib_pfiftable },
	{ MIB(pfIfOut4PassBytes),	OID_TRD, mib_pfiftable },
	{ MIB(pfIfOut4BlockPkts),	OID_TRD, mib_pfiftable },
	{ MIB(pfIfOut4BlockBytes),	OID_TRD, mib_pfiftable },
	{ MIB(pfIfIn6PassPkts),		OID_TRD, mib_pfiftable },
	{ MIB(pfIfIn6PassBytes),	OID_TRD, mib_pfiftable },
	{ MIB(pfIfIn6BlockPkts),	OID_TRD, mib_pfiftable },
	{ MIB(pfIfIn6BlockBytes),	OID_TRD, mib_pfiftable },
	{ MIB(pfIfOut6PassPkts),	OID_TRD, mib_pfiftable },
	{ MIB(pfIfOut6PassBytes),	OID_TRD, mib_pfiftable },
	{ MIB(pfIfOut6BlockPkts),	OID_TRD, mib_pfiftable },
	{ MIB(pfIfOut6BlockBytes),	OID_TRD, mib_pfiftable },
	{ MIB(pfTblNumber),		OID_RD, mib_pftablenum },
	{ MIB(pfTblIndex),		OID_TRD, mib_pftables },
	{ MIB(pfTblName),		OID_TRD, mib_pftables },
	{ MIB(pfTblAddresses),		OID_TRD, mib_pftables },
	{ MIB(pfTblAnchorRefs),		OID_TRD, mib_pftables },
	{ MIB(pfTblRuleRefs),		OID_TRD, mib_pftables },
	{ MIB(pfTblEvalsMatch),		OID_TRD, mib_pftables },
	{ MIB(pfTblEvalsNoMatch),	OID_TRD, mib_pftables },
	{ MIB(pfTblInPassPkts),		OID_TRD, mib_pftables },
	{ MIB(pfTblInPassBytes),	OID_TRD, mib_pftables },
	{ MIB(pfTblInBlockPkts),	OID_TRD, mib_pftables },
	{ MIB(pfTblInBlockBytes),	OID_TRD, mib_pftables },
	{ MIB(pfTblInXPassPkts),	OID_TRD, mib_pftables },
	{ MIB(pfTblInXPassBytes),	OID_TRD, mib_pftables },
	{ MIB(pfTblOutPassPkts),	OID_TRD, mib_pftables },
	{ MIB(pfTblOutPassBytes),	OID_TRD, mib_pftables },
	{ MIB(pfTblOutBlockPkts),	OID_TRD, mib_pftables },
	{ MIB(pfTblOutBlockBytes),	OID_TRD, mib_pftables },
	{ MIB(pfTblOutXPassPkts),	OID_TRD, mib_pftables },
	{ MIB(pfTblOutXPassBytes),	OID_TRD, mib_pftables },
	{ MIB(pfTblStatsCleared),	OID_TRD, mib_pftables },
	{ MIB(pfTblAddrTblIndex),	OID_TRD, mib_pftableaddrs,
	    NULL, mib_pftableaddrstable },
	{ MIB(pfTblAddrNet),		OID_TRD, mib_pftableaddrs,
	    NULL, mib_pftableaddrstable },
	{ MIB(pfTblAddrMask),		OID_TRD, mib_pftableaddrs,
	    NULL, mib_pftableaddrstable },
	{ MIB(pfTblAddrCleared),	OID_TRD, mib_pftableaddrs,
	    NULL, mib_pftableaddrstable },
	{ MIB(pfTblAddrInBlockPkts),	OID_TRD, mib_pftableaddrs,
	    NULL, mib_pftableaddrstable },
	{ MIB(pfTblAddrInBlockBytes),	OID_TRD, mib_pftableaddrs,
	    NULL, mib_pftableaddrstable },
	{ MIB(pfTblAddrInPassPkts),	OID_TRD, mib_pftableaddrs,
	    NULL, mib_pftableaddrstable },
	{ MIB(pfTblAddrInPassBytes),	OID_TRD, mib_pftableaddrs,
	    NULL, mib_pftableaddrstable },
	{ MIB(pfTblAddrOutBlockPkts),	OID_TRD, mib_pftableaddrs,
	    NULL, mib_pftableaddrstable },
	{ MIB(pfTblAddrOutBlockBytes),	OID_TRD, mib_pftableaddrs,
	    NULL, mib_pftableaddrstable },
	{ MIB(pfTblAddrOutPassPkts),	OID_TRD, mib_pftableaddrs,
	    NULL, mib_pftableaddrstable },
	{ MIB(pfTblAddrOutPassBytes),	OID_TRD, mib_pftableaddrs,
	    NULL, mib_pftableaddrstable },
	{ MIB(pfLabelNumber),		OID_RD, mib_pflabelnum },
	{ MIB(pfLabelIndex),		OID_TRD, mib_pflabels },
	{ MIB(pfLabelName),		OID_TRD, mib_pflabels },
	{ MIB(pfLabelEvals),		OID_TRD, mib_pflabels },
	{ MIB(pfLabelPkts),		OID_TRD, mib_pflabels },
	{ MIB(pfLabelBytes),		OID_TRD, mib_pflabels },
	{ MIB(pfLabelInPkts),		OID_TRD, mib_pflabels },
	{ MIB(pfLabelInBytes),		OID_TRD, mib_pflabels },
	{ MIB(pfLabelOutPkts),		OID_TRD, mib_pflabels },
	{ MIB(pfLabelOutBytes),		OID_TRD, mib_pflabels },
	{ MIB(pfLabelTotalStates),	OID_TRD, mib_pflabels },
	{ MIB(pfsyncIpPktsRecv),	OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncIp6PktsRecv),	OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncPktDiscardsForBadInterface), OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncPktDiscardsForBadTtl), OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncPktShorterThanHeader), OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncPktDiscardsForBadVersion), OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncPktDiscardsForBadAction), OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncPktDiscardsForBadLength), OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncPktDiscardsForBadAuth), OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncPktDiscardsForStaleState), OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncPktDiscardsForBadValues), OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncPktDiscardsForBadState), OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncIpPktsSent),	OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncIp6PktsSent),	OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncNoMemory),		OID_RD, mib_pfsyncstats },
	{ MIB(pfsyncOutputErrors),	OID_RD, mib_pfsyncstats },
	{ MIB(sensorsMIBObjects),	OID_MIB },
	{ MIB(sensorNumber),		OID_RD,	mib_sensornum },
	{ MIB(sensorIndex),		OID_TRD, mib_sensors },
	{ MIB(sensorDescr),		OID_TRD, mib_sensors },
	{ MIB(sensorType),		OID_TRD, mib_sensors },
	{ MIB(sensorDevice),		OID_TRD, mib_sensors },
	{ MIB(sensorValue),		OID_TRD, mib_sensors },
	{ MIB(sensorUnits),		OID_TRD, mib_sensors },
	{ MIB(sensorStatus),		OID_TRD, mib_sensors },
	{ MIB(carpMIBObjects),		OID_MIB },
	{ MIB(carpAllow),		OID_RD, mib_carpsysctl },
	{ MIB(carpPreempt),		OID_RD, mib_carpsysctl },
	{ MIB(carpLog),			OID_RD, mib_carpsysctl },
	{ MIB(carpIpPktsRecv),		OID_RD, mib_carpstats },
	{ MIB(carpIp6PktsRecv),		OID_RD, mib_carpstats },
	{ MIB(carpPktDiscardsBadIface),	OID_RD, mib_carpstats },
	{ MIB(carpPktDiscardsBadTtl),	OID_RD, mib_carpstats },
	{ MIB(carpPktShorterThanHdr),	OID_RD, mib_carpstats },
	{ MIB(carpDiscardsBadCksum),	OID_RD, mib_carpstats },
	{ MIB(carpDiscardsBadVersion),	OID_RD, mib_carpstats },
	{ MIB(carpDiscardsTooShort),	OID_RD, mib_carpstats },
	{ MIB(carpDiscardsBadAuth),	OID_RD, mib_carpstats },
	{ MIB(carpDiscardsBadVhid),	OID_RD, mib_carpstats },
	{ MIB(carpDiscardsBadAddrList),	OID_RD, mib_carpstats },
	{ MIB(carpIpPktsSent),		OID_RD, mib_carpstats },
	{ MIB(carpIp6PktsSent),		OID_RD, mib_carpstats },
	{ MIB(carpNoMemory),		OID_RD, mib_carpstats },
	{ MIB(carpTransitionsToMaster),	OID_RD, mib_carpstats },
	{ MIB(carpIfNumber),		OID_RD, mib_carpifnum },
	{ MIB(carpIfIndex),		OID_TRD, mib_carpiftable },
	{ MIB(carpIfDescr),		OID_TRD, mib_carpiftable },
	{ MIB(carpIfVhid),		OID_TRD, mib_carpiftable },
	{ MIB(carpIfDev	),		OID_TRD, mib_carpiftable },
	{ MIB(carpIfAdvbase),		OID_TRD, mib_carpiftable },
	{ MIB(carpIfAdvskew),		OID_TRD, mib_carpiftable },
	{ MIB(carpIfState),		OID_TRD, mib_carpiftable },
	{ MIB(memMIBObjects),		OID_MIB },
	{ MIB(memMIBVersion),		OID_RD, mps_getint, NULL, NULL,
	    OIDVER_OPENBSD_MEM },
	{ MIB(memIfName),		OID_TRD, mib_memiftable },
	{ MIB(memIfLiveLocks),		OID_TRD, mib_memiftable },
	{ MIBEND }
};

int
mib_pfinfo(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct pf_status	 s;
	time_t			 runtime;
	char			 str[11];

	if (pf_get_stats(&s))
		return (-1);

	switch (oid->o_oid[OIDIDX_pfstatus]) {
	case 1:
		*elm = ber_add_integer(*elm, s.running);
		break;
	case 2:
		if (s.since > 0)
			runtime = time(NULL) - s.since;
		else
			runtime = 0;
		runtime *= 100;
		*elm = ber_add_integer(*elm, runtime);
		ber_set_header(*elm, BER_CLASS_APPLICATION, SNMP_T_TIMETICKS);
		break;
	case 3:
		*elm = ber_add_integer(*elm, s.debug);
		break;
	case 4:
		snprintf(str, sizeof(str), "0x%08x", ntohl(s.hostid));
		*elm = ber_add_string(*elm, str);
		break;
	default:
		return (-1);
	}

	return (0);
}

int
mib_pfcounters(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct pf_status	 s;
	int			 i;
	struct statsmap {
		u_int8_t	 m_id;
		u_int64_t	*m_ptr;
	}			 mapping[] = {
		{ 1, &s.counters[PFRES_MATCH] },
		{ 2, &s.counters[PFRES_BADOFF] },
		{ 3, &s.counters[PFRES_FRAG] },
		{ 4, &s.counters[PFRES_SHORT] },
		{ 5, &s.counters[PFRES_NORM] },
		{ 6, &s.counters[PFRES_MEMORY] },
		{ 7, &s.counters[PFRES_TS] },
		{ 8, &s.counters[PFRES_CONGEST] },
		{ 9, &s.counters[PFRES_IPOPTIONS] },
		{ 10, &s.counters[PFRES_PROTCKSUM] },
		{ 11, &s.counters[PFRES_BADSTATE] },
		{ 12, &s.counters[PFRES_STATEINS] },
		{ 13, &s.counters[PFRES_MAXSTATES] },
		{ 14, &s.counters[PFRES_SRCLIMIT] },
		{ 15, &s.counters[PFRES_SYNPROXY] },
		{ 16, &s.counters[PFRES_TRANSLATE] }
	};

	if (pf_get_stats(&s))
		return (-1);

	for (i = 0;
	    (u_int)i < (sizeof(mapping) / sizeof(mapping[0])); i++) {
		if (oid->o_oid[OIDIDX_pfstatus] == mapping[i].m_id) {
			*elm = ber_add_integer(*elm, *mapping[i].m_ptr);
			ber_set_header(*elm, BER_CLASS_APPLICATION,
			    SNMP_T_COUNTER64);
			return (0);
		}
	}
	return (-1);
}

int
mib_pfscounters(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct pf_status	 s;
	int			 i;
	struct statsmap {
		u_int8_t	 m_id;
		u_int64_t	*m_ptr;
	}			 mapping[] = {
		{ 2, &s.fcounters[FCNT_STATE_SEARCH] },
		{ 3, &s.fcounters[FCNT_STATE_INSERT] },
		{ 4, &s.fcounters[FCNT_STATE_REMOVALS] },
	};

	if (pf_get_stats(&s))
		return (-1);

	switch (oid->o_oid[OIDIDX_pfstatus]) {
	case 1:
		*elm = ber_add_integer(*elm, s.states);
		ber_set_header(*elm, BER_CLASS_APPLICATION, SNMP_T_UNSIGNED32);
		break;
	default:
		for (i = 0;
		    (u_int)i < (sizeof(mapping) / sizeof(mapping[0])); i++) {
			if (oid->o_oid[OIDIDX_pfstatus] == mapping[i].m_id) {
				*elm = ber_add_integer(*elm, *mapping[i].m_ptr);
				ber_set_header(*elm, BER_CLASS_APPLICATION,
				    SNMP_T_COUNTER64);
				return (0);
			}
		}
		return (-1);
	}

	return (0);
}

int
mib_pflogif(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct pf_status	 s;
	int			 i;
	struct statsmap {
		u_int8_t	 m_id;
		u_int64_t	*m_ptr;
	}			 mapping[] = {
		{ 2, &s.bcounters[IPV4][IN] },
		{ 3, &s.bcounters[IPV4][OUT] },
		{ 4, &s.pcounters[IPV4][IN][PF_PASS] },
		{ 5, &s.pcounters[IPV4][IN][PF_DROP] },
		{ 6, &s.pcounters[IPV4][OUT][PF_PASS] },
		{ 7, &s.pcounters[IPV4][OUT][PF_DROP] },
		{ 8, &s.bcounters[IPV6][IN] },
		{ 9, &s.bcounters[IPV6][OUT] },
		{ 10, &s.pcounters[IPV6][IN][PF_PASS] },
		{ 11, &s.pcounters[IPV6][IN][PF_DROP] },
		{ 12, &s.pcounters[IPV6][OUT][PF_PASS] },
		{ 13, &s.pcounters[IPV6][OUT][PF_DROP] }
	};

	if (pf_get_stats(&s))
		return (-1);

	switch (oid->o_oid[OIDIDX_pfstatus]) {
	case 1:
		*elm = ber_add_string(*elm, s.ifname);
		break;
	default:
		for (i = 0;
		    (u_int)i < (sizeof(mapping) / sizeof(mapping[0])); i++) {
			if (oid->o_oid[OIDIDX_pfstatus] == mapping[i].m_id) {
				*elm = ber_add_integer(*elm, *mapping[i].m_ptr);
				ber_set_header(*elm, BER_CLASS_APPLICATION,
				    SNMP_T_COUNTER64);
				return (0);
			}
		}
		return (-1);
	}

	return (0);
}

int
mib_pfsrctrack(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct pf_status	 s;
	int			 i;
	struct statsmap {
		u_int8_t	 m_id;
		u_int64_t	*m_ptr;
	}			 mapping[] = {
		{ 2, &s.scounters[SCNT_SRC_NODE_SEARCH] },
		{ 3, &s.scounters[SCNT_SRC_NODE_INSERT] },
		{ 4, &s.scounters[SCNT_SRC_NODE_REMOVALS] }
	};

	if (pf_get_stats(&s))
		return (-1);

	switch (oid->o_oid[OIDIDX_pfstatus]) {
	case 1:
		*elm = ber_add_integer(*elm, s.src_nodes);
		ber_set_header(*elm, BER_CLASS_APPLICATION, SNMP_T_UNSIGNED32);
		break;
	default:
		for (i = 0;
		    (u_int)i < (sizeof(mapping) / sizeof(mapping[0])); i++) {
			if (oid->o_oid[OIDIDX_pfstatus] == mapping[i].m_id) {
				*elm = ber_add_integer(*elm, *mapping[i].m_ptr);
				ber_set_header(*elm, BER_CLASS_APPLICATION,
				    SNMP_T_COUNTER64);
				return (0);
			}
		}
		return (-1);
	}

	return (0);
}

int
mib_pflimits(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct pfioc_limit	 pl;
	int			 i;
	extern int		 devpf;
	struct statsmap {
		u_int8_t	 m_id;
		u_int8_t	 m_limit;
	}			 mapping[] = {
		{ 1, PF_LIMIT_STATES },
		{ 2, PF_LIMIT_SRC_NODES },
		{ 3, PF_LIMIT_FRAGS },
		{ 4, PF_LIMIT_TABLES },
		{ 5, PF_LIMIT_TABLE_ENTRIES }
	};

	memset(&pl, 0, sizeof(pl));
	pl.index = PF_LIMIT_MAX;

	for (i = 0;
	    (u_int)i < (sizeof(mapping) / sizeof(mapping[0])); i++) {
		if (oid->o_oid[OIDIDX_pfstatus] == mapping[i].m_id) {
			pl.index = mapping[i].m_limit;
			break;
		}
	}

	if (pl.index == PF_LIMIT_MAX)
		return (-1);

	if (ioctl(devpf, DIOCGETLIMIT, &pl)) {
		log_warn("DIOCGETLIMIT");
		return (-1);
	}

	*elm = ber_add_integer(*elm, pl.limit);
	ber_set_header(*elm, BER_CLASS_APPLICATION, SNMP_T_UNSIGNED32);

	return (0);
}

int
mib_pftimeouts(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct pfioc_tm		 pt;
	int			 i;
	extern int		 devpf;
	struct statsmap {
		u_int8_t	 m_id;
		u_int8_t	 m_tm;
	}			 mapping[] = {
		{ 1, PFTM_TCP_FIRST_PACKET },
		{ 2, PFTM_TCP_OPENING },
		{ 3, PFTM_TCP_ESTABLISHED },
		{ 4, PFTM_TCP_CLOSING },
		{ 5, PFTM_TCP_FIN_WAIT },
		{ 6, PFTM_TCP_CLOSED },
		{ 7, PFTM_UDP_FIRST_PACKET },
		{ 8, PFTM_UDP_SINGLE },
		{ 9, PFTM_UDP_MULTIPLE },
		{ 10, PFTM_ICMP_FIRST_PACKET },
		{ 11, PFTM_ICMP_ERROR_REPLY },
		{ 12, PFTM_OTHER_FIRST_PACKET },
		{ 13, PFTM_OTHER_SINGLE },
		{ 14, PFTM_OTHER_MULTIPLE },
		{ 15, PFTM_FRAG },
		{ 16, PFTM_INTERVAL },
		{ 17, PFTM_ADAPTIVE_START },
		{ 18, PFTM_ADAPTIVE_END },
		{ 19, PFTM_SRC_NODE }
	};

	memset(&pt, 0, sizeof(pt));
	pt.timeout = PFTM_MAX;

	for (i = 0;
	    (u_int)i < (sizeof(mapping) / sizeof(mapping[0])); i++) {
		if (oid->o_oid[OIDIDX_pfstatus] == mapping[i].m_id) {
			pt.timeout = mapping[i].m_tm;
			break;
		}
	}

	if (pt.timeout == PFTM_MAX)
		return (-1);

	if (ioctl(devpf, DIOCGETTIMEOUT, &pt)) {
		log_warn("DIOCGETTIMEOUT");
		return (-1);
	}

	*elm = ber_add_integer(*elm, pt.seconds);

	return (0);
}

int
mib_pfifnum(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	int	 c;

	if ((c = pfi_count()) == -1)
		return (-1);

	*elm = ber_add_integer(*elm, c);

	return (0);
}

int
mib_pfiftable(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_element	*ber = *elm;
	struct pfi_kif		 pif;
	int			 idx, iftype;

	/* Get and verify the current row index */
	idx = o->bo_id[OIDIDX_pfIfEntry];

	if (pfi_get_if(&pif, idx))
		return (1);

	ber = ber_add_oid(ber, o);

	switch (o->bo_id[OIDIDX_pfInterface]) {
	case 1:
		ber = ber_add_integer(ber, idx);
		break;
	case 2:
		ber = ber_add_string(ber, pif.pfik_name);
		break;
	case 3:
		iftype = (pif.pfik_ifp == NULL ? PFI_IFTYPE_GROUP
		    : PFI_IFTYPE_INSTANCE);
		ber = ber_add_integer(ber, iftype);
		break;
	case 4:
		ber = ber_add_integer(ber, pif.pfik_states);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_UNSIGNED32);
		break;
	case 5:
		ber = ber_add_integer(ber, pif.pfik_rules);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_UNSIGNED32);
		break;
	case 6:
		ber = ber_add_integer(ber, pif.pfik_packets[IPV4][IN][PASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 7:
		ber = ber_add_integer(ber, pif.pfik_bytes[IPV4][IN][PASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 8:
		ber = ber_add_integer(ber, pif.pfik_packets[IPV4][IN][BLOCK]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 9:
		ber = ber_add_integer(ber, pif.pfik_bytes[IPV4][IN][BLOCK]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 10:
		ber = ber_add_integer(ber, pif.pfik_packets[IPV4][OUT][PASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 11:
		ber = ber_add_integer(ber, pif.pfik_bytes[IPV4][OUT][PASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 12:
		ber = ber_add_integer(ber, pif.pfik_packets[IPV4][OUT][BLOCK]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 13:
		ber = ber_add_integer(ber, pif.pfik_bytes[IPV4][OUT][BLOCK]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 14:
		ber = ber_add_integer(ber, pif.pfik_packets[IPV6][IN][PASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 15:
		ber = ber_add_integer(ber, pif.pfik_bytes[IPV6][IN][PASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 16:
		ber = ber_add_integer(ber, pif.pfik_packets[IPV6][IN][BLOCK]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 17:
		ber = ber_add_integer(ber, pif.pfik_bytes[IPV6][IN][BLOCK]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 18:
		ber = ber_add_integer(ber, pif.pfik_packets[IPV6][OUT][PASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 19:
		ber = ber_add_integer(ber, pif.pfik_bytes[IPV6][OUT][PASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 20:
		ber = ber_add_integer(ber, pif.pfik_packets[IPV6][OUT][BLOCK]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 21:
		ber = ber_add_integer(ber, pif.pfik_bytes[IPV6][OUT][BLOCK]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	default:
		return (1);
	}

	return (0);
}

int
mib_pftablenum(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	int	 c;

	if ((c = pft_count()) == -1)
		return (-1);

	*elm = ber_add_integer(*elm, c);

	return (0);
}

int
mib_pftables(struct oid *oid, struct ber_oid *o, struct ber_element **elm)
{
	struct ber_element	*ber = *elm;
	struct pfr_tstats	 ts;
	time_t			 tzero;
	int			 idx;

	/* Get and verify the current row index */
	idx = o->bo_id[OIDIDX_pfTableEntry];

	if (pft_get_table(&ts, idx))
		return (1);

	ber = ber_add_oid(ber, o);

	switch (o->bo_id[OIDIDX_pfTable]) {
	case 1:
		ber = ber_add_integer(ber, idx);
		break;
	case 2:
		ber = ber_add_string(ber, ts.pfrts_name);
		break;
	case 3:
		ber = ber_add_integer(ber, ts.pfrts_cnt);
		break;
	case 4:
		ber = ber_add_integer(ber, ts.pfrts_refcnt[PFR_REFCNT_ANCHOR]);
		break;
	case 5:
		ber = ber_add_integer(ber, ts.pfrts_refcnt[PFR_REFCNT_RULE]);
		break;
	case 6:
		ber = ber_add_integer(ber, ts.pfrts_match);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 7:
		ber = ber_add_integer(ber, ts.pfrts_nomatch);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 8:
		ber = ber_add_integer(ber, ts.pfrts_packets[IN][PFR_OP_PASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 9:
		ber = ber_add_integer(ber, ts.pfrts_bytes[IN][PFR_OP_PASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 10:
		ber = ber_add_integer(ber, ts.pfrts_packets[IN][PFR_OP_BLOCK]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 11:
		ber = ber_add_integer(ber, ts.pfrts_bytes[IN][PFR_OP_BLOCK]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 12:
		ber = ber_add_integer(ber, ts.pfrts_packets[IN][PFR_OP_XPASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 13:
		ber = ber_add_integer(ber, ts.pfrts_bytes[IN][PFR_OP_XPASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 14:
		ber = ber_add_integer(ber, ts.pfrts_packets[OUT][PFR_OP_PASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 15:
		ber = ber_add_integer(ber, ts.pfrts_bytes[OUT][PFR_OP_PASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 16:
		ber = ber_add_integer(ber, ts.pfrts_packets[OUT][PFR_OP_BLOCK]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 17:
		ber = ber_add_integer(ber, ts.pfrts_bytes[OUT][PFR_OP_BLOCK]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 18:
		ber = ber_add_integer(ber, ts.pfrts_packets[OUT][PFR_OP_XPASS]);
		ber_set_header(ber, BER_CLASS_APPLICATION, SNMP_T_COUNTER64);
		break;
	case 19:
		ber = ber_add_integer(ber, ts.pfrts_bytes[OUT][PFR_OP_XPASS]);
