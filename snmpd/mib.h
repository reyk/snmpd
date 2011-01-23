/*	$OpenBSD: mib.h,v 1.30 2013/03/11 19:49:37 sthen Exp $	*/

/*
 * Copyright (c) 2007, 2008 Reyk Floeter <reyk@openbsd.org>
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

#ifndef _SNMPD_MIB_H
#define _SNMPD_MIB_H

/*
 * Adding new MIBs:
 * - add the OID definitions below
 * - add the OIDs to the MIB_TREE table at the end of this file
 * - optional: write the implementation in mib.c
 */

/* From the SNMPv2-SMI MIB */
#define MIB_iso				1
#define MIB_org				MIB_iso, 3
#define MIB_dod				MIB_org, 6
#define MIB_internet			MIB_dod, 1
#define MIB_directory			MIB_internet, 1
#define MIB_mgmt			MIB_internet, 2
#define MIB_mib_2			MIB_mgmt, 1	/* XXX mib-2 */
#define MIB_system			MIB_mib_2, 1
#define OIDIDX_system			7
#define MIB_sysDescr			MIB_system, 1
#define MIB_sysOID			MIB_system, 2
#define MIB_sysUpTime			MIB_system, 3
#define MIB_sysContact			MIB_system, 4
#define MIB_sysName			MIB_system, 5
#define MIB_sysLocation			MIB_system, 6
#define MIB_sysServices			MIB_system, 7
#define MIB_sysORLastChange		MIB_system, 8
#define MIB_sysORTable			MIB_system, 9
#define MIB_sysOREntry			MIB_sysORTable, 1
#define OIDIDX_sysOR			9
#define OIDIDX_sysOREntry		10
#define MIB_sysORIndex			MIB_sysOREntry, 1
#define MIB_sysORID			MIB_sysOREntry, 2
#define MIB_sysORDescr			MIB_sysOREntry, 3
#define MIB_sysORUpTime			MIB_sysOREntry, 4
#define MIB_transmission		MIB_mib_2, 10
#define MIB_snmp			MIB_mib_2, 11
#define OIDIDX_snmp			7
#define MIB_snmpInPkts			MIB_snmp, 1
#define MIB_snmpOutPkts			MIB_snmp, 2
#define MIB_snmpInBadVersions		MIB_snmp, 3
#define MIB_snmpInBadCommunityNames	MIB_snmp, 4
#define MIB_snmpInBadCommunityUses	MIB_snmp, 5
#define MIB_snmpInASNParseErrs		MIB_snmp, 6
#define MIB_snmpInTooBigs		MIB_snmp, 8
#define MIB_snmpInNoSuchNames		MIB_snmp, 9
#define MIB_snmpInBadValues		MIB_snmp, 10
#define MIB_snmpInReadOnlys		MIB_snmp, 11
#define MIB_snmpInGenErrs		MIB_snmp, 12
#define MIB_snmpInTotalReqVars		MIB_snmp, 13
#define MIB_snmpInTotalSetVars		MIB_snmp, 14
#define MIB_snmpInGetRequests		MIB_snmp, 15
#define MIB_snmpInGetNexts		MIB_snmp, 16
#define MIB_snmpInSetRequests		MIB_snmp, 17
#define MIB_snmpInGetResponses		MIB_snmp, 18
#define MIB_snmpInTraps			MIB_snmp, 19
#define MIB_snmpOutTooBigs		MIB_snmp, 20
#define MIB_snmpOutNoSuchNames		MIB_snmp, 21
#define MIB_snmpOutBadValues		MIB_snmp, 22
#define MIB_snmpOutGenErrs		MIB_snmp, 24
#define MIB_snmpOutGetRequests		MIB_snmp, 25
#define MIB_snmpOutGetNexts		MIB_snmp, 26
#define MIB_snmpOutSetRequests		MIB_snmp, 27
#define MIB_snmpOutGetResponses		MIB_snmp, 28
#define MIB_snmpOutTraps		MIB_snmp, 29
#define MIB_snmpEnableAuthenTraps	MIB_snmp, 30
#define MIB_snmpSilentDrops		MIB_snmp, 31
#define MIB_snmpProxyDrops		MIB_snmp, 32
#define MIB_experimental		MIB_internet, 3
#define MIB_private			MIB_internet, 4
#define MIB_enterprises			MIB_private, 1
#define MIB_security			MIB_internet, 5
#define MIB_snmpV2			MIB_internet, 6
#define MIB_snmpDomains			MIB_snmpV2, 1
#define MIB_snmpProxies			MIB_snmpV2, 2
#define MIB_snmpModules			MIB_snmpV2, 3
#define MIB_snmpMIB			MIB_snmpModules, 1
#define MIB_snmpMIBObjects		MIB_snmpMIB, 1
#define MIB_snmpTrap			MIB_snmpMIBObjects, 4
#define MIB_snmpTrapOID			MIB_snmpTrap, 1
#define MIB_snmpTrapEnterprise		MIB_snmpTrap, 3
#define MIB_snmpTraps			MIB_snmpMIBObjects, 5
#define MIB_coldStart			MIB_snmpTraps, 1
#define MIB_warmStart			MIB_snmpTraps, 2
#define MIB_linkDown			MIB_snmpTraps, 3
#define MIB_linkUp			MIB_snmpTraps, 4
#define MIB_authenticationFailure	MIB_snmpTraps, 5
#define MIB_egpNeighborLoss		MIB_snmpTraps, 6

/* SNMP-USER-BASED-SM-MIB */
#define MIB_framework			MIB_snmpModules, 10
#define MIB_frameworkObjects		MIB_framework, 2
#define OIDIDX_snmpEngine		9
#define MIB_snmpEngine			MIB_frameworkObjects, 1
#define MIB_snmpEngineID		MIB_snmpEngine, 1
#define MIB_snmpEngineBoots		MIB_snmpEngine, 2
#define MIB_snmpEngineTime		MIB_snmpEngine, 3
#define MIB_snmpEngineMaxMsgSize	MIB_snmpEngine, 4
#define MIB_usm				MIB_snmpModules, 15
#define MIB_usmObjects			MIB_usm, 1
#define MIB_usmStats			MIB_usmObjects, 1
#define OIDIDX_usmStats			9
#define OIDVAL_usmErrSecLevel		1
#define OIDVAL_usmErrTimeWindow		2
#define OIDVAL_usmErrUserName		3
#define OIDVAL_usmErrEngineId		4
#define OIDVAL_usmErrDigest		5
#define OIDVAL_usmErrDecrypt		6
#define MIB_usmStatsUnsupportedSecLevels MIB_usmStats, OIDVAL_usmErrSecLevel
#define MIB_usmStatsNotInTimeWindow	MIB_usmStats, OIDVAL_usmErrTimeWindow
#define MIB_usmStatsUnknownUserNames	MIB_usmStats, OIDVAL_usmErrUserName
#define MIB_usmStatsUnknownEngineId	MIB_usmStats, OIDVAL_usmErrEngineId
#define MIB_usmStatsWrongDigests	MIB_usmStats, OIDVAL_usmErrDigest
#define MIB_usmStatsDecryptionErrors	MIB_usmStats, OIDVAL_usmErrDecrypt

/* HOST-RESOURCES-MIB */
#define MIB_host			MIB_mib_2, 25
#define MIB_hrSystem			MIB_host, 1
#define OIDIDX_hrsystem			8
#define MIB_hrSystemUptime		MIB_hrSystem, 1
#define MIB_hrSystemDate		MIB_hrSystem, 2
#define MIB_hrSystemInitialLoadDevice	MIB_hrSystem, 3
#define MIB_hrSystemInitialLoadParameters MIB_hrSystem, 4
#define MIB_hrSystemNumUsers		MIB_hrSystem, 5
#define MIB_hrSystemProcesses		MIB_hrSystem, 6
#define MIB_hrSystemMaxProcesses	MIB_hrSystem, 7
#define MIB_hrStorage			MIB_host, 2
#define MIB_hrStorageTypes		MIB_hrStorage, 1
#define MIB_hrStorageOther		MIB_hrStorageTypes, 1
#define MIB_hrStorageRam		MIB_hrStorageTypes, 2
#define MIB_hrStorageVirtualMemory	MIB_hrStorageTypes, 3
#define MIB_hrStorageFixedDisk		MIB_hrStorageTypes, 4
#define MIB_hrStorageRemovableDisk	MIB_hrStorageTypes, 5
#define MIB_hrStorageFloppyDisk		MIB_hrStorageTypes, 6
#define MIB_hrStorageCompactDisc	MIB_hrStorageTypes, 7
#define MIB_hrStorageRamDisk		MIB_hrStorageTypes, 8
#define MIB_hrStorageFlashMemory	MIB_hrStorageTypes, 9
#define MIB_hrStorageNetworkDisk	MIB_hrStorageTypes, 10
#define MIB_hrMemorySize		MIB_hrStorage, 2
#define MIB_hrStorageTable		MIB_hrStorage, 3
#define MIB_hrStorageEntry		MIB_hrStorageTable, 1
#define OIDIDX_hrStorage		10
#define OIDIDX_hrStorageEntry		11
#define MIB_hrStorageIndex		MIB_hrStorageEntry, 1
#define MIB_hrStorageType		MIB_hrStorageEntry, 2
#define MIB_hrStorageDescr		MIB_hrStorageEntry, 3
#define MIB_hrStorageAllocationUnits	MIB_hrStorageEntry, 4
#define MIB_hrStorageSize		MIB_hrStorageEntry, 5
#define MIB_hrStorageUsed		MIB_hrStorageEntry, 6
#define MIB_hrStorageAllocationFailures	MIB_hrStorageEntry, 7
#define MIB_hrDevice			MIB_host, 3
#define MIB_hrDeviceTypes		MIB_hrDevice, 1
#define MIB_hrDeviceOther		MIB_hrDeviceTypes, 1
#define MIB_hrDeviceUnknown		MIB_hrDeviceTypes, 2
#define MIB_hrDeviceProcessor		MIB_hrDeviceTypes, 3
#define MIB_hrDeviceNetwork		MIB_hrDeviceTypes, 4
#define MIB_hrDevicePrinter		MIB_hrDeviceTypes, 5
#define MIB_hrDeviceDiskStorage		MIB_hrDeviceTypes, 6
#define MIB_hrDeviceVideo		MIB_hrDeviceTypes, 10
#define MIB_hrDeviceAudio		MIB_hrDeviceTypes, 11
#define MIB_hrDeviceCoprocessor		MIB_hrDeviceTypes, 12
#define MIB_hrDeviceKeyboard		MIB_hrDeviceTypes, 13
#define MIB_hrDeviceModem		MIB_hrDeviceTypes, 14
#define MIB_hrDeviceParallelPort	MIB_hrDeviceTypes, 15
#define MIB_hrDevicePointing		MIB_hrDeviceTypes, 16
#define MIB_hrDeviceSerialPort		MIB_hrDeviceTypes, 17
#define MIB_hrDeviceTape		MIB_hrDeviceTypes, 18
#define MIB_hrDeviceClock		MIB_hrDeviceTypes, 19
#define MIB_hrDeviceVolatileMemory	MIB_hrDeviceTypes, 20
#define MIB_hrDeviceNonVolatileMemory	MIB_hrDeviceTypes, 21
#define MIB_hrDeviceTable		MIB_hrDevice, 2
#define MIB_hrDeviceEntry		MIB_hrDeviceTable, 1
#define OIDIDX_hrDevice			10
#define OIDIDX_hrDeviceEntry		11
#define MIB_hrDeviceIndex		MIB_hrDeviceEntry, 1
#define MIB_hrDeviceType		MIB_hrDeviceEntry, 2
#define MIB_hrDeviceDescr		MIB_hrDeviceEntry, 3
#define MIB_hrDeviceID			MIB_hrDeviceEntry, 4
#define MIB_hrDeviceStatus		MIB_hrDeviceEntry, 5
#define MIB_hrDeviceErrors		MIB_hrDeviceEntry, 6
#define MIB_hrProcessorTable		MIB_hrDevice, 3
#define MIB_hrProcessorEntry		MIB_hrProcessorTable, 1
#define OIDIDX_hrProcessor		10
#define OIDIDX_hrProcessorEntry		11
#define MIB_hrProcessorFrwID		MIB_hrProcessorEntry, 1
#define MIB_hrProcessorLoad		MIB_hrProcessorEntry, 2
#define MIB_hrSWRun			MIB_host, 4
#define MIB_hrSWOSIndex			MIB_hrSWRun, 1
#define MIB_hrSWRunTable		MIB_hrSWRun, 2
#define MIB_hrSWRunEntry		MIB_hrSWRunTable, 1
#define OIDIDX_hrSWRun			10
#define OIDIDX_hrSWRunEntry		11
#define MIB_hrSWRunIndex		MIB_hrSWRunEntry, 1
#define MIB_hrSWRunName			MIB_hrSWRunEntry, 2
