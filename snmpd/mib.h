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
#define MIB_hrSWRunID			MIB_hrSWRunEntry, 3
#define MIB_hrSWRunPath			MIB_hrSWRunEntry, 4
#define MIB_hrSWRunParameters		MIB_hrSWRunEntry, 5
#define MIB_hrSWRunType			MIB_hrSWRunEntry, 6
#define MIB_hrSWRunStatus		MIB_hrSWRunEntry, 7
#define MIB_hrSWRunPerf			MIB_host, 5
#define MIB_hrSWRunPerfTable		MIB_hrSWRunPerf, 1
#define OIDIDX_hrSWRunPerf		10
#define OIDIDX_hrSWRunPerfEntry		11
#define MIB_hrSWRunPerfEntry		MIB_hrSWRunPerfTable, 1
#define MIB_hrSWRunPerfCPU		MIB_hrSWRunPerfEntry, 1
#define MIB_hrSWRunPerfMem		MIB_hrSWRunPerfEntry, 2
#define MIB_hrSWInstalled		MIB_host, 6
#define MIB_hrMIBAdminInfo		MIB_host, 7

/* IF-MIB */
#define MIB_ifMIB			MIB_mib_2, 31
#define MIB_ifMIBObjects		MIB_ifMIB, 1
#define MIB_ifXTable			MIB_ifMIBObjects, 1
#define MIB_ifXEntry			MIB_ifXTable, 1
#define OIDIDX_ifX			10
#define OIDIDX_ifXEntry			11
#define MIB_ifName			MIB_ifXEntry, 1
#define MIB_ifInMulticastPkts		MIB_ifXEntry, 2
#define MIB_ifInBroadcastPkts		MIB_ifXEntry, 3
#define MIB_ifOutMulticastPkts		MIB_ifXEntry, 4
#define MIB_ifOutBroadcastPkts		MIB_ifXEntry, 5
#define MIB_ifHCInOctets		MIB_ifXEntry, 6
#define MIB_ifHCInUcastPkts		MIB_ifXEntry, 7
#define MIB_ifHCInMulticastPkts		MIB_ifXEntry, 8
#define MIB_ifHCInBroadcastPkts		MIB_ifXEntry, 9
#define MIB_ifHCOutOctets		MIB_ifXEntry, 10
#define MIB_ifHCOutUcastPkts		MIB_ifXEntry, 11
#define MIB_ifHCOutMulticastPkts	MIB_ifXEntry, 12
#define MIB_ifHCOutBroadcastPkts	MIB_ifXEntry, 13
#define MIB_ifLinkUpDownTrapEnable	MIB_ifXEntry, 14
#define MIB_ifHighSpeed			MIB_ifXEntry, 15
#define MIB_ifPromiscuousMode		MIB_ifXEntry, 16
#define MIB_ifConnectorPresent		MIB_ifXEntry, 17
#define MIB_ifAlias			MIB_ifXEntry, 18
#define MIB_ifCounterDiscontinuityTime	MIB_ifXEntry, 19
#define MIB_ifStackTable		MIB_ifMIBObjects, 2
#define MIB_ifStackEntry		MIB_ifStackTable, 1
#define OIDIDX_ifStack			10
#define OIDIDX_ifStackEntry		11
#define MIB_ifStackStatus		MIB_ifStackEntry, 3
#define MIB_ifRcvAddressTable		MIB_ifMIBObjects, 4
#define MIB_ifRcvAddressEntry		MIB_ifRcvAddressTable, 1
#define OIDIDX_ifRcvAddress		10
#define OIDIDX_ifRcvAddressEntry	11
#define MIB_ifRcvAddressStatus		MIB_ifRcvAddressEntry, 2
#define MIB_ifRcvAddressType		MIB_ifRcvAddressEntry, 3
#define MIB_ifStackLastChange		MIB_ifMIBObjects, 6
#define MIB_interfaces			MIB_mib_2, 2
#define MIB_ifNumber			MIB_interfaces, 1
#define MIB_ifTable			MIB_interfaces, 2
#define MIB_ifEntry			MIB_ifTable, 1
#define OIDIDX_if			9
#define OIDIDX_ifEntry			10
#define MIB_ifIndex			MIB_ifEntry, 1
#define MIB_ifDescr			MIB_ifEntry, 2
#define MIB_ifType			MIB_ifEntry, 3
#define MIB_ifMtu			MIB_ifEntry, 4
#define MIB_ifSpeed			MIB_ifEntry, 5
#define MIB_ifPhysAddress		MIB_ifEntry, 6
#define MIB_ifAdminStatus		MIB_ifEntry, 7
#define MIB_ifOperStatus		MIB_ifEntry, 8
#define MIB_ifLastChange		MIB_ifEntry, 9
#define MIB_ifInOctets			MIB_ifEntry, 10
#define MIB_ifInUcastPkts		MIB_ifEntry, 11
#define MIB_ifInNUcastPkts		MIB_ifEntry, 12
#define MIB_ifInDiscards		MIB_ifEntry, 13
#define MIB_ifInErrors			MIB_ifEntry, 14
#define MIB_ifInUnknownProtos		MIB_ifEntry, 15
#define MIB_ifOutOctets			MIB_ifEntry, 16
#define MIB_ifOutUcastPkts		MIB_ifEntry, 17
#define MIB_ifOutNUcastPkts		MIB_ifEntry, 18
#define MIB_ifOutDiscards		MIB_ifEntry, 19
#define MIB_ifOutErrors			MIB_ifEntry, 20
#define MIB_ifOutQLen			MIB_ifEntry, 21
#define MIB_ifSpecific			MIB_ifEntry, 22

/* IP-MIB */
#define MIB_ipMIB			MIB_mib_2, 4
#define OIDIDX_ip			7
#define MIB_ipForwarding		MIB_ipMIB, 1
#define MIB_ipDefaultTTL		MIB_ipMIB, 2
#define MIB_ipInReceives		MIB_ipMIB, 3
#define MIB_ipInHdrErrors		MIB_ipMIB, 4
#define MIB_ipInAddrErrors		MIB_ipMIB, 5
#define MIB_ipForwDatagrams		MIB_ipMIB, 6
#define MIB_ipInUnknownProtos		MIB_ipMIB, 7
#define MIB_ipInDiscards		MIB_ipMIB, 8
#define MIB_ipInDelivers		MIB_ipMIB, 9
#define MIB_ipOutRequests		MIB_ipMIB, 10
#define MIB_ipOutDiscards		MIB_ipMIB, 11
#define MIB_ipOutNoRoutes		MIB_ipMIB, 12
#define MIB_ipReasmTimeout		MIB_ipMIB, 13
#define MIB_ipReasmReqds		MIB_ipMIB, 14
#define MIB_ipReasmOKs			MIB_ipMIB, 15
#define MIB_ipReasmFails		MIB_ipMIB, 16
#define MIB_ipFragOKs			MIB_ipMIB, 17
#define MIB_ipFragFails			MIB_ipMIB, 18
#define MIB_ipFragCreates		MIB_ipMIB, 19
#define MIB_ipAddrTable			MIB_ipMIB, 20
#define MIB_ipAddrEntry			MIB_ipAddrTable, 1
#define OIDIDX_ipAddr			9
#define OIDIDX_ipAddrEntry		10
#define MIB_ipAdEntAddr			MIB_ipAddrEntry, 1
#define MIB_ipAdEntIfIndex		MIB_ipAddrEntry, 2
#define MIB_ipAdEntNetMask		MIB_ipAddrEntry, 3
#define MIB_ipAdEntBcastAddr		MIB_ipAddrEntry, 4
#define MIB_ipAdEntReasmMaxSize		MIB_ipAddrEntry, 5
#define MIB_ipNetToMediaTable		MIB_ipMIB, 22
#define MIB_ipNetToMediaEntry		MIB_ipNetToMediaTable, 1
#define MIB_ipNetToMediaIfIndex		MIB_ipNetToMediaEntry, 1
#define MIB_ipNetToMediaPhysAddress	MIB_ipNetToMediaEntry, 2
#define MIB_ipNetToMediaNetAddress	MIB_ipNetToMediaEntry, 3
#define MIB_ipNetToMediaType		MIB_ipNetToMediaEntry, 4
#define MIB_ipRoutingDiscards		MIB_ipMIB, 23

/* IP-FORWARD-MIB */
#define MIB_ipfMIB			MIB_ipMIB, 24
#define MIB_ipfInetCidrRouteNumber	MIB_ipfMIB, 6
#define MIB_ipfInetCidrRouteTable	MIB_ipfMIB, 7
#define MIB_ipfInetCidrRouteEntry	MIB_ipfInetCidrRouteTable, 1
#define OIDIDX_ipfInetCidrRoute		10
#define MIB_ipfRouteEntDestType		MIB_ipfInetCidrRouteEntry, 1
#define MIB_ipfRouteEntDest		MIB_ipfInetCidrRouteEntry, 2
#define MIB_ipfRouteEntPfxLen		MIB_ipfInetCidrRouteEntry, 3
#define MIB_ipfRouteEntPolicy		MIB_ipfInetCidrRouteEntry, 4
#define MIB_ipfRouteEntNextHopType	MIB_ipfInetCidrRouteEntry, 5
#define MIB_ipfRouteEntNextHop		MIB_ipfInetCidrRouteEntry, 6
#define MIB_ipfRouteEntIfIndex		MIB_ipfInetCidrRouteEntry, 7
#define MIB_ipfRouteEntType		MIB_ipfInetCidrRouteEntry, 8
#define MIB_ipfRouteEntProto		MIB_ipfInetCidrRouteEntry, 9
#define MIB_ipfRouteEntAge		MIB_ipfInetCidrRouteEntry, 10
#define MIB_ipfRouteEntNextHopAS	MIB_ipfInetCidrRouteEntry, 11
#define MIB_ipfRouteEntRouteMetric1	MIB_ipfInetCidrRouteEntry, 12
#define MIB_ipfRouteEntRouteMetric2	MIB_ipfInetCidrRouteEntry, 13
#define MIB_ipfRouteEntRouteMetric3	MIB_ipfInetCidrRouteEntry, 14
#define MIB_ipfRouteEntRouteMetric4	MIB_ipfInetCidrRouteEntry, 15
#define MIB_ipfRouteEntRouteMetric5	MIB_ipfInetCidrRouteEntry, 16
#define MIB_ipfRouteEntStatus		MIB_ipfInetCidrRouteEntry, 17
#define MIB_ipfInetCidrRouteDiscards	MIB_ipfMIB, 8

/* BRIDGE-MIB */
#define MIB_dot1dBridge			MIB_mib_2, 17
#define MIB_dot1dBase			MIB_dot1dBridge, 1
#define MIB_dot1dBaseBridgeAddress	MIB_dot1dBase, 1
#define MIB_dot1dBaseNumPorts		MIB_dot1dBase, 2
#define MIB_dot1dBaseType		MIB_dot1dBase, 3
#define MIB_dot1dBasePortTable		MIB_dot1dBase, 4
#define OIDIDX_dot1d			10
#define OIDIDX_dot1dEntry		11
#define MIB_dot1dBasePortEntry		MIB_dot1dBasePortTable, 1
#define MIB_dot1dBasePort		MIB_dot1dBasePortEntry, 1
#define MIB_dot1dBasePortIfIndex	MIB_dot1dBasePortEntry, 2
#define MIB_dot1dBasePortCircuit	MIB_dot1dBasePortEntry, 3
#define MIB_dot1dBasePortDelayExceededDiscards	MIB_dot1dBasePortEntry, 4
#define MIB_dot1dBasePortMtuExceededDiscards	MIB_dot1dBasePortEntry, 5
#define MIB_dot1dStp			MIB_dot1dBridge, 2
#define MIB_dot1dSr			MIB_dot1dBridge, 3
#define MIB_dot1dTp			MIB_dot1dBridge, 4
#define MIB_dot1dStatic			MIB_dot1dBridge, 5

/*
 * PRIVATE ENTERPRISE NUMBERS from
 * http://www.iana.org/assignments/enterprise-numbers
 *
 * This is not the complete list of private enterprise numbers, it only
 * includes some well-known companies and especially network companies
 * that are very common in the datacenters around the world, other
 * companies that contributed to snmpd or OpenBSD in some way, or just
 * any other organizations that we wanted to include. It would be an
 * overkill to include ~30.000 entries for all the organizations from
 * the official list.
 */
#define MIB_ibm				MIB_enterprises, 2
#define MIB_cmu				MIB_enterprises, 3
#define MIB_unix			MIB_enterprises, 4
#define MIB_ciscoSystems		MIB_enterprises, 9
#define MIB_hp				MIB_enterprises, 11
#define MIB_mit				MIB_enterprises, 20
#define MIB_nortelNetworks		MIB_enterprises, 35
#define MIB_sun				MIB_enterprises, 42
#define MIB_3com			MIB_enterprises, 43
#define MIB_synOptics			MIB_enterprises, 45
#define MIB_enterasys			MIB_enterprises, 52
#define MIB_sgi				MIB_enterprises, 59
#define MIB_apple			MIB_enterprises, 63
#define MIB_nasa			MIB_enterprises, 71
#define MIB_att				MIB_enterprises, 74
#define MIB_nokia			MIB_enterprises, 94
#define MIB_cern			MIB_enterprises, 96
#define MIB_oracle			MIB_enterprises, 111
#define MIB_motorola			MIB_enterprises, 161
#define MIB_ncr				MIB_enterprises, 191
#define MIB_ericsson			MIB_enterprises, 193
#define MIB_fsc				MIB_enterprises, 231
#define MIB_compaq			MIB_enterprises, 232
#define MIB_bmw				MIB_enterprises, 513
#define MIB_dell			MIB_enterprises, 674
#define MIB_iij				MIB_enterprises, 770
#define MIB_sandia			MIB_enterprises, 1400
#define MIB_mercedesBenz		MIB_enterprises, 1635
#define MIB_alteon			MIB_enterprises, 1872
#define MIB_extremeNetworks		MIB_enterprises, 1916
#define MIB_foundryNetworks		MIB_enterprises, 1991
#define MIB_huawaiTechnology		MIB_enterprises, 2011
#define MIB_ucDavis			MIB_enterprises, 2021
#define MIB_checkPoint			MIB_enterprises, 2620
#define MIB_juniper			MIB_enterprises, 2636
#define MIB_audi			MIB_enterprises, 3195
#define MIB_volkswagen			MIB_enterprises, 3210
#define MIB_genua			MIB_enterprises, 3717
#define MIB_amazon			MIB_enterprises, 4843
#define MIB_force10Networks		MIB_enterprises, 6027
#define MIB_vMware			MIB_enterprises, 6876
#define MIB_alcatelLucent		MIB_enterprises, 7483
#define MIB_snom			MIB_enterprises, 7526
#define MIB_google			MIB_enterprises, 11129
#define MIB_f5Networks			MIB_enterprises, 12276
#define MIB_sFlow			MIB_enterprises, 14706
#define MIB_microSystems		MIB_enterprises, 18623
#define MIB_paloAltoNetworks		MIB_enterprises, 25461
#define MIB_h3c				MIB_enterprises, 25506
#define MIB_vantronix			MIB_enterprises, 26766
#define OIDVAL_openBSD_eid		30155
#define MIB_openBSD			MIB_enterprises, OIDVAL_openBSD_eid
#define MIB_nicira			MIB_enterprises, 39961

/* UCD-DISKIO-MIB */
#define MIB_ucdExperimental		MIB_ucDavis, 13
#define MIB_ucdDiskIOMIB		MIB_ucdExperimental, 15
#define MIB_diskIOTable			MIB_ucdDiskIOMIB, 1
#define MIB_diskIOEntry			MIB_diskIOTable, 1
#define OIDIDX_diskIO			11
#define OIDIDX_diskIOEntry		12
#define MIB_diskIOIndex			MIB_diskIOEntry, 1
#define MIB_diskIODevice		MIB_diskIOEntry, 2
#define MIB_diskIONRead			MIB_diskIOEntry, 3
#define MIB_diskIONWritten		MIB_diskIOEntry, 4
#define MIB_diskIOReads			MIB_diskIOEntry, 5
#define MIB_diskIOWrites		MIB_diskIOEntry, 6
#define MIB_diskIONReadX		MIB_diskIOEntry, 12
#define MIB_diskIONWrittenX		MIB_diskIOEntry, 13

/* OPENBSD-MIB */
#define MIB_pfMIBObjects		MIB_openBSD, 1
#define MIB_pfInfo			MIB_pfMIBObjects, 1
#define MIB_pfRunning			MIB_pfInfo, 1
#define MIB_pfRuntime			MIB_pfInfo, 2
#define MIB_pfDebug			MIB_pfInfo, 3
#define MIB_pfHostid			MIB_pfInfo, 4
#define MIB_pfCounters			MIB_pfMIBObjects, 2
#define MIB_pfCntMatch			MIB_pfCounters, 1
#define MIB_pfCntBadOffset		MIB_pfCounters, 2
#define MIB_pfCntFragment		MIB_pfCounters, 3
#define MIB_pfCntShort			MIB_pfCounters, 4
#define MIB_pfCntNormalize		MIB_pfCounters, 5
#define MIB_pfCntMemory			MIB_pfCounters, 6
#define MIB_pfCntTimestamp		MIB_pfCounters, 7
#define MIB_pfCntCongestion		MIB_pfCounters, 8
#define MIB_pfCntIpOptions		MIB_pfCounters, 9
#define MIB_pfCntProtoCksum		MIB_pfCounters, 10
#define MIB_pfCntStateMismatch		MIB_pfCounters, 11
#define MIB_pfCntStateInsert		MIB_pfCounters, 12
#define MIB_pfCntStateLimit		MIB_pfCounters, 13
#define MIB_pfCntSrcLimit		MIB_pfCounters, 14
#define MIB_pfCntSynproxy		MIB_pfCounters, 15
#define MIB_pfCntTranslate		MIB_pfCounters, 16
#define MIB_pfStateTable		MIB_pfMIBObjects, 3
#define MIB_pfStateCount		MIB_pfStateTable, 1
#define MIB_pfStateSearches		MIB_pfStateTable, 2
#define MIB_pfStateInserts		MIB_pfStateTable, 3
#define MIB_pfStateRemovals		MIB_pfStateTable, 4
#define MIB_pfLogInterface		MIB_pfMIBObjects, 4
#define MIB_pfLogIfName			MIB_pfLogInterface, 1
#define MIB_pfLogIfIpBytesIn		MIB_pfLogInterface, 2
#define MIB_pfLogIfIpBytesOut		MIB_pfLogInterface, 3
#define MIB_pfLogIfIpPktsInPass		MIB_pfLogInterface, 4
#define MIB_pfLogIfIpPktsInDrop		MIB_pfLogInterface, 5
#define MIB_pfLogIfIpPktsOutPass	MIB_pfLogInterface, 6
#define MIB_pfLogIfIpPktsOutDrop	MIB_pfLogInterface, 7
#define MIB_pfLogIfIp6BytesIn		MIB_pfLogInterface, 8
#define MIB_pfLogIfIp6BytesOut		MIB_pfLogInterface, 9
#define MIB_pfLogIfIp6PktsInPass	MIB_pfLogInterface, 10
#define MIB_pfLogIfIp6PktsInDrop	MIB_pfLogInterface, 11
#define MIB_pfLogIfIp6PktsOutPass	MIB_pfLogInterface, 12
#define MIB_pfLogIfIp6PktsOutDrop	MIB_pfLogInterface, 13
#define MIB_pfSrcTracking		MIB_pfMIBObjects, 5
#define MIB_pfSrcTrackCount		MIB_pfSrcTracking, 1
#define MIB_pfSrcTrackSearches		MIB_pfSrcTracking, 2
#define MIB_pfSrcTrackInserts		MIB_pfSrcTracking, 3
#define MIB_pfSrcTrackRemovals		MIB_pfSrcTracking, 4
#define MIB_pfLimits			MIB_pfMIBObjects, 6
#define MIB_pfLimitStates		MIB_pfLimits, 1
#define MIB_pfLimitSourceNodes		MIB_pfLimits, 2
#define MIB_pfLimitFragments		MIB_pfLimits, 3
#define MIB_pfLimitMaxTables		MIB_pfLimits, 4
#define MIB_pfLimitMaxTableEntries	MIB_pfLimits, 5
#define MIB_pfTimeouts			MIB_pfMIBObjects, 7
#define MIB_pfTimeoutTcpFirst		MIB_pfTimeouts, 1
#define MIB_pfTimeoutTcpOpening		MIB_pfTimeouts, 2
#define MIB_pfTimeoutTcpEstablished	MIB_pfTimeouts, 3
#define MIB_pfTimeoutTcpClosing		MIB_pfTimeouts, 4
#define MIB_pfTimeoutTcpFinWait		MIB_pfTimeouts, 5
#define MIB_pfTimeoutTcpClosed		MIB_pfTimeouts, 6
#define MIB_pfTimeoutUdpFirst		MIB_pfTimeouts, 7
#define MIB_pfTimeoutUdpSingle		MIB_pfTimeouts, 8
#define MIB_pfTimeoutUdpMultiple	MIB_pfTimeouts, 9
#define MIB_pfTimeoutIcmpFirst		MIB_pfTimeouts, 10
#define MIB_pfTimeoutIcmpError		MIB_pfTimeouts, 11
#define MIB_pfTimeoutOtherFirst		MIB_pfTimeouts, 12
#define MIB_pfTimeoutOtherSingle	MIB_pfTimeouts, 13
#define MIB_pfTimeoutOtherMultiple	MIB_pfTimeouts, 14
#define MIB_pfTimeoutFragment		MIB_pfTimeouts, 15
#define MIB_pfTimeoutInterval		MIB_pfTimeouts, 16
#define MIB_pfTimeoutAdaptiveStart	MIB_pfTimeouts, 17
#define MIB_pfTimeoutAdaptiveEnd	MIB_pfTimeouts, 18
#define MIB_pfTimeoutSrcTrack		MIB_pfTimeouts, 19
#define OIDIDX_pfstatus			9
#define MIB_pfInterfaces		MIB_pfMIBObjects, 8
#define MIB_pfIfNumber			MIB_pfInterfaces, 1
#define MIB_pfIfTable			MIB_pfInterfaces, 128
#define MIB_pfIfEntry			MIB_pfIfTable, 1
#define OIDIDX_pfInterface		11
#define OIDIDX_pfIfEntry		12
#define MIB_pfIfIndex			MIB_pfIfEntry, 1
#define MIB_pfIfDescr			MIB_pfIfEntry, 2
#define MIB_pfIfType			MIB_pfIfEntry, 3
#define MIB_pfIfRefs			MIB_pfIfEntry, 4
#define MIB_pfIfRules			MIB_pfIfEntry, 5
#define MIB_pfIfIn4PassPkts		MIB_pfIfEntry, 6
#define MIB_pfIfIn4PassBytes		MIB_pfIfEntry, 7
#define MIB_pfIfIn4BlockPkts		MIB_pfIfEntry, 8
#define MIB_pfIfIn4BlockBytes		MIB_pfIfEntry, 9
#define MIB_pfIfOut4PassPkts		MIB_pfIfEntry, 10
#define MIB_pfIfOut4PassBytes		MIB_pfIfEntry, 11
#define MIB_pfIfOut4BlockPkts		MIB_pfIfEntry, 12
#define MIB_pfIfOut4BlockBytes		MIB_pfIfEntry, 13
#define MIB_pfIfIn6PassPkts		MIB_pfIfEntry, 14
#define MIB_pfIfIn6PassBytes		MIB_pfIfEntry, 15
#define MIB_pfIfIn6BlockPkts		MIB_pfIfEntry, 16
#define MIB_pfIfIn6BlockBytes		MIB_pfIfEntry, 17
#define MIB_pfIfOut6PassPkts		MIB_pfIfEntry, 18
#define MIB_pfIfOut6PassBytes		MIB_pfIfEntry, 19
#define MIB_pfIfOut6BlockPkts		MIB_pfIfEntry, 20
#define MIB_pfIfOut6BlockBytes		MIB_pfIfEntry, 21
#define MIB_pfTables			MIB_pfMIBObjects, 9
#define MIB_pfTblNumber			MIB_pfTables, 1
#define MIB_pfTblTable			MIB_pfTables, 128
#define MIB_pfTblEntry			MIB_pfTblTable, 1
#define OIDIDX_pfTable			11
#define OIDIDX_pfTableEntry		12
#define MIB_pfTblIndex			MIB_pfTblEntry, 1
#define MIB_pfTblName			MIB_pfTblEntry, 2
#define MIB_pfTblAddresses		MIB_pfTblEntry, 3
#define MIB_pfTblAnchorRefs		MIB_pfTblEntry, 4
#define MIB_pfTblRuleRefs		MIB_pfTblEntry, 5
#define MIB_pfTblEvalsMatch		MIB_pfTblEntry, 6
#define MIB_pfTblEvalsNoMatch		MIB_pfTblEntry, 7
#define MIB_pfTblInPassPkts		MIB_pfTblEntry, 8
#define MIB_pfTblInPassBytes		MIB_pfTblEntry, 9
#define MIB_pfTblInBlockPkts		MIB_pfTblEntry, 10
#define MIB_pfTblInBlockBytes		MIB_pfTblEntry, 11
#define MIB_pfTblInXPassPkts		MIB_pfTblEntry, 12
#define MIB_pfTblInXPassBytes		MIB_pfTblEntry, 13
#define MIB_pfTblOutPassPkts		MIB_pfTblEntry, 14
#define MIB_pfTblOutPassBytes		MIB_pfTblEntry, 15
#define MIB_pfTblOutBlockPkts		MIB_pfTblEntry, 16
#define MIB_pfTblOutBlockBytes		MIB_pfTblEntry, 17
#define MIB_pfTblOutXPassPkts		MIB_pfTblEntry, 18
#define MIB_pfTblOutXPassBytes		MIB_pfTblEntry, 19
#define MIB_pfTblStatsCleared		MIB_pfTblEntry, 20
#define MIB_pfTblAddrTable		MIB_pfTables, 129
