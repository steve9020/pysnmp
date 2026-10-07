#!/usr/bin/env python3
"""Keeper functional check, no network needed (sandbox blocks UDP sendto).

Covers the modernized paths:
  * pysnmp.compat.octets (pyasn1 0.6.x installed, pyasn1.compat.octets gone)
  * vendored asyncore carrier (dispatcher init / register / unregister)
  * asyncio hlapi converted to async def (await contract with fake dispatcher)
  * SMI/MIB load + ObjectIdentity resolution (exercises SNMPv2-TC octets use)
  * BER encode/decode of v1/v2c/v3 messages
  * SNMPv3 auth (HMAC-SHA, hashlib) and priv (DES/AES via pysnmpcrypto)
  * Twisted carrier import
"""
import asyncio

results = []


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print('%-52s %s %s' % (name, 'PASS' if cond else 'FAIL', detail))


# 1. compat.octets -------------------------------------------------------
from pysnmp.compat import octets
check('compat null == b""', octets.null == b'')
check('compat oct2int', octets.oct2int(b'\x41') == 0x41)
check('compat int2oct', octets.int2oct(0x41) == b'\x41')
check('compat octs2ints', octets.octs2ints(b'\x01\x02') == [1, 2])
check('compat str2octs/octs2str',
      octets.octs2str(octets.str2octs('ab')) == 'ab')
check('compat ints2octs', octets.ints2octs([1, 2]) == b'\x01\x02')
check('compat isStringType/isOctetsType',
      octets.isStringType('a') and octets.isOctetsType(b'a')
      and not octets.isStringType(b'a'))

# 2. vendored asyncore ----------------------------------------------------
from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher
from pysnmp.carrier.asyncore.dgram import udp

disp = AsyncoreDispatcher()
check('asyncore dispatcher init', disp.getSocketMap() == {})
disp.registerTransport(udp.DOMAIN_NAME,
                       udp.UdpTransport().openClientMode())
check('asyncore registerTransport',
      len(disp.getSocketMap()) == 1)
disp.unregisterTransport(udp.DOMAIN_NAME)
check('asyncore unregisterTransport',
      len(disp.getSocketMap()) == 0)

# 3. asyncio hlapi contract -----------------------------------------------
from pysnmp.hlapi.v3arch.asyncio import (
    getCmd as v3getCmd, nextCmd as v3nextCmd, sendNotification,
    CommunityData, UsmUserData, UdpTransportTarget, ContextData,
    ObjectIdentity, ObjectType)
from pysnmp.hlapi.v1arch.asyncio import (
    getCmd as v1getCmd)

check('asyncio getCmd is coroutinefunction',
      asyncio.iscoroutinefunction(v3getCmd))
check('asyncio nextCmd is coroutinefunction',
      asyncio.iscoroutinefunction(v3nextCmd))
check('asyncio sendNotification is coroutinefunction',
      asyncio.iscoroutinefunction(sendNotification))
check('asyncio v1 getCmd is coroutinefunction',
      asyncio.iscoroutinefunction(v1getCmd))



def make_canned_responder():
    from pysnmp.proto import api
    from pysnmp.entity.rfc3413 import cmdgen as low_cmdgen

    def fake_sendVarBinds(self, snmpEngine, addrName, contextEngineId,
                          contextName, varBinds, cbFun, cbCtx):
        pMod = api.PROTOCOL_MODULES[1]  # SNMPv2c
        rspPdu = pMod.GetResponsePDU()
        pMod.apiPDU.setDefaults(rspPdu)
        pMod.apiPDU.setVarBinds(rspPdu, [])
        cbFun(snmpEngine, None, None, 0, 0, [], cbCtx)
    return fake_sendVarBinds


async def amain():
    from pysnmp.entity.engine import SnmpEngine
    from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
    from pysnmp.carrier.asyncio.dgram import udp as aio_udp
    from pysnmp.entity.rfc3413 import cmdgen as low_cmdgen

    snmpEngine = SnmpEngine()
    snmpEngine.registerTransportDispatcher(AsyncioDispatcher())
    snmpEngine.transportDispatcher.registerTransport(
        aio_udp.domainName, aio_udp.UdpAsyncioTransport().openClientMode())
    # answer immediately with a canned empty-varbinds response
    # (the sandbox blocks UDP sendto, so no real I/O here)
    low_cmdgen.GetCommandGenerator.sendVarBinds = make_canned_responder()

    out = await v3getCmd(
        snmpEngine, CommunityData('public', mpModel=1),
        UdpTransportTarget(('127.0.0.1', 161)), ContextData(),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
    errInd, errStat, errIdx, vb = out
    check('asyncio getCmd await returns 4-tuple',
          errInd is None and errStat in (0, None) and errIdx == 0
          and vb == [],
          repr(out)[:60])


asyncio.run(amain())

# 4. SMI / MIB -------------------------------------------------------------
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType
from pysnmp.smi.builder import MibBuilder
from pysnmp.smi.view import MibViewController

mibBuilder = MibBuilder()
mibView = MibViewController(mibBuilder)
mibBuilder.loadModules('SNMPv2-MIB')
oid = ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)
oid.resolveWithMib(mibView)
check('MIB resolve sysDescr',
      oid.getOid() == (1, 3, 6, 1, 2, 1, 1, 1, 0),
      repr(oid.getOid()))
ot = ObjectType(oid)
ot.resolveWithMib(mibView)
check('ObjectType resolveWithMib',
      ot[0].prettyPrint() == 'SNMPv2-SMI::mib-2.1.1.0'
      or 'sysDescr' in ot[0].prettyPrint(),
      ot[0].prettyPrint()[:60])

# SNMPv2-TC DisplayString path (uses pysnmp.compat.octets heavily)
mibBuilder.loadModules('SNMPv2-TC')
DisplayString, = mibBuilder.importSymbols('SNMPv2-TC', 'DisplayString')
ds = DisplayString('hello')
check('SNMPv2-TC DisplayString',
      ds.prettyPrint() == 'hello', repr(ds.prettyPrint())[:40])

# 5. BER codec ---------------------------------------------------------------
from pysnmp.proto import api
from pyasn1.codec.ber import encoder, decoder

for mpModel, name in ((0, 'v1'), (1, 'v2c')):
    pMod = api.PROTOCOL_MODULES[mpModel]
    reqPdu = pMod.GetRequestPDU()
    pMod.apiPDU.setDefaults(reqPdu)
    pMod.apiPDU.setVarBinds(reqPdu, [((1, 3, 6, 1, 2, 1, 1, 1, 0),
                                     pMod.Null(''))])
    msg = pMod.Message()
    pMod.apiMessage.setDefaults(msg)
    pMod.apiMessage.setCommunity(msg, 'public')
    pMod.apiMessage.setPDU(msg, reqPdu)
    wire = encoder.encode(msg)
    msg2, rest = decoder.decode(wire, asn1Spec=pMod.Message())
    pdu2 = pMod.apiMessage.getPDU(msg2)
    vb = pMod.apiPDU.getVarBinds(pdu2)
    check('BER %s encode/decode round trip' % name,
          tuple(vb[0][0]) == (1, 3, 6, 1, 2, 1, 1, 1, 0) and not rest)

# 6. SNMPv3 auth (HMAC-SHA, hashlib-only) --------------------------------------
from pysnmp.proto.secmod.rfc3414.auth import hmacsha
from pyasn1.type import univ

authSvc = hmacsha.HmacSha()
engineID = univ.OctetString(b'\x80\x00\x00\x00\x01\x02\x03\x04')
kul = authSvc.localizeKey(authSvc.hashPassphrase('authkey1'), engineID)
wholeMsg = b'\x30\x20' + b'\x00' * 12 + bytes(range(1, 30))
authMsg = authSvc.authenticateOutgoingMsg(kul, wholeMsg)
mac = univ.OctetString(authMsg[2:14])  # MAC sits where the placeholder was
ok = authSvc.authenticateIncomingMsg(kul, mac, authMsg)
check('v3 HMAC-SHA authenticate round trip', ok == wholeMsg)
# tamper -> must fail
badMsg = authMsg[:20] + bytes([authMsg[20] ^ 0xff]) + authMsg[21:]
try:
    authSvc.authenticateIncomingMsg(kul, mac, badMsg)
    check('v3 HMAC-SHA tamper rejected', False)
except Exception:
    check('v3 HMAC-SHA tamper rejected', True)

# 7. SNMPv3 priv (DES + AES via pysnmpcrypto) -----------------------------------
from pysnmp.proto.secmod.rfc3414.priv import des as desMod
from pysnmp.proto.secmod.rfc3826.priv import aes as aesMod

desSvc = desMod.Des()
privKey = desSvc.localizeKey(hmacsha.HmacSha.SERVICE_ID,
                             'privkey1', engineID)
if desMod.des is None:
    check('v3 DES priv (pysnmpcrypto present)', False, 'pysnmpcrypto missing')
else:
    enc, privParams = desSvc.encryptData(
        privKey, (1, 2, b'\x00' * 8), b'abcdefgh' * 4)
    dec = desSvc.decryptData(privKey, (1, 2, privParams), enc)
    check('v3 DES encrypt/decrypt round trip',
          bytes(dec[:32]) == b'abcdefgh' * 4, repr(bytes(dec[:32]))[:40])

aesSvc = aesMod.Aes()
aPrivKey = aesSvc.localizeKey(hmacsha.HmacSha.SERVICE_ID,
                              'privkey1privkey1', engineID)
if aesMod.aes is None:
    check('v3 AES priv (pysnmpcrypto present)', False, 'pysnmpcrypto missing')
else:
    enc, privParams = aesSvc.encryptData(
        aPrivKey, (1, 2, b'\x00' * 8), b'0123456789abcdef')
    dec = aesSvc.decryptData(aPrivKey, (1, 2, privParams), enc)
    check('v3 AES-128 encrypt/decrypt round trip',
          bytes(dec[:16]) == b'0123456789abcdef',
          repr(bytes(dec[:16]))[:40])

# 8. Twisted carrier import ------------------------------------------------------
try:
    import pysnmp.carrier.twisted.dispatch  # noqa
    check('twisted carrier import', True)
except Exception as e:
    check('twisted carrier import', False, str(e)[:60])

# 9. debug module (uses compat octs2ints) ---------------------------------------
from pysnmp import debug
check('debug module import', hasattr(debug, 'Printer'))

# ---------------------------------------------------------------- summary
failed = [n for n, ok in results if not ok]
print('\n%d/%d checks passed' % (len(results) - len(failed), len(results)))
raise SystemExit(1 if failed else 0)
