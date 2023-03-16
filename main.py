#!/usr/bin/env vpython3

import sys
import os
import aiofiles
import pathlib

import PyKCS11 as PK11
import datetime
from cryptography import x509
from cryptography.hazmat import backends
from ast import literal_eval
from fastapi import FastAPI, File, UploadFile, Form
from dotenv import load_dotenv

from endesive import hsm, pdf

if sys.platform == 'win32':
    dllpath = r'W:\binw\SoftHSM2\lib\softhsm2-x64.dll'
else:
    dllpath = '/usr/lib/libcs_pkcs11_R3.so'


class HSM(hsm.HSM):
    def __init__(self, name, keyID, label_port, pin_port):
        super().__init__(dllpath)
        self.name = name
        self.keyID = keyID
        self.label_port = label_port
        self.pin_port = pin_port

    def existcert(self, keyID, name):
        self.login(self.label_port, self.pin_port)
        cakeyID = bytes((0x1,))
        label = name
        keyname = keyID.hex()
        rec = self.session.findObjects(
            [(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY), (PK11.CKA_ID, keyID)])
        if len(rec) == 0:
            sn = literal_eval('0x{}'.format(keyname))
            self.gen_privkey(label, keyID)
            self.ca_sign(keyID, label, sn, name, 365, cakeyID)
        self.cert_export('cert-hsm-{}'.format(keyname), keyID)
        self.logout()

    def certificate(self):
        self.login(self.label_port, self.pin_port)
        keyid = self.keyID
        try:
            pk11objects = self.session.findObjects(
                [(PK11.CKA_CLASS, PK11.CKO_CERTIFICATE)])
            all_attributes = [
                # PK11.CKA_SUBJECT,
                PK11.CKA_VALUE,
                # PK11.CKA_ISSUER,
                # PK11.CKA_CERTIFICATE_CATEGORY,
                # PK11.CKA_END_DATE,
                PK11.CKA_ID,
            ]

            for pk11object in pk11objects:
                try:
                    attributes = self.session.getAttributeValue(
                        pk11object, all_attributes)
                except PK11.PyKCS11Error as e:
                    continue

                attrDict = dict(list(zip(all_attributes, attributes)))
                cert = bytes(attrDict[PK11.CKA_VALUE])
                if keyid == bytes(attrDict[PK11.CKA_ID]):
                    return keyid, cert
        finally:
            self.logout()
        return None, None

    def sign(self, keyid, data, mech):
        self.login(self.label_port, self.pin_port)
        try:
            privKey = self.session.findObjects(
                [(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY), (PK11.CKA_ID, keyid)])[0]
            mech = getattr(PK11, 'CKM_%s_RSA_PKCS' % mech.upper())
            sig = self.session.sign(privKey, data, PK11.Mechanism(mech, None))
            return bytes(sig)
        finally:
            self.logout()


app = FastAPI()


@app.post("/sign")
async def sign(userkey: str = Form(), name: str = Form(), fs_source: UploadFile = File(), fs_pic_sign: UploadFile = File(None)):
    if len(userkey) != 6:
        return "userkey length not match"
    source_path = '{}/{}/{}'.format(pathlib.Path().resolve(),
                                    'source', fs_source.filename)
    async with aiofiles.open(source_path, "wb") as out_file:
        content = await fs_source.read()
        await out_file.write(content)

    if fs_pic_sign:
        sign_path = '{}/{}/{}'.format(pathlib.Path().resolve(),
                                      'sign', fs_pic_sign.filename)
        async with aiofiles.open(sign_path, "wb") as out_file:
            content = await fs_pic_sign.read()
            await out_file.write(content)

    keyID = bytes.fromhex(userkey)
    label_port = "CryptoServer PKCS11 Token"
    pin_port = "12345"
    cls = HSM(keyID, name, label_port, pin_port)
    # cls.create("CryptoServer PKCS11 Token", "77777", "11111")
    # cls.login("CryptoServer PKCS11 Token", "12345")
    cls.existcert(keyID, name)
    # cls.logout()
    
    tspurl = "http://time.certum.pl"
    tspurl = "http://public-qlts.certum.pl/qts-17"

    ocspurl = 'https://ocsp.certum.pl/'
    #ocspissuer = open('CertumDigitalIdentificationCASHA2.crt', 'rb').read()
    ocspissuer = cls.certificate()[1]
    ocspissuer = x509.load_pem_x509_certificate(
        ocspissuer, backends.default_backend())

    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime('D:%Y%m%d%H%M%S+00\'00\'')
    dct = {
        'sigflags': 3,
        'contact': 'mak@trisoft.com.pl',
        'location': 'Szczecin',
        'signingdate': date.encode(),
        'reason': 'Dokument podpisany cyfrowo',
        'application': 'app:xyz',
    }

    fname = source_path
    if len(sys.argv) > 1:
        fname = sys.argv[1]

    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
                         None, None,
                         [],
                         'sha256',
                         cls,
                         tspurl,
                         ocspurl=ocspurl,
                         ocspissuer=ocspissuer
                         )
    fname = fname.replace('.pdf', '-signed-hsm.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)

    return name
