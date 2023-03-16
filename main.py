#!/usr/bin/env vpython3

from fastapi import FastAPI, File, UploadFile, Form
from pydantic import BaseModel
import pathlib 
import aiofiles

import os
import sys
import base64

if sys.platform == 'win32':
    dllpath = r'W:\binw\SoftHSM2\lib\softhsm2-x64.dll'
else:
    dllpath = '/usr/lib/libcs_pkcs11_R3.so'

sys.path.append('/opt/endesive')

from endesive import hsm
import PyKCS11 as PK11


class HSM(hsm.HSM):
    def __init__(self, name, keyID,label_port,pin_port):
        super().__init__(dllpath)
        self.name = name
        self.keyID = keyID
        self.label_port = label_port
        self.pin_port = pin_port
        

    def existcert(self):
        cakeyID = bytes((0x1))
        rec = self.session.findObjects(
            [(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY), (PK11.CKA_ID, self.keyID)])
        if len(rec) ==0:
            label = self.name
            self.gen_privkey(label, self.keyID)
            self.ca_sign(self.keyID, label, 0x666690,self.name, 365, cakeyID)
            
        #self.cert_export('cert-hsm-ca', cakeyID)
        self.cert_export('cert-hsm-'+self.keyID, self.keyID)

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
    clshsm = HSM(user.name, user.userkey, "CryptoServer PKCS11 Token","12345")
    clshsm.existcert()
    
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
    return name
    
