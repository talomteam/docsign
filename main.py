#!/usr/bin/env vpython3

from fastapi import FastAPI, File, UploadFile
from pydantic import BaseModel
from pathlib import Path

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
            




class User(BaseModel):
    userkey: str
    name: str
    fs_source: UploadFile = File()
    fs_pic_sign: UploadFile = File(None)


app = FastAPI()


@app.post("/sign")
async def sign(user: User):
    clshsm = HSM(user.name, user.userkey, "CryptoServer PKCS11 Token","12345")
    clshsm.existcert()
    
    if not user.fs_source:
        return {'message': 'No upload file sent'}
    else:
        path = Path('/tmp') / user.fs_source.filename
        size = path.write_bytes(await user.fs_source.read())
        


        return {'file': path, 'bytes': size}

    return user
