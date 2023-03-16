#!/usr/bin/env vpython3

import base64
import sys
import os
import aiofiles
import pathlib
from ast import literal_eval
from fastapi import FastAPI, File, UploadFile, Form
import PyKCS11 as PK11
from endesive import hsm

if sys.platform == 'win32':
    dllpath = r'W:\binw\SoftHSM2\lib\softhsm2-x64.dll'
else:
    dllpath = '/usr/lib/libcs_pkcs11_R3.so'

class HSM(hsm.HSM):
    def existcert(self, keyID, name):
        cakeyID = bytes((0x1))
        rec = self.session.findObjects(
            [(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY), (PK11.CKA_ID, keyID)])
        if len(rec) == 0:
            label = name
            keyname = keyID.hex()
            sn = literal_eval('0x{}'.format(keyname))
            self.gen_privkey(label, keyID)
            self.ca_sign(keyID, label, sn, name, 365, cakeyID)

        # self.cert_export('cert-hsm-ca', cakeyID)
        self.cert_export('cert-hsm-{}'.format(keyname),keyID)


app = FastAPI()


@app.post("/sign")
async def sign(userkey: str = Form(), name: str = Form(), fs_source: UploadFile = File(), fs_pic_sign: UploadFile = File(None)):

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
    cls = HSM(dllpath)
    cls.create("CryptoServer PKCS11 Token", "77777", "11111")
    cls.login("CryptoServer PKCS11 Token", "12345")
    cls.existcert(keyID, name)
    cls.logout()

    return name
