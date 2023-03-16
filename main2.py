from fastapi import FastAPI, File, UploadFile, Form

import aiofiles
import pathlib

app = FastAPI()


@app.post("/sign")
async def sign(userkey: str = Form(), name: str = Form(), fs_source: UploadFile = File(),fs_pic_sign: UploadFile = File(None)):
    source_path = '{}/{}/{}'.format(pathlib.Path().resolve(),'source',fs_source.filename)
    async with aiofiles.open(source_path,"wb") as out_file:
        content = await fs_source.read()
        await out_file.write(content)

    if fs_pic_sign :
        sign_path = '{}/{}/{}'.format(pathlib.Path().resolve(),
                                        'sign', fs_pic_sign.filename)
        async with aiofiles.open(sign_path, "wb") as out_file:
            content = await fs_pic_sign.read()
            await out_file.write(content)
    return name
