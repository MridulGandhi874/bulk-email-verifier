import asyncio
import aiodns
import re
import io
import os
import pandas as pd
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse

app = FastAPI()


@app.get("/")
async def get_ui():
    # Vercel executes from the root directory, so we look for index.html there
    html_path = os.path.join(os.getcwd(), "index.html")
    with open(html_path, "r") as f:
        return HTMLResponse(content=f.read())


async def verify_email(email: str):
    email = email.strip()

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return email, "Bounce"

    domain = email.split('@')[1]

    resolver = aiodns.DNSResolver()
    try:
        mx_records = await resolver.query(domain, 'MX')
        mx_records = sorted(mx_records, key=lambda x: x.priority)
        mx_host = mx_records[0].host
    except Exception:
        return email, "Bounce"

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(mx_host, 25), timeout=8.0)
        await asyncio.wait_for(reader.read(1024), timeout=5.0)

        writer.write(b"HELO verify.local\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(1024), timeout=5.0)

        writer.write(b"MAIL FROM:<admin@verify.local>\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(1024), timeout=5.0)

        writer.write(f"RCPT TO:<{email}>\r\n".encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
        response_text = response.decode()

        status = "Valid"
        if response_text.startswith("250"):
            writer.write(f"RCPT TO:<dummy_fake_12345@{domain}>\r\n".encode())
            await writer.drain()
            catch_resp = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            if catch_resp.decode().startswith("250"):
                status = "Catch-All"
        elif response_text.startswith("550"):
            status = "Bounce"
        else:
            status = "Unknown/Error"

        writer.write(b"QUIT\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

        return email, status

    except Exception:
        return email, "Unknown/Error"


@app.post("/verify")
async def verify_bulk(file: UploadFile = File(...)):
    content = await file.read()

    if file.filename.endswith('.csv'):
        df = pd.read_csv(io.BytesIO(content))
        emails = df.iloc[:, 0].dropna().astype(str).tolist()
    else:
        emails = content.decode('utf-8').splitlines()

    sem = asyncio.Semaphore(20)

    async def sem_verify(em):
        async with sem:
            return await verify_email(em)

    tasks = [sem_verify(em) for em in emails if em.strip()]
    results = await asyncio.gather(*tasks)

    out_df = pd.DataFrame(results, columns=["EmailAddress", "Status"])
    stream = io.StringIO()
    out_df.to_csv(stream, index=False)

    response = StreamingResponse(iter([stream.getvalue()]), media_type="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=results.csv"
    return response