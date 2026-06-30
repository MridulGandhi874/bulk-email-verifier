import asyncio
import dns.resolver
import re
import io
import os
import httpx
import pandas as pd
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse

app = FastAPI()


@app.get("/")
async def get_ui():
    html_path = os.path.join(os.getcwd(), "index.html")
    with open(html_path, "r") as f:
        return HTMLResponse(content=f.read())


async def verify_via_http_fallback(email: str, domain: str):
    try:
        async with httpx.AsyncClient(timeout=3.0, follow_redirects=True) as client:
            if domain in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]:
                url = f"https://mail.google.com/mail/gxlu?email={email}"
                response = await client.get(url)
                if response.headers.get("Set-Cookie"):
                    return "Valid"
                else:
                    return "Bounce"
            else:
                web_check = await client.get(f"https://{domain}")
                if web_check.status_code < 500:
                    return "Valid"
                else:
                    return "Bounce"
    except Exception:
        return "Unknown/Error"


async def verify_email_core(email: str):
    email = email.strip()
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return email, "Bounce"

    domain = email.split('@')[1]
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted(answers, key=lambda x: x.preference)
        mx_host = str(mx_records[0].exchange).rstrip('.')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return email, "Bounce"
    except Exception:
        return email, "Unknown/Error"

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(mx_host, 25), timeout=1.0)
        await asyncio.wait_for(reader.read(1024), timeout=1.0)

        writer.write(b"HELO verify.local\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(1024), timeout=1.0)

        writer.write(b"MAIL FROM:<admin@verify.local>\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(1024), timeout=1.0)

        writer.write(f"RCPT TO:<{email}>\r\n".encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(1024), timeout=1.0)
        response_text = response.decode()

        status = "Valid"
        if response_text.startswith("250"):
            writer.write(f"RCPT TO:<dummy_fake_12345@{domain}>\r\n".encode())
            await writer.drain()
            catch_resp = await asyncio.wait_for(reader.read(1024), timeout=1.0)
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
        fallback_status = await verify_via_http_fallback(email, domain)
        return email, fallback_status


@app.post("/verify")
async def verify_bulk(file: UploadFile = File(...)):
    content = await file.read()
    if file.filename.endswith('.csv'):
        df = pd.read_csv(io.BytesIO(content))
        emails = df.iloc[:, 0].dropna().astype(str).tolist()
    else:
        emails = content.decode('utf-8').splitlines()

    tasks = [verify_email_core(em) for em in emails if em.strip()]
    results = await asyncio.gather(*tasks)

    out_df = pd.DataFrame(results, columns=["EmailAddress", "Status"])
    stream = io.StringIO()
    out_df.to_csv(stream, index=False)

    response = StreamingResponse(iter([stream.getvalue()]), media_type="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=results.csv"
    return response