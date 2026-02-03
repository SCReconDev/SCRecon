cd dashboard
uvicorn dashboard:app --port 8000 --reload

cd portscanner
uvicorn portscanner:app --port 8001 --reload

cd bannergrabbing
uvicorn bannergrabbing:app --port 8002 --reload

cd vulnerability
uvicorn vulnerability:app --port 8003 --reload

cd subdomainenumeration
uvicorn subdomainenumeration:app --port 8004 --reload

cd smbshares
uvicorn smbshares:app --port 8005 --reload

cd whatweb
uvicorn whatweb:app --port 8006 --reload

cd cvelookup
uvicorn cvelookup:app --port 8007 --reload

cd metasploit
uvicorn metasploit:app --port 8008 --reload
