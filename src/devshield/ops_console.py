"""Local-only authenticated operations UI (not a public management API)."""
from __future__ import annotations
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import urlsplit
from devshield.ops_store import OpsStore
from devshield.security_policy import can_access

COOKIE = "devshield_ops_session"


def make_handler(store, *, csrf_secret=None):
    secret = os.urandom(32) if csrf_secret is None else csrf_secret
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("CSRF secret must be at least 32 bytes")

    class Handler(BaseHTTPRequestHandler):
        server_version = "DevShieldConsole"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def headers_safe(self, length, content_type, cookie=None):
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; base-uri 'none'; form-action 'self'; "
                "frame-ancestors 'none'")
            if cookie is not None:
                self.send_header("Set-Cookie", cookie)

        def reply(self, status, payload, cookie=None):
            body=json.dumps(payload,separators=(",",":")).encode("utf-8")
            self.send_response(status)
            self.headers_safe(len(body),"application/json; charset=utf-8",cookie)
            self.end_headers()
            self.wfile.write(body)

        def asset(self,name,mime):
            body=resources.files("devshield").joinpath("static",name).read_bytes()
            self.send_response(200)
            self.headers_safe(len(body),mime)
            self.end_headers()
            self.wfile.write(body)

        def token(self):
            try:
                jar=cookies.SimpleCookie()
                jar.load(self.headers.get("Cookie",""))
                item=jar.get(COOKIE)
                return item.value if item is not None else None
            except cookies.CookieError:
                return None

        def identity(self):
            token=self.token()
            return token, (store.resolve(token) if token else None)

        def csrf(self,token):
            return hmac.new(secret,token.encode("utf-8"),hashlib.sha256).hexdigest()

        def valid_origin(self):
            host,port=self.server.server_address[:2]
            return (self.headers.get("Origin")==f"http://{host}:{port}" and
                    self.headers.get("Host")==f"{host}:{port}")

        def parse_json(self):
            if self.headers.get("Content-Type","").split(";")[0].strip()!="application/json":
                raise ValueError("JSON required")
            try:
                size=int(self.headers.get("Content-Length","0"))
            except ValueError:
                raise ValueError("bad length") from None
            if not 1 <= size <= 4096:
                raise ValueError("bad size")
            parsed=json.loads(self.rfile.read(size))
            if not isinstance(parsed,dict):
                raise ValueError("object required")
            return parsed

        def do_GET(self):
            route=urlsplit(self.path).path
            if route=="/":
                return self.asset("console.html","text/html; charset=utf-8")
            if route=="/assets/console.js":
                return self.asset("console.js","text/javascript; charset=utf-8")
            if route=="/assets/console.css":
                return self.asset("console.css","text/css; charset=utf-8")
            if route=="/healthz":
                try:
                    ok=store.health()
                except Exception:
                    ok=False
                return self.reply(200 if ok else 503,{"status":"ok" if ok else "unavailable"})
            if route not in ("/api/me","/api/metrics","/api/audit","/api/restrictions","/api/users"):
                return self.reply(404,{"error":"not found"})
            try:
                token,principal=self.identity()
                if principal is None:
                    return self.reply(401,{"error":"unauthorized"})
                if route=="/api/me":
                    return self.reply(200,dict(tenant=principal.tenant_id,user=principal.user_id,
                                               role=principal.role,csrf=self.csrf(token)))
                perm=("manage_users" if route=="/api/users" else
                      "manage_restrictions" if route=="/api/restrictions" else
                      "view_metrics" if route=="/api/metrics" else "view_audit")
                if not can_access(principal,tenant_id=principal.tenant_id,permission=perm):
                    return self.reply(403,{"error":"forbidden"})
                result=(store.metrics(principal.tenant_id) if route=="/api/metrics"
                        else store.restrictions(principal) if route=="/api/restrictions"
                        else store.users(principal) if route=="/api/users"
                        else store.audit(principal.tenant_id))
                return self.reply(200,result)
            except Exception:
                return self.reply(503,{"error":"security policy unavailable"})

        def do_POST(self):
            route=urlsplit(self.path).path
            if route not in ("/api/login","/api/logout",
                             "/api/restrictions","/api/restrictions/revoke",
                             "/api/users", "/api/users/status"):
                return self.reply(404,{"error":"not found"})
            if not self.valid_origin():
                return self.reply(403,{"error":"origin rejected"})
            if route=="/api/login":
                try:
                    data=self.parse_json()
                    tenant,user,password=(data.get("tenant"),data.get("user"),data.get("password"))
                    if not all(isinstance(x,str) for x in (tenant,user,password)):
                        return self.reply(400,{"error":"invalid credentials"})
                    session=store.login(tenant=tenant,user=user,password=password)
                    if session is None:
                        return self.reply(401,{"error":"invalid credentials"})
                    token,principal=session
                    return self.reply(200,dict(tenant=principal.tenant_id,
                            user=principal.user_id,role=principal.role,csrf=self.csrf(token)),
                            f"{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/")
                except ValueError:
                    return self.reply(400,{"error":"invalid request"})
                except Exception:
                    return self.reply(503,{"error":"security policy unavailable"})
            try:
                token,principal=self.identity()
                if principal is None:
                    return self.reply(401,{"error":"unauthorized"})
                supplied=self.headers.get("X-CSRF-Token","")
                if not hmac.compare_digest(supplied,self.csrf(token)):
                    return self.reply(403,{"error":"csrf rejected"})
                if route in ("/api/users", "/api/users/status"):
                    if not can_access(principal, tenant_id=principal.tenant_id,
                                      permission="manage_users"):
                        return self.reply(403, {"error":"forbidden"})
                    try:
                        data = self.parse_json()
                        if route == "/api/users":
                            created = store.create_user(
                                principal, user=data.get("user"),
                                password=data.get("password"), role=data.get("role"))
                            return self.reply(201 if created else 409,
                                              {"created": created})
                        updated = store.set_user_active(
                            principal, user=data.get("user"),
                            active=data.get("active"))
                        return self.reply(200 if updated else 404,
                                          {"updated": updated})
                    except ValueError:
                        return self.reply(400, {"error":"invalid user management request"})
                    except PermissionError:
                        return self.reply(403, {"error":"forbidden"})
                if route in ("/api/restrictions", "/api/restrictions/revoke"):
                    if not can_access(principal, tenant_id=principal.tenant_id,
                                      permission="manage_restrictions"):
                        return self.reply(403, {"error":"forbidden"})
                    try:
                        data = self.parse_json()
                        subject = data.get("subject")
                        if route == "/api/restrictions":
                            result = store.restrict(principal, subject=subject,
                                                    minutes=data.get("minutes"))
                            return self.reply(200, result)
                        revoked = store.revoke_restriction(principal, subject=subject)
                        return self.reply(200, {"revoked": revoked})
                    except ValueError:
                        return self.reply(400, {"error":"invalid restriction request"})
                    except PermissionError:
                        return self.reply(403, {"error":"forbidden"})
                store.logout(token,principal)
                return self.reply(200,{"status":"signed out"},
                                  f"{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
            except Exception:
                return self.reply(503,{"error":"security policy unavailable"})
    return Handler


def main(argv=None):
    parser=argparse.ArgumentParser(description="DevShield loopback operations console")
    parser.add_argument("--host",default="127.0.0.1")
    parser.add_argument("--port",type=int,default=8877)
    parser.add_argument("--init-schema",action="store_true")
    parser.add_argument("--bootstrap-user")
    parser.add_argument("--bootstrap-tenant")
    parser.add_argument("--bootstrap-role",default="org_admin",
                       choices=["org_admin","operator","analyst","auditor"])
    args=parser.parse_args(argv)
    try:
        if not ipaddress.ip_address(args.host).is_loopback:
            parser.error("only loopback addresses supported")
    except ValueError:
        parser.error("host must be a loopback IP")
    dsn=os.environ.get("DEVSHIELD_POSTGRES_DSN")
    if not dsn:
        parser.error("DEVSHIELD_POSTGRES_DSN required")
    store=OpsStore(dsn)
    if args.init_schema:
        store.migrate()
    if args.bootstrap_user:
        password=os.environ.get("DEVSHIELD_BOOTSTRAP_PASSWORD")
        if not args.bootstrap_tenant or not password:
            parser.error("bootstrap requires tenant and DEVSHIELD_BOOTSTRAP_PASSWORD")
        created=store.provision_user(tenant=args.bootstrap_tenant,user=args.bootstrap_user,
                                     password=password,role=args.bootstrap_role)
        print("Created" if created else "Already exists")
        return
    with ThreadingHTTPServer((args.host,args.port),make_handler(store)) as server:
        print(f"DevShield console at http://{args.host}:{server.server_port}")
        server.serve_forever()


if __name__=="__main__":
    main()
