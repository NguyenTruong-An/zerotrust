"""Proposed realm/account policy specification, not an importable realm or live readback."""
import copy
import re
from secret_contract import require
from urllib.parse import urlsplit

RISK_ROLES=["risk:evaluate","risk:device:write","risk:events:write"]
CLIENTS={
    "zerotrust-spa":{"publicClient":True,"standardFlowEnabled":True,"serviceAccountsEnabled":False,
                     "directAccessGrantsEnabled":False,"fullScopeAllowed":False,"pkce":"S256",
                     "roles":[],"realmManagementRoles":[],"secretRef":None},
    "zerotrust-risk-caller":{"publicClient":False,"standardFlowEnabled":False,"serviceAccountsEnabled":True,
                            "directAccessGrantsEnabled":False,"fullScopeAllowed":False,"roles":RISK_ROLES,
                            "realmManagementRoles":[],"secretRef":"risk-caller-client"},
    "zerotrust-portal-risk-admin":{"publicClient":False,"standardFlowEnabled":False,"serviceAccountsEnabled":True,
                                  "directAccessGrantsEnabled":False,"fullScopeAllowed":False,"roles":["risk:device:revoke"],
                                  "realmManagementRoles":[],"secretRef":"portal-risk-client"},
    "zerotrust-provisioner":{"publicClient":False,"standardFlowEnabled":False,"serviceAccountsEnabled":True,
                             "directAccessGrantsEnabled":False,"fullScopeAllowed":False,"roles":[],
                             "realmManagementRoles":["manage-users"],"secretRef":"portal-identity-client"},
}


def template():
    return {"not_a_realm_export":True,"registrationAllowed":False,"realmRoles":["ADMIN","STUDENT"],
            "portalOrigin":"https://portal.example.invalid","authOrigin":"https://auth.example.invalid",
            "redirectUris":["https://portal.example.invalid/","https://portal.example.invalid/silent-check-sso.html"],
            "webOrigins":["https://portal.example.invalid"],"clients":copy.deepcopy(CLIENTS),
            "demoAccounts":[{"alias":"demo-admin","role":"ADMIN"},{"alias":"demo-student-a","role":"STUDENT"},
                            {"alias":"demo-student-b","role":"STUDENT"}],
            "d10":"PENDING_OWNER_DECISION_CURRENT_ADMIN_RESET_UNCHANGED",
            "sessionEnrollmentRecoveryPolicy":"PENDING_OWNER_D10",
            "nativeFineGrainedAdminAcceptanceRequired":True}


def validate(c):
    try:
        expected=template()
        require(set(c)==set(expected))
        for key in expected.keys()-{"portalOrigin","authOrigin","redirectUris","webOrigins"}:
            require(c[key]==expected[key])
        for key in ("portalOrigin","authOrigin"):
            u=urlsplit(c[key]);require(u.scheme=="https" and u.hostname and u.path=="" and not u.username and not u.password and not u.query and not u.fragment)
            require(u.hostname!="localhost" and not u.hostname.startswith("127.") and "lab" not in u.hostname.lower() and "*" not in u.hostname and ":" not in u.hostname)
            require(u.hostname!="0.0.0.0" and re.fullmatch(r"[a-z0-9.-]+",u.hostname) is not None and (u.port is None or 1<=u.port<=65535))
        require(c["portalOrigin"]!=c["authOrigin"])
        require(c["redirectUris"]==[c["portalOrigin"]+"/",c["portalOrigin"]+"/silent-check-sso.html"])
        require(c["webOrigins"]==[c["portalOrigin"]])
    except Exception:
        raise ValueError("Public Demo account contract rejected (values redacted)") from None
    return c
