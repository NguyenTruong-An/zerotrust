import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import secret_contract as secrets
import account_contract as accounts
from test_configuration import fixture as data_fixture

MARKER="synthetic-PD06-secret-marker-never-log"
ROOT=Path(__file__).resolve().parents[2]


def deployment():
    c=data_fixture()
    for name,bindings in secrets.BINDINGS.items():
        service=c["services"].setdefault(name,{"environment":{}})
        service["secrets"]=[]
        for target,identifier in bindings.items():
            c["secrets"][identifier]={"file":"/srv/zerotrust-secrets/production/"+identifier}
            service["secrets"].append({"source":identifier,"target":target,"mode":"0400"})
    c["services"]["gateway"]["environment"].update(SPRING_PROFILES_ACTIVE="public-demo",PUBLIC_DEMO_MODE="public-demo",PUBLIC_DEMO_ACADEMIC_READ_ONLY="true",SPRING_CONFIG_IMPORT="configtree:/run/secrets/")
    c["services"]["keycloak"]["environment"].update(secrets.template()["keycloak_environment"])
    return c


class SecretContractTest(unittest.TestCase):
    def test_reference_only_policy_and_combined_data_deployment_preflight(self):
        c=json.loads((ROOT/"deploy/public-demo/secret-contract.json").read_text(encoding="utf-8"))
        secrets.validate(c)
        from validate_configuration import validate
        config=deployment();validate(config);secrets.validate_deployment(config)

    def test_missing_fields_modes_shared_sources_or_lab_paths_fail(self):
        for key in secrets.template():
            c=secrets.template();del c[key]
            with self.subTest(key=key),self.assertRaises(ValueError):secrets.validate(c)
        for field,value in (("mode","0444"),("mode","0600"),("file","/tmp/"+MARKER),("file","/srv/zerotrust-secrets/lab/old")):
            c=secrets.template();c["entries"]["school-db-runtime"][field]=value
            with self.assertRaises(ValueError) as error:secrets.validate(c)
            self.assertNotIn(MARKER,str(error.exception))

    def test_each_secret_mount_is_required_unique_and_owner_only(self):
        for name in secrets.BINDINGS:
            for mutation in ("missing","mode","shared","environment","build","shadow"):
                c=deployment();s=c["services"][name]
                if mutation=="missing":s["secrets"].pop()
                elif mutation=="mode":s["secrets"][0]["mode"]="0444"
                elif mutation=="shared":s["secrets"][0]["source"]="school-db-runtime"
                elif mutation=="environment":s["environment"]["CLIENT_SECRET"]=MARKER
                elif mutation=="build":s["build"]={"args":{"CLIENT_SECRET":MARKER}}
                else:s["volumes"]=[{"type":"bind","source":"/tmp/fixture","target":"/run","read_only":False}]
                if mutation=="shared" and name=="backend":continue
                with self.subTest(name=name,mutation=mutation),self.assertRaises(ValueError) as error:secrets.validate_deployment(c)
                self.assertNotIn(MARKER,str(error.exception))

    def test_browser_or_unknown_service_cannot_receive_credentials(self):
        c=deployment();c["services"]["frontend"]={"environment":{"NEXT_PUBLIC_CLIENT_SECRET":MARKER}}
        with self.assertRaises(ValueError):secrets.validate_deployment(c)

    def test_actual_synthetic_files_missing_empty_duplicate_and_size(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for index,identifier in enumerate(secrets.template()["entries"]):
                p=root/identifier;p.write_text(MARKER+str(index),encoding="utf-8");p.chmod(0o400)
            secrets.validate_files(secrets.template(),root)
            p=root/"school-db-runtime";p.chmod(0o600);p.write_text("short",encoding="utf-8");p.chmod(0o400)
            with self.assertRaises(ValueError) as error:secrets.validate_files(secrets.template(),root)
            self.assertNotIn(MARKER,str(error.exception))
            p.chmod(0o600);p.write_bytes((root/"portal-risk-client").read_bytes());p.chmod(0o400)
            with self.assertRaises(ValueError):secrets.validate_files(secrets.template(),root)
            # Windows owner-only POSIX mode acceptance is not asserted; native Linux checks remain required.
            for file in root.iterdir():file.chmod(0o600)

    def test_private_keycloak_config_requires_distinct_passwords_and_validate_only(self):
        text=("db-password="+MARKER+"-db\nhttps-key-store-password="+MARKER+"-tls\nhttp-enabled=false\nhostname-strict=true\n"
              "spi-connections-jpa--quarkus--migration-strategy=validate\nspi-connections-jpa--quarkus--initialize-empty=false\n")
        secrets.validate_keycloak_config(text)
        for modified in (text.replace(MARKER+"-tls",MARKER+"-db"),text.replace("=validate","=update"),text.replace("=false","=true"),text.replace("db-password=", "missing=")):
            with self.assertRaises(ValueError) as error:secrets.validate_keycloak_config(modified)
            self.assertNotIn(MARKER,str(error.exception))

    def test_account_roles_clients_redirects_and_d10_are_restricted(self):
        c=json.loads((ROOT/"deploy/public-demo/account-contract.json").read_text(encoding="utf-8"));accounts.validate(c)
        variants=[]
        for client in c["clients"]:
            for field,value in (("directAccessGrantsEnabled",True),("fullScopeAllowed",True),("roles",["risk:device:revoke","realm-admin"])):
                v=copy.deepcopy(c);v["clients"][client][field]=value;variants.append(v)
        for key,value in (("registrationAllowed",True),("realmRoles",["TEACHER"]),("redirectUris",["*"]),("webOrigins",["*"]),
                          ("d10","APPROVED"),("portalOrigin","https://user:"+MARKER+"@portal.invalid")):
            v=copy.deepcopy(c);v[key]=value;variants.append(v)
        v=copy.deepcopy(c);v["demoAccounts"][0]["password"]=MARKER;variants.append(v)
        for v in variants:
            with self.assertRaises(ValueError) as error:accounts.validate(v)
            self.assertNotIn(MARKER,str(error.exception))

    def test_duplicate_json_rejected_and_cli_failures_are_redacted(self):
        with self.assertRaises(ValueError):secrets.load_json('{"secret":"'+MARKER+'","secret":"second"}')
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"fixture.json";p.write_text('{"bad":"'+MARKER+'"}',encoding="utf-8")
            result=subprocess.run([os.sys.executable,str(ROOT/"scripts/public_demo/secret_contract.py"),str(p)],capture_output=True,text=True)
            self.assertEqual(1,result.returncode);self.assertNotIn(MARKER,result.stdout+result.stderr)

    def test_git_and_build_context_exclude_private_material(self):
        names=[".public-demo-private/fixture.env",".public-demo-private/tls.key"]
        result=subprocess.run(["git","check-ignore","--stdin","-z"],input=b"\0".join(n.encode() for n in names)+b"\0",cwd=ROOT,capture_output=True)
        self.assertEqual(set(names),set(result.stdout.decode().strip("\0").split("\0")))
        patterns=(ROOT/".dockerignore").read_text(encoding="utf-8").splitlines()
        for pattern in (".public-demo-private/","**/*.key","**/*.p12","**/.env*"):self.assertIn(pattern,patterns)

    def test_combined_cli_checks_rendered_deployment_without_reading_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"deployment.json";p.write_text(json.dumps(deployment()),encoding="utf-8")
            args=[os.sys.executable,str(ROOT/"scripts/public_demo/secret_contract.py"),str(ROOT/"deploy/public-demo/secret-contract.json"),"--deployment-json",str(p)]
            result=subprocess.run(args,capture_output=True,text=True);self.assertEqual(0,result.returncode,result.stdout+result.stderr)
            c=deployment();c["services"]["backend"]["environment"]["CLIENT_SECRET"]=MARKER;p.write_text(json.dumps(c),encoding="utf-8")
            result=subprocess.run(args,capture_output=True,text=True);self.assertEqual(1,result.returncode);self.assertNotIn(MARKER,result.stdout+result.stderr)

    def test_redis_acl_covers_existing_lua_and_denies_broad_commands_keys(self):
        import re,hashlib
        source=(ROOT/"deploy/public-demo/redis-acl-contract.conf").read_text(encoding="utf-8")
        rendered=source.replace("__REQUIRED_RISK_REDIS_PASSWORD_SHA256__",hashlib.sha256(MARKER.encode()).hexdigest())
        secrets.validate_redis_config(rendered)
        lua=(ROOT/"risk-scoring-service/src/main/java/com/zerotrust/risk/repository/RedisAuthenticationFailureStore.java").read_text(encoding="utf-8")
        self.assertLessEqual({c.lower() for c in re.findall(r"redis.call\('([^']+)'",lua)},secrets.REDIS_COMMANDS)
        for changed in (source,rendered.replace("-@all","+@all"),rendered.replace("~zerotrust:risk:auth-history:*","~*"),
                        rendered+"\nuser unsafe on nopass +@all ~*\n",rendered+" +flushall"):
            with self.assertRaises(ValueError) as error:secrets.validate_redis_config(changed)
            self.assertNotIn(MARKER,str(error.exception))


if __name__=="__main__":unittest.main()
