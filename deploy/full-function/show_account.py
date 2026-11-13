"""Local-only synthetic credential/OTP window. Never prints credentials or seeds."""
import argparse
import hashlib
import hmac
import json
import struct
import subprocess
import sys
import time
import tkinter as tk
from tkinter import messagebox
import uuid

import operate as full
import promotion_context as promotion


def read_account(alias, include_secret=False):
    """Read this owner's synthetic account; never configure Compose or fetch tokens."""
    context=promotion.Context('active')
    full.check(context.project==full.PROJECT=='zt-full-function-20261111b','Wrong profile')
    mysql=context.engine.name('mysql')
    row=context.engine.d.owned(mysql)
    full.check(row['State']['Running'],'Profile database is stopped')
    actor=json.loads((full.STATE/'accounts.json').read_text(encoding='utf-8'))[alias]
    expected_role='ADMIN' if alias=='admin' else 'STUDENT'
    full.check(actor['role']==expected_role,'Fixture role mismatch')
    subject=str(uuid.UUID(actor['id']))
    secret_field=(",'otp_secret',(SELECT c.SECRET_DATA FROM pd_staging_keycloak.CREDENTIAL c "
                  "WHERE c.USER_ID=u.ID AND c.TYPE='otp' LIMIT 1)") if include_secret else ''
    query=("SELECT JSON_OBJECT('username',u.USERNAME,'enabled',u.ENABLED,"
           "'roles',(SELECT GROUP_CONCAT(k.NAME) FROM pd_staging_keycloak.USER_ROLE_MAPPING m "
           "JOIN pd_staging_keycloak.KEYCLOAK_ROLE k ON k.ID=m.ROLE_ID WHERE m.USER_ID=u.ID),"
           "'otp_count',(SELECT COUNT(*) FROM pd_staging_keycloak.CREDENTIAL c WHERE c.USER_ID=u.ID AND c.TYPE='otp'),"
           "'otp_metadata',(SELECT c.CREDENTIAL_DATA FROM pd_staging_keycloak.CREDENTIAL c WHERE c.USER_ID=u.ID AND c.TYPE='otp' LIMIT 1),"
           "'recovery_count',(SELECT COUNT(*) FROM pd_staging_keycloak.CREDENTIAL c WHERE c.USER_ID=u.ID AND c.TYPE='recovery-authn-codes'),"
           "'required_actions',(SELECT GROUP_CONCAT(a.REQUIRED_ACTION) FROM pd_staging_keycloak.USER_REQUIRED_ACTION a WHERE a.USER_ID=u.ID),"
           "'server_time',UNIX_TIMESTAMP()"+secret_field+
           ") FROM pd_staging_keycloak.USER_ENTITY u JOIN pd_staging_keycloak.REALM r ON r.ID=u.REALM_ID "
           "WHERE r.NAME='DoAn' AND u.ID='"+subject+"'")
    result=subprocess.run(['docker','exec',mysql,'mysql','--defaults-extra-file=/fixture/root.cnf',
                           '--batch','--raw','--skip-column-names','--execute',query],
                          capture_output=True,timeout=20)
    full.check(result.returncode==0 and result.stdout.strip(),'Private account read failed')
    data=json.loads(result.stdout)
    roles=(data['roles'] or '').split(',')
    full.check(data['username']==actor['username'] and data['enabled'],'Fixture/account mismatch or disabled account')
    full.check(expected_role in roles and (expected_role=='ADMIN' or 'ADMIN' not in roles),'Unexpected account privileges')
    full.check(data['otp_count'] in (0,1),'Multiple OTP credentials require owner Authenticator selection')
    metadata=json.loads(data['otp_metadata']) if data['otp_count'] else None
    if metadata:
        full.check(metadata['subType']=='totp' and int(metadata['digits'])==6 and int(metadata['period'])==30
                   and metadata['algorithm']=='HmacSHA1','Unsupported OTP settings')
    seed=None
    if include_secret and data['otp_count']:
        seed=json.loads(data['otp_secret'])['value'].encode()
        full.check(bool(seed),'Empty synthetic OTP fixture')
    status={'project':full.PROJECT,'realm':'DoAn','alias':alias,'role':expected_role,
            'enabled':True,'roster_matches_database':True,'TOTP_configured':bool(data['otp_count']),
            'TOTP_supported':bool(metadata),'TOTP_enrollment_pending':'CONFIGURE_TOTP' in (data['required_actions'] or '').split(','),
            'recovery_credential_present':bool(data['recovery_count']),'runtime_actions':'SELECT_ONLY'}
    return actor,seed,float(data['server_time']),status


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account',choices=('admin','student_a','student_b'),default='admin')
    parser.add_argument('--check',action='store_true',help='Read-only status, never displays credentials or OTP')
    args=parser.parse_args()
    actor,seed,epoch,status=read_account(args.account,include_secret=not args.check)
    if args.check:
        print(json.dumps(status))
        return
    anchor=time.monotonic();expires=anchor+600
    root=tk.Tk();root.title('FULL-FUNCTION DoAn - private '+args.account)
    root.geometry('570x340');root.resizable(False,False);root.attributes('-topmost',True)
    root.update_idletasks();root.geometry('+%s+%s'%((root.winfo_screenwidth()-570)//2,(root.winfo_screenheight()-340)//2))
    tk.Label(root,text='FULL-FUNCTION SYNTHETIC / '+actor['role'],font=('Segoe UI',13,'bold')).pack(pady=12)
    for label,value,mask in [('Username',actor['username'],''),('Password',actor['password'],'*')]:
        row=tk.Frame(root);row.pack(fill='x',padx=20,pady=5)
        tk.Label(row,text=label,width=10,anchor='w').pack(side='left')
        entry=tk.Entry(row,width=53,show=mask);entry.insert(0,value);entry.configure(state='readonly');entry.pack(side='left')
        if mask:
            toggle=tk.BooleanVar(value=False)
            tk.Checkbutton(root,text='Show password privately',variable=toggle,command=lambda e=entry:e.configure(show='' if toggle.get() else '*')).pack()
    otp=tk.StringVar(value='Click Show OTP');remaining=tk.StringVar(value='No values are printed or written to a log.')
    enabled=tk.BooleanVar(value=False)
    tk.Checkbutton(root,text='Show current OTP privately',variable=enabled).pack(pady=5)
    tk.Label(root,textvariable=otp,font=('Consolas',28,'bold')).pack()
    tk.Label(root,textvariable=remaining,font=('Segoe UI',10)).pack()
    tk.Button(root,text='Close',command=root.destroy).pack(pady=8)
    def refresh():
        if time.monotonic()>=expires:root.destroy();return
        now=epoch+time.monotonic()-anchor
        if seed and enabled.get():
            digest=hmac.digest(seed,struct.pack('>Q',int(now)//30),'sha1');offset=digest[-1]&15
            otp.set(f'{(int.from_bytes(digest[offset:offset+4],"big")&0x7fffffff)%1000000:06d}')
            remaining.set('New code in '+str(30-int(now)%30)+' seconds. Closes automatically after 10 minutes.')
        else:otp.set('Click Show OTP' if seed else 'Enroll OTP in the browser');remaining.set('No OTP seed is displayed or exported.')
        root.after(250,refresh)
    refresh();root.lift();root.mainloop()


if __name__=='__main__':
    try:main()
    except Exception:
        text='Private account viewer could not open. Check Docker and this isolated profile. No credential values were logged.'
        if '--check' in sys.argv:
            print(json.dumps({'status':'NOT_VERIFIED','error':'Private account read failed; values withheld'}))
            sys.exit(1)
        try:
            error_root=tk.Tk();error_root.withdraw()
            messagebox.showerror('FULL-FUNCTION private account viewer',text,parent=error_root)
            error_root.destroy()
        except Exception:print(text)
        sys.exit(1)
