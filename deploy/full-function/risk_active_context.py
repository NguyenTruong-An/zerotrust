"""Reviewed fixed context entry point. Default action is READ-ONLY preflight.

Selecting --context active does not grant mutation authority. No sign/enroll CLI.
"""
import argparse
import json
from pathlib import Path
import promotion_context as c
import risk_promotion as r


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',nargs='?',default='preflight',choices=('preflight','plan','status',*c.OPERATIONS))
    p.add_argument('--context',choices=('active','disposable'),default='active');p.add_argument('--request',type=Path)
    args=p.parse_args();ctx=c.Context(args.context)
    if args.action in ('preflight','plan'):result=ctx.preflight()
    elif args.action=='status':result=ctx.engine.validate()
    else:
        r.need(args.request is not None,'EXPLICIT_OPERATION_AUTHORIZATION_REQUIRED')
        result=getattr(ctx.engine,c.OPERATIONS[args.action])(r.json_bytes(args.request.read_bytes()))
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'status':'REJECTED','code':str(exc) if type(exc) is r.Rejected else type(exc).__name__}));raise SystemExit(1)
