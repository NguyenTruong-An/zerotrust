const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// A DOM harness exercises rendering and interaction without opening a browser or accessing a network.
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.style = {}; this.events = {}; this._text = ""; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(" "); }
  set innerHTML(_) { throw new Error("Untrusted trace data must never be rendered with innerHTML"); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this._text = ""; this.children = nodes; }
  setAttribute(name, value) { this[name] = value; }
  addEventListener(name, handler) { this.events[name] = handler; }
  click() { this.events.click?.(); }
}

function fixture() {
  const detail = {model_version:"BASELINE_B0:1",risk_score:27.5,decision:"STEP_UP_MFA",
    calculated_level:"LOW",effective_level:"MEDIUM",decision_source:"MANDATORY_STEP_UP",
    mandatory_step_up_reason:"NEW_DEVICE",data_status:"COMPLETE",reason_codes:["NEW_DEVICE"],
    features:{device:{status:"AVAILABLE",score:60,weight:.25,contribution:15,inputs:{recognition_reason:"NOT_REGISTERED"}},
      network:{status:"AVAILABLE",score:50,weight:.25,contribution:12.5,
        inputs:{geoip_status:"AVAILABLE",country_code:"VN",city_name:'</script><img onerror="bad()">'}},
      temporal:{status:"AVAILABLE",score:0,weight:.25,contribution:0,inputs:{sample_size:20}},
      authentication_history:{status:"AVAILABLE",score:0,weight:.25,contribution:0,inputs:{subject_failures:0}}}};
  return {mode:"ILLUSTRATION",generated_at:"2026-11-02T03:00:00Z",malformed_rows:0,refresh_seconds:0,
    attempts:[{id:"attempt:demo",evaluation_id:"00000000-0000-0000-0000-000000000001",
      correlation_id:"00000000-0000-0000-0000-000000000002",at:"2026-11-02T03:00:00Z",
      risk:detail,detail,mfa:"OTP_EXECUTION_SUCCESS",login_outcome:"LOGIN_SUCCESS",gaps:[],
      events:[{at:"2026-11-02T03:00:01Z",stage:"AUTHENTICATION_EVENT",outcome:"LOGIN_SUCCESS",
        mfa_execution:"OTP_EXECUTION_SUCCESS"}]}]};
}

function run(report, extra = {}) {
  const template = fs.readFileSync(path.join(__dirname,"viewer.html"),"utf8");
  const elements = Object.fromEntries([...template.matchAll(/\bid="([^"]+)"/g)].map(m => [m[1],new Element("div")]));
  elements["report-data"].textContent = JSON.stringify(report);
  const context = {document:{getElementById:id=>elements[id],createElement:tag=>new Element(tag)},
    Intl,Date,Blob,URL,setTimeout:()=>{},location:{reload:()=>{}},
    sessionStorage:{getItem:()=>null,setItem:()=>{}},...extra};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,"viewer.js"),"utf8"),context);
  return elements;
}

test("renders numeric contributions, mandatory override and actual MFA evidence as text",()=>{
  const nodes=run(fixture());
  assert.match(nodes.detail.textContent,/27,5/);
  assert.match(nodes.detail.textContent,/NEW_DEVICE/);
  assert.match(nodes.detail.textContent,/OTP đã thực thi thành công/);
  assert.match(nodes.detail.textContent,/12,5/);
  assert.equal(nodes["demo-banner"].hidden,false);
  assert.match(nodes.detail.textContent,/<img onerror=/);
});

test("filter with no matches clears the previously selected evidence",()=>{
  const nodes=run(fixture());
  nodes.filter.value="DENY";
  nodes.filter.events.input();
  assert.equal(nodes.count.textContent,"0/1");
  assert.equal(nodes.download.disabled,true);
  assert.doesNotMatch(nodes.detail.textContent,/OTP đã thực thi thành công/);
});

test("incomplete scores remain unknown and missing MFA is not reported as success",()=>{
  const data=fixture(),a=data.attempts[0];
  a.risk.risk_score=null;
  a.risk.decision_source="INCOMPLETE_DATA";
  a.mfa="CHALLENGE_ONLY";
  a.login_outcome=null;
  a.events=[];
  a.gaps=["NO_MFA_COMPLETION_PROOF"];
  const nodes=run(data);
  assert.match(nodes.detail.textContent,/CHƯA CÓ ĐIỂM TỔNG/);
  assert.match(nodes.detail.textContent,/chưa có bằng chứng OTP\/recovery hoàn tất/);
  assert.doesNotMatch(nodes.detail.textContent,/OTP đã thực thi thành công/);
});

test("empty real capture is clearly distinguished from illustration",()=>{
  const data=fixture();
  data.mode="DOCKER_LOGS";
  data.attempts=[];
  const nodes=run(data);
  assert.equal(nodes["demo-banner"].hidden,true);
  assert.equal(nodes.download.disabled,true);
});

test("live mode patches new attempts in place without reloading and keeps the selection",async()=>{
  const data=fixture();data.mode="DOCKER_LOGS";data.refresh_seconds=5;
  const next=JSON.parse(JSON.stringify(data));next.generated_at="2026-11-02T03:00:05Z";
  const added=JSON.parse(JSON.stringify(data.attempts[0]));added.id="attempt:new";added.evaluation_id="00000000-0000-0000-0000-000000000009";
  next.attempts=[added,data.attempts[0]];
  const timers=[];let reloads=0;
  const nodes=run(data,{setTimeout:fn=>timers.push(fn),location:{protocol:"https:",reload:()=>reloads++},
    fetch:async()=>({ok:true,json:async()=>next})});
  assert.equal(nodes.count.textContent,"1/1");
  await timers.shift()();
  assert.equal(reloads,0);
  assert.equal(nodes.count.textContent,"2/2");
  assert.match(nodes.detail.textContent,/OTP đã thực thi thành công/);
  assert.equal(timers.length,1);
});

test("file:// snapshots keep the reload fallback",()=>{
  const data=fixture();data.refresh_seconds=5;
  const timers=[];let reloads=0;
  run(data,{setTimeout:fn=>timers.push(fn),location:{protocol:"file:",reload:()=>reloads++}});
  timers.shift()();
  assert.equal(reloads,1);
});
