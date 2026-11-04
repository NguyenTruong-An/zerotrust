"use strict";
(() => {
  const report = JSON.parse(document.getElementById("report-data").textContent);
  const $ = id => document.getElementById(id);
  const el = (tag, content, cls) => {
    const node = document.createElement(tag);
    if (content != null) node.textContent = content;
    if (cls) node.className = cls;
    return node;
  };
  const fmt = value => value == null ? "Chưa quan sát" : typeof value === "number" ?
    new Intl.NumberFormat("vi-VN", {maximumFractionDigits: 4}).format(value) : String(value);
  const short = value => value ? value.slice(0, 8) : "Không có mã đánh giá";
  const clock = at => at ? new Date(at).toLocaleTimeString("vi-VN", {hour12: false}) : "—";
  const decision = value => ({ALLOW: "Cho phép", STEP_UP_MFA: "Yêu cầu MFA", DENY: "Từ chối"})[value] || "Chưa có quyết định";
  const tone = value => value === "ALLOW" ? "good" : value === "DENY" ? "bad" : value === "STEP_UP_MFA" ? "warn" : "";
  const pill = (value, cls = "") => el("span", value, "pill " + cls);
  const featureNames = {device: "Thiết bị", network: "Mạng", temporal: "Thời gian", authentication_history: "Lịch sử"};
  const codes = {device: "D", network: "N", temporal: "T", authentication_history: "H"};
  const labels = {
    recognition_reason:"Lý do nhận diện", recognition_source:"Nguồn nhận diện", ip_source:"Nguồn địa chỉ",
    address_scope:"Phạm vi địa chỉ", geoip_status:"Tra cứu GeoIP", policy_band:"Mức chính sách",
    unavailable_reason:"Lý do thiếu dữ liệu", country_code:"Mã quốc gia", city_name:"Thành phố (tham khảo)",
    geoip_time_zone:"Múi giờ GeoIP (tham khảo)", accuracy_radius_km:"Bán kính sai số (km)",
    asn:"ASN (tham khảo)", asn_organization:"Tổ chức mạng (tham khảo)", geoip_scoring_field:"Trường GeoIP dùng tính điểm",
    history_source:"Nguồn lịch sử", evaluated_at:"Thời điểm đánh giá", zone_id:"Múi giờ tính T",
    history_window_seconds:"Khoảng lịch sử (giây)", minimum_events:"Số mẫu tối thiểu", maximum_events:"Giới hạn số mẫu",
    sample_size:"Số mẫu thực có", day_of_week:"Thứ (1=T2, 7=CN)", hour:"Giờ đánh giá", hour_tolerance:"Dung sai giờ",
    matching_days:"Số mẫu khớp thứ", matching_hours:"Số mẫu khớp giờ", minimum_day_frequency:"Tần suất ngày tối thiểu",
    minimum_hour_frequency:"Tần suất giờ tối thiểu", subject_failures:"Thất bại theo tài khoản",
    source_ip_failures:"Thất bại theo IP", subject_medium_minimum:"Ngưỡng tài khoản MEDIUM",
    subject_high_minimum:"Ngưỡng tài khoản HIGH", source_ip_medium_minimum:"Ngưỡng IP MEDIUM",
    source_ip_high_minimum:"Ngưỡng IP HIGH", failure_window_seconds:"TTL bộ đếm (giây)",
    window_semantics:"Cơ chế cửa sổ đếm", aggregation:"Cách tổng hợp điểm H"
  };
  const values = {
    AVAILABLE:"Có dữ liệu", COLD_START:"Chưa đủ lịch sử", UNAVAILABLE:"Không lấy được dữ liệu",
    NOT_OBSERVED:"Chưa quan sát", NOT_REGISTERED:"Chưa đăng ký thiết bị", MISSING_IDENTIFIER:"Thiếu cookie thiết bị",
    TRUSTED:"Đã tin cậy", PENDING:"Đang chờ", SECURITY_REVOKED:"Đã thu hồi vì bảo mật",
    TRUST_EXPIRED:"Đã hết hạn tin cậy", MFA_RESET:"Đã reset MFA", REAUTHENTICATION_REQUIRED:"Cần xác thực lại",
    PUBLIC:"Public", NON_PUBLIC:"Không public", SKIPPED_NETWORK_DISABLED:"Bỏ qua: Network bị tắt",
    SKIPPED_CIDR_MATCH:"Bỏ qua: đã khớp CIDR", SKIPPED_GEOIP_DISABLED:"Bỏ qua: GeoIP bị tắt",
    SKIPPED_NON_PUBLIC:"Bỏ qua: IP không public", COUNTRY_MISSING:"Record thiếu mã quốc gia",
    NOT_FOUND:"Không tìm thấy record", DISABLED:"Đã tắt", INVALID_IP:"IP không hợp lệ",
    COUNTER_TTL_FROM_FIRST_FAILURE:"TTL từ lần thất bại đầu tiên",
    MAX_ACCOUNT_AND_IP_RISK:"Lấy điểm lớn hơn giữa tài khoản và IP", COUNTRY_CODE:"Mã quốc gia",
    SUCCESS_EVENTS_MYSQL:"Sự kiện LOGIN trong MySQL", FAILURE_COUNTERS_REDIS:"Bộ đếm LOGIN_ERROR trong Redis",
    DEVICE_COOKIE_AND_SERVER_RECORD:"Cookie thiết bị + bản ghi server",
    KEYCLOAK_REMOTE_ADDRESS:"Địa chỉ kết nối Keycloak nhìn thấy",
    RISK_REQUEST_IP_ADDRESS:"Trường ipAddress trong request Risk"
  };
  const friendly = value => value == null ? "Chưa quan sát" : values[value] || fmt(value);
  const outcomes = {
    EVALUATED:"Risk đã đánh giá", STEP_UP_REQUIRED:"Keycloak yêu cầu MFA",
    RISK_STEP_PASSED:"Đi qua bước kiểm tra Risk/MFA", ACCESS_DENIED:"Keycloak từ chối truy cập",
    SERVICE_UNAVAILABLE_DENY:"Risk unavailable · chặn theo cấu hình",
    SERVICE_UNAVAILABLE_STEP_UP:"Risk unavailable · chuyển MFA theo cấu hình",
    MFA_SUBFLOW_SELECTED:"Đã chọn luồng MFA", MFA_SUBFLOW_NOT_SELECTED:"Không chọn luồng MFA",
    MFA_DEFERRED_TO_REQUIRED_ACTION:"Chuyển sang bước đăng ký OTP bắt buộc",
    CHALLENGE_RENDERED:"Đã hiển thị màn hình MFA", MFA_INPUT_REJECTED:"Đầu vào MFA bị từ chối",
    REGISTERED_204:"Risk xác nhận đăng ký thiết bị (204)", COOKIE_ISSUED:"Đã cấp cookie thiết bị",
    ENROLLMENT_PENDING:"Đang chờ đăng ký OTP", NOT_ELIGIBLE:"Chưa đủ điều kiện đăng ký thiết bị",
    REGISTRATION_REJECTED:"Đăng ký thiết bị bị từ chối",
    REGISTRATION_UNAVAILABLE:"Dịch vụ đăng ký thiết bị unavailable", REGISTRATION_ERROR:"Lỗi đăng ký thiết bị",
    LOGIN_SUCCESS:"Đăng nhập thành công", LOGIN_ERROR:"Sự kiện đăng nhập lỗi", SSO_COOKIE_LOGIN:"Đăng nhập qua SSO cookie",
    REFRESH_SUCCESS_NO_BROWSER_FLOW:"Refresh thành công · không chạy Browser Flow",
    REFRESH_ERROR_NO_BROWSER_FLOW:"Refresh lỗi · không chạy Browser Flow",
    RISK_RESPONSE_RECEIVED:"Đã nhận phản hồi Risk", RISK_CALL_FAILED:"Lời gọi Risk thất bại"
  };
  const mfaLabels = {
    OTP_EXECUTION_SUCCESS:"OTP đã thực thi thành công", RECOVERY_EXECUTION_SUCCESS:"Recovery code đã thực thi thành công",
    CHALLENGE_ONLY:"Đã hiện MFA; chưa thấy hoàn tất", ENROLLMENT_PENDING:"Đang chờ đăng ký OTP",
    NOT_SELECTED:"Luồng MFA không được chọn", NOT_OBSERVED:"Chưa quan sát được hoàn tất MFA"
  };
  const gapLabels = {
    CONFLICTING_IDS_OR_DETAILS:"Có mã/bản ghi mâu thuẫn; không ghép phần giải thích Risk vào lần này.",
    NO_RISK_DETAILS:"Chưa có Risk Score Trace tương ứng. Kiểm tra bản chạy hoặc khoảng thời gian lấy log.",
    NO_SIGNAL_INPUTS:"Trace có điểm nhưng chưa có đầu vào chi tiết; có thể là phiên bản trace cũ.",
    NO_SPI_CORRELATION:"Chưa có mã nối với luồng Keycloak; bản ghi được giữ riêng.",
    NO_FINAL_LOGIN_EVENT:"Chưa quan sát được sự kiện kết thúc đăng nhập.",
    NO_MFA_COMPLETION_PROOF:"Risk yêu cầu MFA nhưng chưa có bằng chứng OTP/recovery hoàn tất."
  };
  let saved = {};
  try { saved = JSON.parse(sessionStorage.getItem("zt-observation") || "{}"); } catch (_) { /* Storage may be disabled. */ }
  let selected = report.attempts.find(a => a.id === saved.id) || report.attempts[0];
  $("search").value = saved.search || "";
  $("filter").value = saved.filter || "ALL";
  $("mode").textContent = ({ILLUSTRATION:"MINH HỌA", DOCKER_LOGS:"LOG DOCKER", IMPORTED_LOGS:"LOG NHẬP TỪ FILE"})[report.mode] || report.mode;
  $("generated").textContent = "Cập nhật " + new Date(report.generated_at).toLocaleString("vi-VN") +
    (report.refresh_seconds ? " · Theo dõi " + report.refresh_seconds + "s" : " · Bản chụp");
  $("demo-banner").hidden = report.mode !== "ILLUSTRATION";
  const metrics = [
    [report.attempts.length,"Lần / sự kiện được quan sát"],
    [report.attempts.filter(a => a.detail).length,"Có bản giải thích Risk"],
    [report.attempts.filter(a => a.risk.decision === "STEP_UP_MFA").length,"Quyết định yêu cầu MFA"],
    [report.attempts.filter(a => a.mfa.endsWith("EXECUTION_SUCCESS")).length,"Có bằng chứng hoàn tất MFA"]
  ];
  for (const [value, label] of metrics) {
    const box = el("div", null, "metric");
    box.append(el("span", label), el("strong", fmt(value)));
    $("metrics").append(box);
  }
  function remember() {
    try { sessionStorage.setItem("zt-observation", JSON.stringify({id:selected?.id, search:$("search").value, filter:$("filter").value})); } catch (_) {}
  }
  function kv(data) {
    const dl = el("dl", null, "kv");
    for (const [key, value] of Object.entries(data || {})) dl.append(el("dt", labels[key] || key), el("dd", friendly(value)));
    return dl;
  }
  function panel(title, caption) {
    const box = el("div", null, "panel"), head = el("div", null, "section-title");
    head.append(el("h3", title));
    if (caption) head.append(el("p", caption));
    box.append(head);
    return box;
  }
  function renderList() {
    const q = $("search").value.trim().toLowerCase(), filter = $("filter").value;
    const visible = report.attempts.filter(a =>
      [a.evaluation_id, a.correlation_id, a.id].join(" ").toLowerCase().includes(q) &&
      (filter === "ALL" || (a.risk.decision || "NO_DECISION") === filter));
    if (!visible.some(a => a.id === selected?.id)) {
      selected = visible[0];
      renderDetail();
      remember();
    }
    $("count").textContent = visible.length + "/" + report.attempts.length;
    $("attempts").replaceChildren();
    for (const a of visible) {
      const button = el("button", null, "attempt" + (a.id === selected?.id ? " selected" : ""));
      button.type = "button";
      button.setAttribute("aria-pressed", String(a.id === selected?.id));
      const head = el("div", null, "attempt-head");
      head.append(pill(decision(a.risk.decision), tone(a.risk.decision)), el("span", clock(a.at), "attempt-time"));
      button.append(head, el("div", short(a.evaluation_id || a.correlation_id), "attempt-id"));
      button.addEventListener("click", () => { selected = a; remember(); renderList(); renderDetail(); });
      $("attempts").append(button);
    }
    if (!visible.length) $("attempts").append(el("p", "Không có bản ghi phù hợp bộ lọc.", "subtle"));
  }
  function explain(a) {
    const r = a.risk;
    if (r.decision_source === "MANDATORY_STEP_UP") return "Điểm theo ngưỡng thuộc " + (r.calculated_level || "chưa rõ") +
      ", nhưng quy tắc " + (r.mandatory_step_up_reason || "bắt buộc MFA") + " yêu cầu xác thực bổ sung.";
    if (r.decision_source === "INCOMPLETE_DATA") return "Dữ liệu chưa đầy đủ. Điểm tổng để trống; hệ thống yêu cầu MFA theo quy tắc dữ liệu thiếu.";
    if (r.decision_source === "PRIORITY_RULE") return "Quy tắc chặn ưu tiên đã quyết định DENY. Không có phép cộng điểm tổng cho lần này.";
    if (a.events.some(e => e.outcome?.startsWith("SERVICE_UNAVAILABLE"))) return "Không nhận được đánh giá Risk hợp lệ. Keycloak áp dụng chế độ xử lý sự cố; không tạo điểm Risk thay thế.";
    if (r.decision_source === "SCORE_THRESHOLD") return "Quyết định dựa trên điểm tổng và ngưỡng của mô hình được ghi trong trace.";
    return "Chưa có đủ bản ghi để giải thích đầy đủ quyết định. Xem các bước thực sự quan sát được bên dưới.";
  }
  function renderDetail() {
    const a = selected;
    if (!a) {
      const empty = panel("Chưa có bản ghi phù hợp", "Đăng nhập rồi cập nhật log, hoặc thay bộ lọc.");
      empty.append(el("p", "Trang giữ nguyên trạng thái chưa có bằng chứng, không tự tạo điểm hoặc kết quả MFA.", "subtle"));
      $("detail").replaceChildren(empty);
      $("download").disabled = true;
      return;
    }
    $("detail").replaceChildren();
    $("download").disabled = false;
    const r = a.risk, d = a.detail;
    const summary = el("div", null, "panel summary"), top = el("div", null, "summary-top"), left = el("div");
    left.append(pill(r.model_version || "Chưa có phiên bản mô hình", "blue"), el("h3", decision(r.decision)),
      el("div", explain(a), "summary-text"));
    const right = el("div"), score = el("div", r.risk_score == null ? "—" : fmt(r.risk_score), "score");
    score.append(el("small", " / 100"));
    right.append(score, el("div", r.risk_score == null ? "CHƯA CÓ ĐIỂM TỔNG" : "RISK SCORE", "score-label"));
    if (r.trust_score != null) right.append(el("div", "Trust quy đổi: " + fmt(r.trust_score) + " (100 − Risk)", "score-label"));
    top.append(left, right);
    summary.append(top);
    const tags = el("div", null, "reason-tags");
    if (r.data_status) tags.append(pill(r.data_status));
    if (r.calculated_level) tags.append(pill("Theo điểm: " + r.calculated_level));
    if (r.effective_level) tags.append(pill("Hiệu lực: " + r.effective_level));
    for (const reason of r.reason_codes || []) tags.append(pill(reason));
    summary.append(tags);
    const ids = el("div", null, "ids");
    ids.append(el("span", "Evaluation: " + (a.evaluation_id || "chưa có")), el("span", "Correlation: " + (a.correlation_id || "chưa có")));
    summary.append(ids);
    $("detail").append(summary);
    if (a.gaps.length || report.malformed_rows) {
      const note = el("div", null, "notice"), list = el("ul");
      note.append(el("strong", "Giới hạn bằng chứng của bản đang xem"));
      for (const gap of a.gaps) list.append(el("li", gapLabels[gap] || gap));
      if (report.malformed_rows) list.append(el("li", report.malformed_rows + " dòng trace không hợp lệ đã được bỏ qua."));
      note.append(list);
      $("detail").append(note);
    }
    const featurePanel = panel("Tín hiệu và đóng góp vào điểm", "Các con số được ghi tại thời điểm tính toán");
    if (d?.features) {
      const wrap = el("div", null, "table-wrap"), table = el("table"), thead = el("thead"), heading = el("tr");
      for (const h of ["NHÓM", "TRẠNG THÁI / NGUỒN", "ĐIỂM", "TRỌNG SỐ", "ĐÓNG GÓP"]) heading.append(el("th", h));
      thead.append(heading);
      table.append(thead);
      const body = el("tbody");
      for (const [name, title] of Object.entries(featureNames)) {
        const f = d.features[name] || {}, tr = el("tr"), nameCell = el("td"), state = el("td");
        nameCell.append(el("span", codes[name], "factor-code"), el("span", title, "factor-title"));
        state.append(pill(friendly(f.status), f.status === "AVAILABLE" ? "good" : "warn"));
        if (f.source) state.append(el("div", f.source, "source"));
        tr.append(nameCell, state, el("td", fmt(f.score), "num"), el("td", fmt(f.weight), "num"));
        const contribution = el("td", fmt(f.contribution), "num");
        if (typeof f.contribution === "number") {
          const bar = el("div", null, "bar"), fill = el("div", null, "bar-fill");
          fill.style.width = Math.max(0, Math.min(100, f.contribution)) + "%";
          bar.append(fill);
          contribution.append(bar);
        }
        tr.append(contribution);
        body.append(tr);
      }
      table.append(body);
      wrap.append(table);
      featurePanel.append(wrap);
      if (r.policy_thresholds) featurePanel.append(el("p", "Ngưỡng MEDIUM: " + fmt(r.policy_thresholds.medium_minimum) +
        " · HIGH: " + fmt(r.policy_thresholds.high_minimum) + ". Tổng được làm tròn HALF_UP đến 2 chữ số.", "muted-note"));
      if (r.risk_interval) featurePanel.append(el("p", "Khoảng Risk khi thiếu dữ liệu: " +
        r.risk_interval.map(fmt).join(" – ") + ". Đây là khoảng giới hạn, không phải điểm tổng đã tính.", "muted-note"));
      const signals = el("div", null, "signal-grid");
      for (const [name, title] of Object.entries(featureNames)) {
        const box = el("div", null, "signal"), inputs = d.features[name]?.inputs;
        box.append(el("h4", codes[name] + " · " + title));
        box.append(inputs && Object.keys(inputs).length ? kv(inputs) : el("p", "Chưa có đầu vào chi tiết cho nhóm này.", "subtle"));
        signals.append(box);
      }
      featurePanel.append(signals);
      if (r.user_agent_used_for_scoring === false) featurePanel.append(el("p",
        "User-Agent được thu trong ngữ cảnh nhưng chưa tham gia chấm điểm. Trace không xuất chuỗi User-Agent.", "muted-note"));
    } else featurePanel.append(el("p", r.data_status === "NOT_EVALUATED" ?
      "Không có bảng điểm vì quy tắc chặn ưu tiên kết thúc đánh giá." : "Chưa có bảng D/N/T/H tương ứng trong log Risk.", "subtle"));
    $("detail").append(featurePanel);
    const pair = el("div", null, "two-col"), geo = panel("GeoIP", "Thông tin lấy từ MMDB cục bộ");
    const n = d?.features?.network?.inputs;
    geo.append(pill(friendly(n?.geoip_status), n?.geoip_status === "AVAILABLE" ? "good" : ""),
      el("div", n?.country_code || "—", "geo-number"), el("p", n?.city_name || "Chưa có thông tin thành phố", "subtle"));
    geo.append(kv({asn:n?.asn, asn_organization:n?.asn_organization, geoip_scoring_field:n?.geoip_scoring_field, policy_band:n?.policy_band}));
    geo.append(el("p", "Thành phố và ASN là dữ liệu tham khảo. Không tra cứu lại chỉ để điền bảng; nhánh CIDR có thể bỏ qua GeoIP.", "muted-note"));
    const result = panel("MFA và kết quả cuối", "Bằng chứng thực thi từ Keycloak");
    const resultRows = [
      ["MFA", mfaLabels[a.mfa] || a.mfa, a.mfa.endsWith("EXECUTION_SUCCESS") ? "good" : "warn"],
      ["Đăng nhập", outcomes[a.login_outcome] || "Chưa có sự kiện kết thúc", a.login_outcome === "LOGIN_SUCCESS" ? "good" : ""],
      ["Đăng ký thiết bị", a.device_registered ? "Đã thấy xác nhận 204" : "Chưa thấy xác nhận", a.device_registered ? "good" : ""],
      ["Cookie thiết bị", a.cookie_issued ? "Đã thấy sự kiện cấp cookie" : "Chưa thấy sự kiện cấp cookie", ""]
    ];
    for (const [label, value, cls] of resultRows) {
      const row = el("div", null, "outcome-item");
      row.append(el("span", label), pill(value, cls));
      result.append(row);
    }
    pair.append(geo, result);
    $("detail").append(pair);
    const timeline = panel("Diễn biến lần xác thực", a.events.length + " bản ghi được ghép theo mã"), list = el("ol", null, "timeline");
    for (const e of a.events) {
      const li = el("li"), content = el("div");
      const title = e.stage === "RISK_EVALUATION_DETAILS" ? "Risk ghi bản giải thích điểm" : outcomes[e.outcome] || e.stage;
      content.append(el("h4", title), el("p", e.stage + (e.outcome ? " · " + e.outcome : "") +
        (e.mfa_execution ? " · " + e.mfa_execution : "")));
      li.append(el("time", clock(e.at)), el("span", null, "dot " +
        (e.mfa_execution?.endsWith("EXECUTION_SUCCESS") ? "good" : "")), content);
      list.append(li);
    }
    timeline.append(list);
    if (r.numeric_config_digest) timeline.append(el("p", "Dấu vân tay cấu hình số: " + r.numeric_config_digest, "muted-note"));
    $("detail").append(timeline);
  }
  for (const id of ["search", "filter"]) $(id).addEventListener("input", () => { remember(); renderList(); });
  $("download").addEventListener("click", () => {
    if (!selected) return;
    const blob = new Blob([JSON.stringify({mode:report.mode, generated_at:report.generated_at, attempt:selected}, null, 2)], {type:"application/json"});
    const url = URL.createObjectURL(blob), link = el("a");
    link.href = url;
    link.download = "risk-" + short(selected.evaluation_id || selected.correlation_id) + ".private.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  renderList();
  renderDetail();
  if (report.refresh_seconds) setTimeout(() => { remember(); location.reload(); }, report.refresh_seconds * 1000);
})();
