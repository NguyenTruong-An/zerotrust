document.addEventListener("DOMContentLoaded", () => {
  if (!document.body) return;
  const vi = (document.documentElement.lang || "vi").toLowerCase().startsWith("vi");
  const copy = vi ? {
    portal: "Cổng học vụ", eyebrow: "Không gian học tập của bạn",
    title: "Kết nối học tập.\nAn tâm truy cập.",
    introduction: "Truy cập thông tin học tập và quản lý học vụ trong một không gian thống nhất.",
    benefits: ["Một tài khoản cho Cổng học vụ", "Xác thực thêm khi cần bảo vệ tài khoản", "Khôi phục truy cập bằng mã dự phòng"],
    sideFooter: "Giữ mật khẩu và mã xác thực cho riêng bạn. Quản trị viên không yêu cầu bạn cung cấp mã OTP.",
    login: ["Đăng nhập", "Sử dụng tài khoản được cấp để tiếp tục vào Cổng học vụ."],
    otp: ["Xác thực tài khoản", "Mở ứng dụng xác thực và nhập mã OTP hiện tại để tiếp tục."],
    setup: ["Thiết lập xác thực", "Thêm tài khoản vào ứng dụng xác thực, sau đó nhập mã để xác nhận."],
    recovery: ["Khôi phục truy cập", "Sử dụng mã dự phòng được yêu cầu. Mỗi mã chỉ dùng được một lần."],
    recoverySetup: ["Lưu mã dự phòng", "Lưu các mã này ở nơi an toàn để dùng khi bạn không truy cập được ứng dụng xác thực."],
    error: ["Hỗ trợ truy cập", "Xem thông báo bên dưới để biết bước tiếp theo."],
    other: ["Xác thực tài khoản", "Hoàn tất bước này để tiếp tục vào Cổng học vụ."],
    otpHint: "Dùng mã mới nhất khi mã trong ứng dụng vừa thay đổi.",
  } : {
    portal: "Academic Portal", eyebrow: "Your learning space",
    title: "Stay connected.\nSign in with confidence.",
    introduction: "Access your academic information and manage learning in one connected space.",
    benefits: ["One account for the Academic Portal", "Additional verification when needed", "Recovery codes to restore access"],
    sideFooter: "Keep your password and verification codes private. Administrators will never ask you to share an OTP.",
    login: ["Sign in", "Use your assigned account to continue to the Academic Portal."],
    otp: ["Verify your account", "Open your authenticator app and enter the current code to continue."],
    setup: ["Set up verification", "Add this account to your authenticator app, then enter a code to confirm."],
    recovery: ["Restore access", "Enter the requested recovery code. Each code can only be used once."],
    recoverySetup: ["Save recovery codes", "Store these codes safely for when you cannot access your authenticator app."],
    error: ["Access assistance", "Review the message below for your next step."],
    other: ["Account verification", "Complete this step to continue to the Academic Portal."],
    otpHint: "Use the latest code if your app has just generated a new one.",
  };
  const create = (tag, className, text) => {
    const element = document.createElement(tag);
    element.className = className;
    if (text) element.textContent = text;
    return element;
  };
  const shield = () => {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", "24"); svg.setAttribute("height", "24");
    svg.setAttribute("fill", "none"); svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.6"); svg.setAttribute("aria-hidden", "true");
    const path = document.createElementNS(svg.namespaceURI, "path");
    path.setAttribute("d", "M12 3 4.5 6v5c0 4.7 3.2 8.1 7.5 10 4.3-1.9 7.5-5.3 7.5-10V6L12 3Z M8.5 12l2.4 2.4 4.6-4.8");
    path.setAttribute("stroke-linecap", "round"); path.setAttribute("stroke-linejoin", "round");
    svg.append(path);
    return svg;
  };
  const container = document.querySelector(".pf-v5-c-login__container");
  const main = document.querySelector(".pf-v5-c-login__main");
  if (container && main && !container.querySelector(".zt-intro")) {
    const intro = create("aside", "zt-intro");
    const brand = create("div", "zt-brand");
    const mark = create("span", "zt-brand-mark"); mark.append(shield());
    const brandText = create("div", "");
    brandText.append(create("strong", "", "ZeroTrust"), create("small", "", copy.portal));
    brand.append(mark, brandText);
    const content = create("div", "zt-intro-content");
    const title = create("h2", "");
    copy.title.split("\n").forEach((line, index) => {
      if (index) title.append(document.createElement("br"));
      title.append(document.createTextNode(line));
    });
    const benefits = create("ul", "zt-benefits");
    copy.benefits.forEach(text => {
      const item = create("li", "");
      const icon = create("span", "zt-benefit-icon", "✓"); icon.setAttribute("aria-hidden", "true");
      item.append(icon, document.createTextNode(text)); benefits.append(item);
    });
    content.append(create("p", "zt-eyebrow", copy.eyebrow), title, create("p", "zt-intro-description", copy.introduction), benefits);
    intro.append(brand, content, create("p", "zt-intro-footer", copy.sideFooter));
    container.insertBefore(intro, main);
  }
  const pageId = document.body.dataset.pageId || "";
  const pageCopy = pageId.includes("recovery-authn-code-config") ? copy.recoverySetup
    : pageId.includes("recovery-authn-code-input") ? copy.recovery
    : pageId.includes("config-totp") ? copy.setup
    : pageId.includes("otp") ? copy.otp
    : pageId.includes("error") || pageId.includes("expired") ? copy.error
    : pageId === "login-login" ? copy.login : copy.other;
  const header = document.querySelector(".pf-v5-c-login__main-header");
  if (pageId.includes("otp") && !pageId.includes("config-totp")) {
    const heading = document.querySelector("#kc-page-title");
    if (heading) heading.textContent = vi ? "Xác thực bằng OTP" : "Verify with a one-time code";
  }
  if (main && !main.querySelector(".zt-form-kicker")) main.prepend(create("p", "zt-form-kicker", pageCopy[0]));
  if (header && !header.querySelector(".zt-page-description")) header.append(create("p", "zt-page-description", pageCopy[1]));
  document.querySelectorAll("#otp, #totp").forEach(input => {
    input.setAttribute("inputmode", "numeric");
    input.closest(".pf-v5-c-form-control")?.classList.add("zt-otp-field");
    if (input.id === "otp" && !input.closest(".pf-v5-c-form__group")?.querySelector(".zt-otp-hint")) {
      input.closest(".pf-v5-c-form__group")?.append(create("p", "zt-otp-hint", copy.otpHint));
    }
  });
  // The inherited setup template has legacy label targets; keep its real inputs accessible.
  document.querySelectorAll("#kc-totp-settings-form .pf-v5-c-form__group").forEach(group => {
    const input = group.querySelector("input:not([type='hidden'])");
    const label = group.querySelector("label");
    if (input?.id && label) label.htmlFor = input.id;
  });
  document.querySelector("#printRecoveryCodes")?.parentElement.classList.add("zt-recovery-actions");
  if (pageId.includes("recovery-authn-code-config") && vi) {
    const warning = document.querySelector("[aria-label='Warning alert']");
    warning?.setAttribute("aria-label", "Cảnh báo");
    const prefix = warning?.querySelector(".pf-screen-reader");
    if (prefix) prefix.textContent = "Cảnh báo: ";
  }

  const lockout = document.querySelector(".zt-lockout[data-remaining-seconds]");
  if (lockout) {
    const seconds = Number(lockout.dataset.remainingSeconds);
    if (Number.isSafeInteger(seconds) && seconds > 0) {
      const body = document.querySelector(".pf-v5-c-login__main-body");
      if (body) body.prepend(lockout);
      const deadline = performance.now() + seconds * 1000;
      const submitControls = [...document.querySelectorAll("form button[type='submit'], form input[type='submit']")]
        .map(element => ({ element, disabled: element.disabled }));
      submitControls.forEach(({ element }) => { element.disabled = true; });
      let remaining = seconds;
      const preventEarlySubmit = event => { if (remaining > 0) event.preventDefault(); };
      document.querySelectorAll("form").forEach(form => form.addEventListener("submit", preventEarlySubmit));
      const update = () => {
        remaining = Math.max(0, Math.ceil((deadline - performance.now()) / 1000));
        const hours = Math.floor(remaining / 3600);
        const minutes = Math.floor((remaining % 3600) / 60);
        const rest = remaining % 60;
        const time = [minutes, rest].map(value => String(value).padStart(2, "0")).join(":");
        lockout.querySelector(".zt-lockout-time").textContent = hours ? `${hours}:${time}` : time;
        if (remaining === 0) {
          lockout.classList.add("is-ready");
          lockout.querySelector(".zt-lockout-status").textContent = lockout.dataset.readyMessage;
          submitControls.forEach(({ element, disabled }) => { element.disabled = disabled; });
          return;
        }
        window.setTimeout(update, 250);
      };
      update();
    }
  }
  document.body.classList.add("zt-theme-ready");
});
