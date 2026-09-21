document.addEventListener("DOMContentLoaded", () => {
  const body = document.body;

  if (!body) {
    return;
  }

  const vietnamese = (document.documentElement.lang || "vi")
    .toLowerCase()
    .startsWith("vi");
  const copy = vietnamese
    ? {
        privacy:
          "",
        login: "",
        otp: "Nhập mã OTP từ ứng dụng xác thực để hoàn tất đăng nhập.",
        error: "Kiểm tra thông báo bên dưới hoặc quay lại Portal để bắt đầu lại.",
        defaultDescription: "Hoàn tất bước xác thực để tiếp tục tới Cổng học vụ.",
      }
    : {
        privacy: "",
        login: "",
        otp: "Enter the code from your authenticator application to finish signing in.",
        error: "Review the message below or return to the Portal and start again.",
        defaultDescription: "Complete authentication to continue to the academic portal.",
      };

  const create = (tagName, className, text) => {
    const element = document.createElement(tagName);
    element.className = className;
    if (text) element.textContent = text;
    return element;
  };

  const pageId = body.dataset.pageId || "";
  const pageDescription = pageId.includes("login-otp")
    ? copy.otp
    : pageId.includes("error") || pageId.includes("page-expired")
      ? copy.error
      : pageId === "login-login"
        ? copy.login
        : copy.defaultDescription;
  const mainHeader = document.querySelector(".pf-v5-c-login__main-header");
  if (mainHeader && !mainHeader.querySelector(".zt-page-description")) {
    mainHeader.append(create("p", "zt-page-description", pageDescription));
  }

  const mainBody = document.querySelector(".pf-v5-c-login__main-body");
  if (mainBody && !mainBody.querySelector(".zt-privacy-note")) {
    mainBody.append(create("p", "zt-privacy-note", copy.privacy));
  }

  body.classList.add("zt-theme-ready");
});
