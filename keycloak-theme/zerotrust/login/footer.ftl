<#macro content>
    <#if ztLockout?? && ztLockout.remainingSeconds gt 0>
        <section class="zt-lockout" data-remaining-seconds="${ztLockout.remainingSeconds?c}"
                 data-ready-message="${msg('ztLockoutReady')}" aria-labelledby="zt-lockout-title">
            <span class="zt-lockout-label" id="zt-lockout-title">${msg('ztLockoutTitle')}</span>
            <strong class="zt-lockout-time" role="timer" aria-live="off">${msg('ztLockoutSeconds', ztLockout.remainingSeconds?c)}</strong>
            <p class="zt-lockout-note">${msg('ztLockoutNote')}</p>
            <p class="zt-lockout-status" role="status" aria-live="polite"></p>
        </section>
    </#if>
    <p class="zt-footer-note">${msg('ztFooterNote')}</p>
</#macro>
