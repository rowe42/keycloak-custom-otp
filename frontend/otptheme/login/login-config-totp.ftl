<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "header">
        ${msg("configureTotpNotAllowed")}
    <#elseif section = "form">


    <p>${msg("configureTOTPHint")}</p>
    ${msg("pageExpiredMsg1")} <a id="loginRestartLink" href="${url.loginRestartFlowUrl}">${msg("doClickHere")}</a> .<br/>
    </#if>
</@layout.registrationLayout>
