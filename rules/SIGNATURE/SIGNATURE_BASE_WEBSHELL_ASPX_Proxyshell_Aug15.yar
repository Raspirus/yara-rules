
rule SIGNATURE_BASE_WEBSHELL_ASPX_Proxyshell_Aug15 : FILE
{
	meta:
		description = "Webshells iisstart.aspx and Logout.aspx"
		author = "Moritz Oettle"
		id = "b1e6c0f3-787f-59b8-8123-4045522047ca"
		date = "2021-09-04"
		modified = "2023-12-05"
		reference = "https://github.com/hvs-consulting/ioc_signatures/tree/main/Proxyshell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_proxyshell.yar#L122-L146"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7e2e2f9add5932d28074a252a8e326dd728442df28abc02e8d026d773dd4aa05"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$g1 = "language=\"JScript\"" ascii
		$g2 = "function getErrorWord" ascii
		$g3 = "errorWord" ascii
		$g4 = "Response.Redirect" ascii
		$g5 = "function Page_Load" ascii
		$g6 = "runat=\"server\"" ascii
		$g7 = "Request[" ascii
		$g8 = "eval/*" ascii
		$s1 = "AppcacheVer" ascii
		$s2 = "clientCode" ascii
		$s3 = "LaTkWfI64XeDAXZS6pU1KrsvLAcGH7AZOQXjrFkT816RnFYJQR" ascii

	condition:
		filesize <1KB and (1 of ($s*) or 4 of ($g*))
}