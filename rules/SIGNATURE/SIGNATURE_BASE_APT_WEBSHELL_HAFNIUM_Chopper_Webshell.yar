rule SIGNATURE_BASE_APT_WEBSHELL_HAFNIUM_Chopper_Webshell : APT HAFNIUM WEBSHELL FILE
{
	meta:
		description = "Detects Chopper WebShell Injection Variant (not only Hafnium related)"
		author = "Markus Neis,Swisscom"
		id = "25dcf166-4aea-5680-b161-c5fc8d74b987"
		date = "2021-03-05"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hafnium.yar#L50-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c185a8da2a18fa59a8eeb36dbd95ba12c9c61717efc5f2d19d2d5b27ee243f2b"
		score = 75
		quality = 85
		tags = "APT, HAFNIUM, WEBSHELL, FILE"

	strings:
		$x1 = "runat=\"server\">" nocase
		$s1 = "<script language=\"JScript\" runat=\"server\">function Page_Load(){eval(Request" nocase
		$s2 = "protected void Page_Load(object sender, EventArgs e){System.IO.StreamWriter sw = new System.IO.StreamWriter(Request.Form[\"p\"] , false, Encoding.Default);sw.Write(Request.Form[\"f\"]);"
		$s3 = "<script language=\"JScript\" runat=\"server\"> function Page_Load(){eval (Request[\"" nocase

	condition:
		filesize <10KB and $x1 and 1 of ($s*)
}