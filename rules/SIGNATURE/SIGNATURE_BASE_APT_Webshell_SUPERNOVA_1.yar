rule SIGNATURE_BASE_APT_Webshell_SUPERNOVA_1 : FILE
{
	meta:
		description = "SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args). This rule is looking for specific strings and attributes related to SUPERNOVA."
		author = "FireEye"
		id = "73a27fa2-a846-5f4b-8182-064ac06c71a8"
		date = "2020-12-14"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_solarwinds_sunburst.yar#L80-L99"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8471e6b3675e7e9ccfe5b81ab4c599668f2de528f3b179a675f50aa1fd7814b2"
		score = 85
		quality = 81
		tags = "FILE"

	strings:
		$compile1 = "CompileAssemblyFromSource"
		$compile2 = "CreateCompiler"
		$context = "ProcessRequest"
		$httpmodule = "IHttpHandler" ascii
		$string1 = "clazz"
		$string2 = "//NetPerfMon//images//NoLogo.gif" wide
		$string3 = "SolarWinds" ascii nocase wide

	condition:
		uint16(0)==0x5a4d and uint32( uint32(0x3C))==0x00004550 and filesize <10KB and pe.imports("mscoree.dll","_CorDllMain") and $httpmodule and $context and all of ($compile*) and all of ($string*)
}