rule SIGNATURE_BASE_MAL_Icedid_GZIP_LDR_202104 : FILE
{
	meta:
		description = "2021 initial Bokbot / Icedid loader for fake GZIP payloads"
		author = "Thomas Barabosch, Telekom Security"
		id = "fbf578e7-c318-5f67-82df-f93232362a23"
		date = "2021-04-12"
		modified = "2023-01-27"
		reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_icedid.yar#L14-L40"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7a7cc6c7dcbf43bace6a1f259af38560327c34386517e719ad81068b2d9b6659"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$internal_name = "loader_dll_64.dll" fullword
		$string0 = "_gat=" wide
		$string1 = "_ga=" wide
		$string2 = "_gid=" wide
		$string4 = "_io=" wide
		$string5 = "GetAdaptersInfo" fullword
		$string6 = "WINHTTP.dll" fullword
		$string7 = "DllRegisterServer" fullword
		$string8 = "PluginInit" fullword
		$string9 = "POST" wide fullword
		$string10 = "aws.amazon.com" wide fullword

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and ($internal_name or all of ($s*)) or all of them
}