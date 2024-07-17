
rule TELEKOM_SECURITY_Win_Iceid_Core_202104 : FILE
{
	meta:
		description = "2021 Bokbot / Icedid core"
		author = "Thomas Barabosch, Telekom Security"
		id = "526a73da-415f-58fe-bb5f-4c3df6b2e647"
		date = "2021-04-12"
		modified = "2021-07-08"
		reference = "https://github.com/telekom-security/malware_analysis/"
		source_url = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/icedid/icedid_20210507.yar#L64-L88"
		license_url = "N/A"
		logic_hash = "c208b4122159d24d010e2913c515d2ff730b30306f787d703816b5af1522ae88"
		score = 75
		quality = 70
		tags = "FILE"

	strings:
		$internal_name = "fixed_loader64.dll" fullword
		$string0 = "mail_vault" wide fullword
		$string1 = "ie_reg" wide fullword
		$string2 = "outlook" wide fullword
		$string3 = "user_num" wide fullword
		$string4 = "cred" wide fullword
		$string5 = "Authorization: Basic" fullword
		$string6 = "VaultOpenVault" fullword
		$string7 = "sqlite3_free" fullword
		$string8 = "cookie.tar" fullword
		$string9 = "DllRegisterServer" fullword
		$string10 = "PT0S" wide

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and ($internal_name or all of ($s*)) or all of them
}