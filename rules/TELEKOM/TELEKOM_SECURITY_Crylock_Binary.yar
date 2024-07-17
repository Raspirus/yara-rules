rule TELEKOM_SECURITY_Crylock_Binary : FILE
{
	meta:
		description = "Detects CryLock ransomware v2.3.0.0"
		author = "Thomas Barabosch, Telekom Security"
		id = "5d46adf6-3ea4-5e3d-ac33-1292c076c0df"
		date = "2021-06-28"
		modified = "2021-07-08"
		reference = "TBA"
		source_url = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/crylock/crylock_20210706.yar#L1-L27"
		license_url = "N/A"
		logic_hash = "990be4604c5737383cce1b32dfbf3bc066367d7bf4652e2549730cdeccf1f413"
		score = 75
		quality = 70
		tags = "FILE"

	strings:
		$s1 = "how_to_decrypt.hta" ascii
		$s2 = "UAC annoy and ask admin rights" ascii
		$s3 = "<%UNDECRYPT_DATETIME%>" ascii
		$s4 = "<%RESERVE_CONTACT%>" ascii
		$s5 = "<%MAIN_CONTACT%>" ascii
		$s6 = "<%HID%>" ascii
		$s7 = "Get local IPs list" ascii
		$s8 = "Get password hash" ascii
		$s9 = "END PROCESSES KILL LIST" ascii
		$s10 = "CIS zone detected" ascii
		$s11 = "Launch encryption threads..." ascii
		$s12 = "FastBlackRabbit" ascii
		$s13 = "Preliminary password hash calculation" ascii
		$s14 = "Encrypted:" ascii

	condition:
		uint16(0)==0x5a4d and filesize >150KB and filesize <1MB and 8 of ($s*)
}