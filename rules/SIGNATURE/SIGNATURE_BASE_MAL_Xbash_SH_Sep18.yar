
rule SIGNATURE_BASE_MAL_Xbash_SH_Sep18 : FILE
{
	meta:
		description = "Detects Xbash malware"
		author = "Florian Roth (Nextron Systems)"
		id = "450ef15f-fe9c-5809-9077-457a43326bfe"
		date = "2018-09-18"
		modified = "2023-01-06"
		reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_xbash.yar#L27-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b48cbd64002025d861e2fd381be5a68efd7f6fc5fd239850c940f887e2b01673"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "a27acc07844bb751ac33f5df569fd949d8b61dba26eb5447482d90243fc739af"
		hash2 = "de63ce4a42f06a5903b9daa62b67fcfbdeca05beb574f966370a6ae7fd21190d"

	strings:
		$s1 = "echo \"*/5 * * * * curl -fsSL" fullword ascii
		$s2 = ".sh|sh\" > /var/spool/cron/root" ascii
		$s3 = "#chmod +x /tmp/hawk" fullword ascii
		$s4 = "if [ ! -f \"/tmp/root.sh\" ]" fullword ascii
		$s5 = ".sh > /tmp/lower.sh" ascii
		$s6 = "chmod 777 /tmp/root.sh" fullword ascii
		$s7 = "-P /tmp && chmod +x /tmp/pools.txt" fullword ascii
		$s8 = "-C /tmp/pools.txt>/dev/null 2>&1" ascii

	condition:
		uint16(0)==0x2123 and filesize <3KB and 1 of them
}