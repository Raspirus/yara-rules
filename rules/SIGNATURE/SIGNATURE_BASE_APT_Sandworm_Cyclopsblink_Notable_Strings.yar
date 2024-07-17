
rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Notable_Strings : FILE
{
	meta:
		description = "Detects notable strings identified within the Cyclops Blink executable"
		author = "NCSC"
		id = "81ccf582-41f5-5fe5-8afc-e008e01289ff"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sandworm_cyclops_blink.yar#L6-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fdd3a1de9d178370fcc66dbca4628d7bedfbc002bca9e463e11cb444302900ea"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"

	strings:
		$proc_name1 = "[kworker/0:1]"
		$proc_name2 = "[kworker/1:1]"
		$dns_query = "POST /dns-query HTTP/1.1\x0d\x0aHost: dns.google\x0d\x0a"
		$iptables1 = "iptables -I %s -p tcp --dport %d -j ACCEPT &>/dev/null"
		$iptables2 = "iptables -D %s -p tcp --dport %d -j ACCEPT &>/dev/null"
		$sys_recon1 = "{\"ver\":\"%x\",\"mods\";["
		$sys_recon2 = "uptime: %lu mem_size: %lu mem_free: %lu"
		$sys_recon3 = "disk_size: %lu disk_free: %lu"
		$sys_recon4 = "hw: %02x:%02x:%02x:%02x:%02x:%02x"
		$testpath = "%s/214688dsf46"
		$confpath = "%s/rootfs_cfg"
		$downpath = "/var/tmp/a.tmp"

	condition:
		( uint32(0)==0x464c457f) and (8 of them )
}