
rule ELASTIC_Linux_Hacktool_Wipelog_Daea1Aa4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Wipelog (Linux.Hacktool.Wipelog)"
		author = "Elastic Security"
		id = "daea1aa4-0df7-4308-83e1-0707dcda2e54"
		date = "2022-03-17"
		modified = "2022-07-22"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Wipelog.yar#L1-L29"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "39b3a95928326012c3b2f64e2663663adde4b028d940c7e804ac4d3953677ea6"
		logic_hash = "e2483b7719f4a1e28ec3732120770066333d8db269c9c9711813a8eeb75176d6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "93f899e14e6331c2149ba5c0c1e9dd8def5a7d1b6d2a7af66eade991dea77b3c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$s1 = "Erase one username on tty"
		$s2 = "wipe_utmp"
		$s3 = "wipe_acct"
		$s4 = "wipe_lastlog"
		$s5 = "wipe_wtmp"
		$s6 = "getpwnam"
		$s7 = "ERROR: Can't find user in passwd"
		$s8 = "ERROR: Opening tmp ACCT file"
		$s9 = "/var/log/wtmp"
		$s10 = "/var/log/lastlog"
		$s11 = "Patching %s ...."

	condition:
		4 of them
}