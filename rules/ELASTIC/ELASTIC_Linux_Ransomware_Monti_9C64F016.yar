
rule ELASTIC_Linux_Ransomware_Monti_9C64F016 : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Monti (Linux.Ransomware.Monti)"
		author = "Elastic Security"
		id = "9c64f016-0fd9-41bf-8916-cdf3a35efdd6"
		date = "2023-07-27"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_Monti.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ad8d1b28405d9aebae6f42db1a09daec471bf342e9e0a10ab4e0a258a7fa8713"
		logic_hash = "c22a4efaaf97d68deaf1978e637dd7f790541e5007c6323629bcc9e3d4eecd06"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "af28cc97eed328f3b2b0181784545e41a521e9dfff09a504177cb56929606b84"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "[%s] Flag doesn't equal MONTI."
		$a2 = "--vmkill Whether to kill the virtual machine"
		$a3 = "MONTI strain."
		$a4 = "http://monti"

	condition:
		2 of them
}