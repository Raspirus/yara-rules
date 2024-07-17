rule ELASTIC_Linux_Ransomware_Quantum_8513Fb8B : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Quantum (Linux.Ransomware.Quantum)"
		author = "Elastic Security"
		id = "8513fb8b-43f7-46b1-8318-5549a7609d3b"
		date = "2023-07-28"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_Quantum.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3bcb9ad92fdca53195f390fc4d8d721b504b38deeda25c1189a909a7011406c9"
		logic_hash = "7e24be541bafc2427ecd8f76b7774fb65d7421bc300503eeb068b8104e168c70"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1c1af76ab5df8243b8e25555f1762749ca60da56fecea9d4131c612358244525"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "All your files are encrypted on all devices across the network"
		$a2 = "process with pid %d is blocking %s, going to kill it"

	condition:
		all of them
}