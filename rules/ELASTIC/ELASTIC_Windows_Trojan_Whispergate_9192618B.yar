rule ELASTIC_Windows_Trojan_Whispergate_9192618B : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Whispergate (Windows.Trojan.WhisperGate)"
		author = "Elastic Security"
		id = "9192618b-4f3e-4503-a97f-3c4420fb79e0"
		date = "2022-01-17"
		modified = "2022-01-17"
		reference = "https://www.elastic.co/security-labs/operation-bleeding-bear"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_WhisperGate.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78"
		logic_hash = "28bb08d61d99d2bfc49ba18cdbabc34c31a715ae6439ab25bbce8cc6958ed381"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "21f2a5b730a86567e68491a0d997fc52ba37f28b2164747240a74c225be3c661"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "https://cdn.discordapp.com/attachments/" wide
		$a2 = "DxownxloxadDxatxxax" wide fullword
		$a3 = "powershell" wide fullword
		$a4 = "-enc UwB0AGEAcgB0AC" wide fullword
		$a5 = "Ylfwdwgmpilzyaph" wide fullword

	condition:
		all of them
}