rule ELASTIC_Multi_Trojan_Mythic_4Beb7E17 : FILE MEMORY
{
	meta:
		description = "Detects Multi Trojan Mythic (Multi.Trojan.Mythic)"
		author = "Elastic Security"
		id = "4beb7e17-34c2-4f5c-a668-e54512175f53"
		date = "2023-08-01"
		modified = "2023-09-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Multi_Trojan_Mythic.yar#L1-L28"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "7b3b7bae1763f3c73df206f97065920fa55b973d22c967acb3d26ac8e89e60c7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0b25c5b069cec31e9af31b7822ea19b813fe1882dfaa584661ff14414ae41df5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"

	strings:
		$a1 = "task_id"
		$a2 = "post_response"
		$a3 = "c2_profile"
		$a4 = "get_tasking"
		$a5 = "tasking_size"
		$a6 = "get_delegate_tasks"
		$a7 = "total_chunks"
		$a8 = "is_screenshot"
		$a9 = "file_browser"
		$a10 = "is_file"
		$a11 = "access_time"

	condition:
		7 of them
}