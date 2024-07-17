
rule EMBEERESEARCH_Win_Cobalt_Sleep_Encrypt : FILE
{
	meta:
		description = "Detects Sleep Encryption Logic Found in Cobalt Strike Deployments"
		author = "Matthew @ Embee_Research"
		id = "6bd6fbb4-6634-5b51-90f0-f24e48d69043"
		date = "2023-08-27"
		modified = "2023-10-18"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_cobalt_sleep_encrypt_aug_2023.yar#L1-L55"
		license_url = "N/A"
		hash = "26b2f12906c3590c8272b80358867944fd86b9f2cc21ee6f76f023db812e5bb1"
		logic_hash = "7aa2674ecaaae819c3f26924fa0622df322b1214493f37b1bdf5e00ba5ee98e6"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$r1_nokey = {4E 8B 04 08 B8 ?? ?? ?? ?? 41 F7 E3 41 8B C3 C1 EA 02 41 FF C3 6B D2 0D 2B C2 8A 4C 18 18 41 30 0C 38 48 8B 43 10 41 8B FB 4A 3B 7C 08 08}
		$r2_nokey = {49 8B F9 4C 8B 03 B8 ?? ?? ?? ?? 41 F7 E1 41 8B C1 C1 EA 02 41 FF C1 6B D2 0D 2B C2 8A 4C 18 18 42 30 0C 07 48 FF C7 45 3B CB}

	condition:
		($r1_nokey or $r2_nokey)
}