
rule TRELLIX_ARC_APT_Acidbox_Kernelmode_Module : KERNELDRIVER FILE
{
	meta:
		description = "Rule to detect the kernel mode component of AcidBox"
		author = "Marc Rivero | McAfee ATR Team"
		id = "80b60307-5431-5f21-9e6f-06adaab0519d"
		date = "2020-07-24"
		modified = "2020-08-14"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_acidbox.yar#L1-L32"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "e39da89d0da22115ac7889bc73ff183973a6c5334e304df955362bde76694d42"
		score = 75
		quality = 70
		tags = "KERNELDRIVER, FILE"
		rule_version = "v1"
		malware_type = "kerneldriver"
		malware_family = "Rootkit:W32/Acidbox"
		actor_type = "APT"
		actor_group = "Turla"
		hash1 = "3ef071e0327e7014dd374d96bed023e6c434df6f98cce88a1e7335a667f6749d"

	strings:
		$pattern_0 = { 897c2434 8978b8 8d5f28 448bc3 33d2 }
		$pattern_1 = { 4c8d842470010000 488d942418010000 498bcf e8???????? 8bd8 89442460 }
		$pattern_2 = { 4c8bf1 49d1eb 4585c9 0f88a2000000 440fb717 498bd0 }
		$pattern_3 = { ff15???????? 4c8d9c2480000000 498b5b10 498b7318 498b7b20 4d8b7328 498be3 }
		$pattern_4 = { 33d2 41b8???????? 895c2420 e8???????? }
		$pattern_5 = { 895c2420 4885ff 0f8424010000 440f20c0 84c0 0f8518010000 }
		$pattern_6 = { 85f6 0f8469fdffff 488d8424c8010000 41b9???????? }
		$pattern_7 = { 894c2404 750a ffc7 893c24 41ffc3 ebcb 85c9 }
		$pattern_8 = { 488b5c2450 488b742458 488b7c2460 4883c430 }
		$pattern_9 = { 33d2 488b4c2428 e8???????? 448b842450040000 4503c0 4c8d8c2450040000 488bd7 }

	condition:
		7 of them and filesize <78848
}