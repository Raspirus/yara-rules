rule SIGNATURE_BASE_APT_HKTL_Wiper_Whispergate_Stage3_Jan22 : FILE
{
	meta:
		description = "Detects reversed stage3 related to Ukrainian wiper malware"
		author = "Florian Roth (Nextron Systems)"
		id = "d5d562cd-03ef-5450-8044-3f538cea32d0"
		date = "2022-01-16"
		modified = "2023-12-05"
		reference = "https://twitter.com/juanandres_gs/status/1482827018404257792"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ua_wiper_whispergate.yar#L59-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b06536b6a6eebd5fb398ba2617bf68a5b2c4b0035766b3cd0fc03d95019891ec"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "9ef7dbd3da51332a78eff19146d21c82957821e464e8133e9594a07d716d892d"

	strings:
		$xc1 = { 65 31 63 70 00 31 79 72 61 72 62 69 4c 73 73 61 6c 43 00 6e 69 61 4d }
		$s1 = "lld." wide

	condition:
		uint16( filesize -2)==0x4d5a and filesize <5000KB and all of them
}