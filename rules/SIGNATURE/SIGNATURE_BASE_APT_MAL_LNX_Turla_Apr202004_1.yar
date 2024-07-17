
rule SIGNATURE_BASE_APT_MAL_LNX_Turla_Apr202004_1 : FILE
{
	meta:
		description = "Detects Turla Linux malware x64 x32"
		author = "Leonardo S.p.A."
		id = "2da75433-b1c1-51b3-8f7a-a4442ca3de96"
		date = "2020-04-24"
		modified = "2023-12-05"
		reference = "https://www.leonardocompany.com/en/news-and-stories-detail/-/detail/knowledge-the-basis-of-protection"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_penquin.yar#L2-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1e07963c492f1e6264f01ee292e40b188ca325b76005d9d48e6dc198cb9bdcf4"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
		hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
		hash3 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
		hash4 = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905"
		hash5 = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08"
		hash6 = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4"
		hash7 = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8"
		hash8 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
		hash9 = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0"

	strings:
		$ = "/root/.hsperfdata" ascii fullword
		$ = "Desc| Filename | size |state|" ascii fullword
		$ = "VS filesystem: %s" ascii fullword
		$ = "File already exist on remote filesystem !" ascii fullword
		$ = "/tmp/.sync.pid" ascii fullword
		$ = "rem_fd: ssl " ascii fullword
		$ = "TREX_PID=%u" ascii fullword
		$ = "/tmp/.xdfg" ascii fullword
		$ = "__we_are_happy__" ascii
		$ = "/root/.sess" ascii fullword

	condition:
		uint16(0)==0x457f and filesize <5000KB and 4 of them
}