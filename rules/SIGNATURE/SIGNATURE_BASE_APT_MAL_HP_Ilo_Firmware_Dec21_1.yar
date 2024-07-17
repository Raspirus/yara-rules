rule SIGNATURE_BASE_APT_MAL_HP_Ilo_Firmware_Dec21_1 : FILE
{
	meta:
		description = "Detects suspicios ELF files with sections as described in malicious iLO Board analysis by AmnPardaz in December 2021"
		author = "Florian Roth (Nextron Systems)"
		id = "7f5fa905-07a3-55da-b644-c5ab882b4a9d"
		date = "2021-12-28"
		modified = "2023-12-05"
		reference = "https://threats.amnpardaz.com/en/2021/12/28/implant-arm-ilobleed-a/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_mal_ilo_board_elf.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7e959d07d864a485b8cc7765f9e12869ff34747ab552e26244eb28f510d1051f"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$s1 = ".newelf.elf.text" ascii
		$s2 = ".newelf.elf.libc.so.data" ascii
		$s3 = ".newelf.elf.Initial.stack" ascii
		$s4 = ".newelf.elf.libevlog.so.data" ascii

	condition:
		filesize <5MB and 2 of them or all of them
}