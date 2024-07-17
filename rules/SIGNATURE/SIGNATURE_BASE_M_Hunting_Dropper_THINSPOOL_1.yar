
rule SIGNATURE_BASE_M_Hunting_Dropper_THINSPOOL_1 : FILE
{
	meta:
		description = "This rule detects THINSPOOL, a dropper that installs the LIGHTWIRE web shell onto a Pulse Secure system."
		author = "Mandiant"
		id = "dd340f72-0a2c-5b66-9e31-1c0f20cd842f"
		date = "2024-01-11"
		modified = "2024-04-24"
		reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_report_ivanti_mandiant_jan24.yar#L83-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "677c1aa6e2503b56fe13e1568a814754"
		logic_hash = "a8043822cd36a802ba6656c42085f09d67cedb0689c9da48438d788b320bd6c0"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "/tmp/qactg/" ascii
		$s2 = "echo '/home/config/dscommands'" ascii
		$s3 = "echo '/home/perl/DSLogConfig.pm'" ascii
		$s4 = "ADM20447" ascii

	condition:
		filesize <10KB and all of them
}