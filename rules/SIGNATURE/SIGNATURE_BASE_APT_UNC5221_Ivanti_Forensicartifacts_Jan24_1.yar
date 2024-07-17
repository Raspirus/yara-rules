rule SIGNATURE_BASE_APT_UNC5221_Ivanti_Forensicartifacts_Jan24_1 : FILE
{
	meta:
		description = "Detects forensic artifacts found in the Ivanti VPN exploitation campaign by APT UNC5221"
		author = "Florian Roth"
		id = "49ba2a96-379d-5a58-979d-45e83fa546e7"
		date = "2024-01-11"
		modified = "2024-04-24"
		reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_report_ivanti_mandiant_jan24.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7f485f41072f5584dc76e71564e13066d9fe41685f33bff9c2886fa7d2155f94"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "system(\"chmod a+x /home/etc/sql/dsserver/sessionserver.sh\");"
		$x2 = "SSH-2.0-OpenSSH_0.3xx."
		$x3 = "sed -i '/retval=$(exec $installer $@)/d' /pkg/do-install"

	condition:
		filesize <5MB and 1 of them
}