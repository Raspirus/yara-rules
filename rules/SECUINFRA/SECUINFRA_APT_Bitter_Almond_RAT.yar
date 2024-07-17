rule SECUINFRA_APT_Bitter_Almond_RAT : FILE
{
	meta:
		description = "Detects Bitter (T-APT-17) Almond RAT (.NET)"
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		id = "191fadf9-4f64-56c9-bc2a-a7b4e27ab0fc"
		date = "2022-06-01"
		modified = "2022-07-05"
		reference = " https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/APT/APT_Bitter_T-APT-17.yar#L82-L108"
		license_url = "N/A"
		hash = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"
		logic_hash = "b8d6b95987fe434fc16c87a7bc144f1fe69301a32bb93588df7c2abbfef62d75"
		score = 75
		quality = 70
		tags = "FILE"
		tlp = "WHITE"

	strings:
		$function0 = "GetMacid" ascii
		$function1 = "StartCommWithServer" ascii
		$function2 = "sendingSysInfo" ascii
		$dbg0 = "*|END|*" wide
		$dbg1 = "FILE>" wide
		$dbg2 = "[Command Executed Successfully]" wide

	condition:
		uint16(0)==0x5a4d and dotnet.version=="v4.0.30319" and filesize >12KB and filesize <68KB and any of ($function*) and any of ($dbg*)
}