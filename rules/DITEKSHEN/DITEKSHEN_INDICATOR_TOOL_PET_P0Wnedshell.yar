import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PET_P0Wnedshell : FILE
{
	meta:
		description = "Detects compiled executables of p0wnedShell post-exploitation toolkit"
		author = "ditekSHen"
		id = "7df8f9b4-48d3-5271-9d60-5dd4bfaed316"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L486-L512"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "9745b69573bf695fdada122143fb1889a7b2025250b5fb1e8f1a86b3be6f27d3"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Use WinRM, PsExec, SMB/WMI to execute commands on remote systems" wide
		$s2 = "-CreateProcess \"cmd.exe\" -Username \"nt authority\\system\"" wide
		$s3 = "-Command '\"lsadump::dcsync /user:" wide
		$s4 = "-Payload windows/meterpreter/reverse_https -Lhost" wide
		$s5 = "Get-Content ./EncodedPayload.bat" fullword wide
		$e1 = "OnYNAB+LCAAAAAAABAC8vOeS60iSLvh75yly+rZZVxuqC4KQs3uvLQhFEJIACALoHVuD1oKQBMbuuy+Y4pw8dUTf3R+bZlWVZHh87uHh4vPItv63ZGrCMW+bF7GZ2zL+" wide
		$e2 = "kuIeAB+LCAAAAAAABADsvWt327iuMPw9v0Jv27Wa7DqJc2ma5nl71vZFTpzx/ZJL+3TlyLZiq7EtjyTHcffZ//0BSEqiKEqWbKczs8941qS2LgAIAiAIguDjfNp3DHOq" wide
		$e3 = "mZYIAB+LCAAAAAAABADsvflj2zyOMPx7/gptmnftbBIfuZp0t/OOfMZp7PjO0adfX9lSbCWy5Vp2HGfm+d8/ACQl6vCRNp2Z3bVmnioWSRAEQQAESfC/Pmwp8FTtmTFu" wide
		$e4 = "u9YGAB+LCAAAAAAABADsvW1D40ayKPw9v0Lr4V7ZE8vY5mUY9rKJBzMTnmWAgyGTvYTlCluAdmzJK9nDsEn++1NV/S61ZJmXZJIN52wG7O7q6urq6qrqquoXSfDveZgE" wide
		$e5 = "T3gDAB+LCAAAAAAABADtvX1f2zq2KPz3yafQzuZcwi5JEydQ2nM7v4cCnc0zQLmE7j3z6+7NmMQBnwY7YzsFTqff/WpJsi3Jki07DlA2mT008ctaS0tL601L0nThjSPX" wide
		$e6 = "zRgDAB+LCAAAAAAABADtfW1327jR6OdHv4Kr9TmWdiVZkl+SdZs913Gcrm9tx7WcbvekuS4t0TYbiVRJKYmfbf77xeCNeCVBinKcbNStI5HAYDAYDAaDwczNMhovwjjy" wide
		$e7 = "pxICAB+LCAAAAAAABADtvf17GkeyKPyz+Cvmlfw+ggRhfcXr1X1znsUIx5yVhC7IUbI+fnUHGKRZwww7M1jWyeZ/v1XV3z09wABysnviZ1cBpqe6urqquqq6uno8j4ZZ" wide
		$e8 = "H4sIAAAAAAAEANy9e3wTVfo4PG1SmkLbCdpgFdSgUeuCbLTAthYk005gQhNahUIVkCqIqKi1TaAuIGBaJRzG27Kuul5wV3fV1fUuUFxNKbTl3oJAuaiouE4paAGBFpB5" wide
		$k1 = "EasySystemPPID" fullword ascii
		$k2 = "EasySystemShell" fullword ascii
		$k3 = "LatMovement" fullword ascii
		$k4 = "ListenerURL" fullword ascii
		$k5 = "MeterStager" fullword ascii
		$k6 = "PatchEventLog" fullword ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($s*) or 7 of ($e*) or all of ($k*) or (2 of ($s*) and 2 of ($e*) and 2 of ($k*)))
}