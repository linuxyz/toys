## Set lock screen with Bing's Wallpaper
$day= (Get-Date).DayOfWeek
$wpPath= "$PSScriptRoot\bing-$day-wallpaper.jpg"
$baseUrl='https://www.bing.com'
$jsonUrl='https://www.bing.com/HPImageArchive.aspx?format=js&mbl=1&idx=0&n=1&cc=us'
$json=Invoke-WebRequest -Uri $jsonUrl | ConvertFrom-Json
$url=$baseUrl+$json.images.url.toString().trim()

$webclient = New-Object System.Net.WebClient
try {
	$webClient.DownloadFile($url,$wpPath)
}
catch [Exception] {
	exit
}

#rundll32.exe User32.dll,SystemParametersInfo 0x0014 0 $wpPath 0x03

Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
 
public static class User32
{
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern int SystemParametersInfo(
            Int32 uAction,
            Int32 uParam,
            String lpvParam,
            Int32 fuWithIni);
}
"@

$SPI_SETDESKWALLPAPER = 0x0014
$UpdateIniFile = 0x01
$SendChangeEvent = 0x02
$fWinIni = $UpdateIniFile -bor $SendChangeEvent
[User32]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $wpPath, $fWinIni)

