param(
 [ValidateSet('x64','x86')][string]$Architecture='x64',
 [ValidateSet('Release','Debug')][string]$Configuration='Release',
 [string]$VisualStudioPath,
 [ValidatePattern('^[0-9.]+$')][string]$VCToolsVersion
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$env:PSModulePath="$PSHOME\Modules;${env:ProgramFiles}\WindowsPowerShell\Modules;"+$env:PSModulePath
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if(!$VisualStudioPath){$VisualStudioPath=& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath}
$VisualStudioPath=[IO.Path]::GetFullPath($VisualStudioPath)
if(!$VCToolsVersion){$VCToolsVersion=(Get-Content (Join-Path $VisualStudioPath 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt') -Raw).Trim()}
if($VCToolsVersion -notmatch '^[0-9.]+$'){throw 'Invalid compiler version'}
$version='3.5.9'
$cache=Join-Path $repo '.build\windows-openssl'
$install=Join-Path $cache ($VCToolsVersion+'\'+$Architecture+'\'+$Configuration+'\install')
$recipeHash=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
$stamp=Join-Path $install 'mesh-build-recipe.sha256'
if((Test-Path $stamp) -and (Get-Content $stamp -Raw).Trim() -eq $recipeHash -and
 (Test-Path (Join-Path $install 'lib\libcrypto.lib')) -and (Test-Path (Join-Path $install 'lib\libssl.lib')) -and
 (Test-Path (Join-Path $install 'include\openssl\configuration.h'))){return}
New-Item -ItemType Directory -Force -Path $cache|Out-Null
function VerifiedDownload([string]$Url,[string]$Path,[string]$Sha256){
 if((Test-Path $Path) -and (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -eq $Sha256){return}
 $temporary=$Path+'.partial'
 Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $temporary
 if((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -ne $Sha256){throw ('Download checksum mismatch: '+[IO.Path]::GetFileName($Path))}
 Move-Item -LiteralPath $temporary -Destination $Path -Force
}
$archive=Join-Path $cache ('openssl-'+$version+'.tar.gz')
VerifiedDownload ('https://github.com/openssl/openssl/releases/download/openssl-'+$version+'/openssl-'+$version+'.tar.gz') $archive '603F5602E2EEF00D77FBD429D34DCD5822BB301757A1BC9CDB24C670F1EB859A'
$source=Join-Path $cache ('openssl-'+$version)
if(!(Test-Path (Join-Path $source 'Configure'))){& tar.exe -xzf $archive -C $cache;if($LASTEXITCODE){throw 'OpenSSL source extraction failed'}}
$perlRoot=Join-Path $cache 'tools\strawberry-5.42.3.1'
$perl=Join-Path $perlRoot 'perl\bin\perl.exe'
if(!(Test-Path $perl)){
 $zip=Join-Path $cache 'strawberry-perl-5.42.3.1-64bit-portable.zip'
 VerifiedDownload 'https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/SP_54231_64bit/strawberry-perl-5.42.3.1-64bit-portable.zip' $zip '6A081A811781C30ACA51DBC036AFD93092AF91E3297901F02C17043795A10690'
 Expand-Archive -LiteralPath $zip -DestinationPath $perlRoot -Force
}
$nasmRoot=Join-Path $cache 'tools\nasm-3.02'
if(!(Test-Path (Join-Path $nasmRoot 'nasm.exe'))){
 $zip=Join-Path $cache 'nasm-3.02-win64.zip'
 VerifiedDownload 'https://www.nasm.us/pub/nasm/releasebuilds/3.02/win64/nasm-3.02-win64.zip' $zip '161D0BFAFF53C2F9E9F3E69FD0672323EBABAFD1268976A5CEC11BE92A19AEE7'
 Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $cache 'tools') -Force
}
$matching=$env:VSCMD_ARG_TGT_ARCH -eq $Architecture -and $env:VCToolsVersion -and $env:VCToolsVersion.TrimEnd('\') -eq $VCToolsVersion
if(!$matching){
 $env:PATH=$env:SystemRoot+'\System32;'+$env:SystemRoot+';'+$env:SystemRoot+'\System32\WindowsPowerShell\v1.0'
 foreach($name in @('INCLUDE','LIB','LIBPATH','VSCMD_VER','__VSCMD_PREINIT_PATH')){[Environment]::SetEnvironmentVariable($name,$null,'Process')}
}
$build=Join-Path $cache ($VCToolsVersion+'\'+$Architecture+'\'+$Configuration+'\build-'+$recipeHash.Substring(0,12))
New-Item -ItemType Directory -Force -Path $build|Out-Null
$target=if($Architecture -eq 'x64'){'VC-WIN64A'}else{'VC-WIN32'}
$debugFlag=if($Configuration -eq 'Debug'){' --debug'}else{''}
$vcvars=Join-Path $VisualStudioPath 'VC\Auxiliary\Build\vcvarsall.bat'
$commands=@(
 '@echo off',
 $(if($matching){'rem Reuse matching compiler environment'}else{'call "'+$vcvars+'" '+$Architecture+' -vcvars_ver='+$VCToolsVersion}),
 'if errorlevel 1 exit /b %errorlevel%',
 ('set "PATH='+[IO.Path]::GetDirectoryName($perl)+';'+$nasmRoot+';%PATH%"'),
 'set "LANG=C"',
 'set "LC_ALL=C"',
 ('"'+$perl+'" "'+(Join-Path $source 'Configure')+'" '+$target+' no-shared no-module no-dso no-engine /guard:cf --libdir=lib --openssldir="C:/Program Files/Common Files/SSL" --prefix="'+$install.Replace('\','/')+'"'+$debugFlag),
 'if errorlevel 1 exit /b %errorlevel%',
 'nmake /nologo build_libs',
 'if errorlevel 1 exit /b %errorlevel%',
 'nmake /nologo install_dev',
 'exit /b %errorlevel%'
)
$cmd=Join-Path $build 'build.cmd'
$commands|Set-Content -LiteralPath $cmd -Encoding ASCII
Push-Location $build
try {& $env:ComSpec /d /c $cmd;if($LASTEXITCODE){throw 'OpenSSL static build failed'}} finally {Pop-Location}
if(!(Test-Path (Join-Path $install 'lib\libcrypto.lib')) -or !(Test-Path (Join-Path $install 'lib\libssl.lib'))){throw 'OpenSSL libraries missing after build'}
$recipeHash|Set-Content -LiteralPath $stamp -Encoding ASCII

