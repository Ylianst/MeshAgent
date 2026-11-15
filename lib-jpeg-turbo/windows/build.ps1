param(
 [ValidateSet('x64','x86')][string]$Architecture='x64',
 [ValidateSet('Release','Debug')][string]$Configuration='Release',
 [string]$VisualStudioPath,
 [ValidatePattern('^[0-9.]+$')][string]$VCToolsVersion
)
$ErrorActionPreference='Stop'
# Windows PowerShell may inherit PowerShell 7 module paths from the caller.
$env:PSModulePath="$PSHOME\Modules;${env:ProgramFiles}\WindowsPowerShell\Modules;"+$env:PSModulePath
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if(!$VisualStudioPath){
 $VisualStudioPath=& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
}
$VisualStudioPath=[IO.Path]::GetFullPath($VisualStudioPath)
if(!$VCToolsVersion){$VCToolsVersion=(Get-Content (Join-Path $VisualStudioPath 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt') -Raw).Trim()}
if($VCToolsVersion -notmatch '^[0-9.]+$'){throw 'Invalid compiler version'}
$work=Join-Path $repo ('.build\windows-jpeg\'+$VCToolsVersion)
New-Item -ItemType Directory -Force -Path $work|Out-Null
$archive=Join-Path $PSScriptRoot 'libjpeg-turbo-3.2.1.tar.gz'
if((Get-FileHash $archive -Algorithm SHA256).Hash -ne 'C27AD72A68DA151177929AA969AE773A2DA5AC2AF9CE946079314FDAC8CECE7F'){throw 'JPEG source archive hash mismatch'}
$source=Join-Path $work 'libjpeg-turbo-3.2.1'
if(!(Test-Path (Join-Path $source 'CMakeLists.txt'))){& tar.exe -xzf $archive -C $work;if($LASTEXITCODE){throw 'JPEG source extraction failed'}}
# A private, pinned build-tool copy; no system installation or PATH changes.
$nasm=Join-Path $work 'nasm-3.02\nasm.exe'
if(!(Test-Path $nasm)){
 $zip=Join-Path $work 'nasm-3.02-win64.zip'
 Invoke-WebRequest -UseBasicParsing 'https://www.nasm.us/pub/nasm/releasebuilds/3.02/win64/nasm-3.02-win64.zip' -OutFile $zip
 if((Get-FileHash $zip -Algorithm SHA256).Hash -ne '161D0BFAFF53C2F9E9F3E69FD0672323EBABAFD1268976A5CEC11BE92A19AEE7'){throw 'NASM archive hash mismatch'}
 Expand-Archive -LiteralPath $zip -DestinationPath $work -Force
}
$cmake=Join-Path $VisualStudioPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
$vcvars=Join-Path $VisualStudioPath 'VC\Auxiliary\Build\vcvarsall.bat'
if(!(Test-Path $cmake) -or !(Test-Path $vcvars)){throw 'Install the Visual Studio C++ CMake tools and selected compiler first'}
$out=Join-Path $work ($Architecture+'\'+$Configuration)
New-Item -ItemType Directory -Force -Path $out|Out-Null
# A different initialized VC environment must not be nested (cmd has an 8191-byte limit).
$matchingEnvironment=$env:VSCMD_ARG_TGT_ARCH -eq $Architecture -and $env:VCToolsVersion -and $env:VCToolsVersion.TrimEnd('\') -eq $VCToolsVersion
if(!$matchingEnvironment){
 $env:PATH=$env:SystemRoot+'\System32;'+$env:SystemRoot+';'+$env:SystemRoot+'\System32\WindowsPowerShell\v1.0'
 foreach($name in @('INCLUDE','LIB','LIBPATH','VSCMD_VER','__VSCMD_PREINIT_PATH')){[Environment]::SetEnvironmentVariable($name,$null,'Process')}
}
# Match the Agent compiler and static CRT in every configuration.
$commands=@(
 '@echo off',
 $(if($matchingEnvironment){'rem Reuse the matching initialized Visual Studio environment'}else{'call "'+$vcvars+'" '+$Architecture+' -vcvars_ver='+$VCToolsVersion}),
 'if errorlevel 1 exit /b %errorlevel%',
 ('"'+$cmake+'" -S "'+$source+'" -B "'+$out+'" -G "NMake Makefiles" -DCMAKE_BUILD_TYPE='+$Configuration+' -DENABLE_SHARED=OFF -DWITH_CRT_DLL=OFF -DWITH_TOOLS=OFF -DCMAKE_ASM_NASM_COMPILER="'+$nasm.Replace('\','/')+'" -DCMAKE_C_FLAGS="/Gy /Gw /guard:cf"'),
 'if errorlevel 1 exit /b %errorlevel%',
 ('"'+$cmake+'" --build "'+$out+'" --target jpeg-static')
)
$cmd=Join-Path $out 'build.cmd';$commands|Set-Content -LiteralPath $cmd -Encoding ASCII
& $env:ComSpec /d /c $cmd
if($LASTEXITCODE){throw 'Static JPEG build failed'}
