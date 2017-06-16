//@echo Off
REM MyGet Build Commands

set config=%1
if "%config%" == "" (
   set config=Release
)

set version=-Version 1.0.0
if not "%PackageVersion%" == "" (
   set version=-Version %PackageVersion%
)

REM Restore packages
@echo %Nuget% restore Neo4j.AspNet.Identity.Core.sln
%Nuget% restore Neo4j.AspNet.Identity.Core.sln
if not "%errorlevel%"=="0" goto failure
@echo Packages restored - on to build...

REM Build
@echo "%MsBuildExe%" Neo4j.AspNet.Identity.Core.sln /p:Configuration="%config%" /m /v:M /fl /flp:LogFile=msbuild.log;Verbosity=Normal /nr:false
"%MsBuildExe%" Neo4j.AspNet.Identity.Core.sln /p:Configuration="%config%" /m /v:M /fl /flp:LogFile=msbuild.log;Verbosity=Normal /nr:false
if not "%errorlevel%"=="0" goto failure
@echo Built and onto tests....


REM XUnit tests
@echo %Nuget% install xunit.runner.console -Version 2.2.0 -OutputDirectory packages
%Nuget% install xunit.runner.console -Version 2.2.0 -OutputDirectory packages
if not "%errorlevel%"=="0" goto failure
@echo XUnit installed...

@echo packages\xunit.runner.console.2.2.0\tools\xunit.console.x86.exe Neo4j.AspNet.Identity.Core.Tests\bin\%config%\Neo4j.AspNet.Identitiy.Core.Tests.dll
packages\xunit.runner.console.2.2.0\tools\xunit.console.x86.exe Neo4j.AspNet.Identity.Core.Tests\bin\%config%\Neo4j.AspNet.Identitiy.Core.Tests.dll
if not "%errorlevel%"=="0" goto failure
@echo Neo4jClient tests... SUCCESS.

REM Package
mkdir Artifacts
@echo %Nuget% pack "Neo4j.AspNet.Identity.Core.nuspec" -o Artifacts -p Configuration=%config% %version%
%Nuget% pack "Neo4j.AspNet.Identity.Core.nuspec" -o Artifacts -p Configuration=%config% %version%
if not "%errorlevel%"=="0" goto failure
@echo Packed and ready to roll!

:success
exit 0

:failure
exit -1