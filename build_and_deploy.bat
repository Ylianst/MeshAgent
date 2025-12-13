@echo off
setlocal EnableDelayedExpansion
title Build & Deploy Agent Custom MeshCentral

:: ==========================================
:: CONFIGURATION SERVEUR
:: ==========================================
set "SERVER_IP=141.145.194.69"
set "USER=rocky"
set "REMOTE_TEMP=/home/%USER%"
set "REMOTE_DEST=/opt/meshcentral/meshcentral-data/agents"
set "SERVICE_NAME=meshcentral"
set "FILE_NAME=MeshService64.exe"
set "LOCAL_BUILD_PATH=%~dp0Release\%FILE_NAME%"

:: ==========================================
:: 1. COMPILATION
:: ==========================================
cls
echo ========================================================
echo      BUILD ^& DEPLOY AGENT CUSTOM MESHCENTRAL
echo ========================================================
echo.
echo [1/4] Compilation de l'agent en cours...
echo.

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" "%~dp0MeshAgent.sln" /p:Configuration=Release /p:Platform=x64 /verbosity:minimal /nologo

:: ==========================================
:: 2. VERIFICATION DES ERREURS
:: ==========================================
if %errorlevel% neq 0 (
    color 0C
    echo.
    echo ========================================================
    echo [X] ECHEC DE LA COMPILATION
    echo ========================================================
    echo.
    echo     La compilation a echoue avec des erreurs.
    echo     Veuillez corriger les erreurs ci-dessus avant de
    echo     continuer.
    echo.
    pause
    exit /b 1
)

:: Vérifier que le fichier a bien été créé
if not exist "%LOCAL_BUILD_PATH%" (
    color 0C
    echo.
    echo ========================================================
    echo [X] FICHIER INTROUVABLE
    echo ========================================================
    echo.
    echo     Le fichier compile "%FILE_NAME%" est introuvable
    echo     dans le dossier Release.
    echo.
    pause
    exit /b 1
)

color 0A
echo.
echo ========================================================
echo [OK] COMPILATION REUSSIE
echo ========================================================
echo.
echo     Fichier genere : %LOCAL_BUILD_PATH%
echo.

:: ==========================================
:: 3. PROPOSITION DE DEPLOIEMENT
:: ==========================================
color 0E
echo ========================================================
echo      DEPLOIEMENT SUR LE SERVEUR ?
echo ========================================================
echo.
echo     Serveur cible : %SERVER_IP%
echo     Utilisateur   : %USER%
echo     Destination   : %REMOTE_DEST%
echo.
set /p "DEPLOY_CHOICE=Voulez-vous deployer sur le serveur ? (O/N) : "

if /i not "%DEPLOY_CHOICE%"=="O" if /i not "%DEPLOY_CHOICE%"=="OUI" if /i not "%DEPLOY_CHOICE%"=="Y" if /i not "%DEPLOY_CHOICE%"=="YES" (
    color 0E
    echo.
    echo [i] Deploiement annule par l'utilisateur.
    echo.
    echo     Le fichier compile se trouve ici :
    echo     %LOCAL_BUILD_PATH%
    echo.
    pause
    exit /b 0
)

:: ==========================================
:: 4. TRANSFERT SCP
:: ==========================================
color 07
echo.
echo ========================================================
echo [2/4] Transfert vers le serveur...
echo ========================================================
echo.

scp "%LOCAL_BUILD_PATH%" %USER%@%SERVER_IP%:%REMOTE_TEMP%/%FILE_NAME%

if %errorlevel% neq 0 (
    color 0C
    echo.
    echo ========================================================
    echo [X] ECHEC DU TRANSFERT SCP
    echo ========================================================
    echo.
    echo     Verifiez :
    echo     - Votre connexion SSH
    echo     - Vos cles SSH (ssh-keygen / ssh-copy-id)
    echo     - L'acces au serveur %SERVER_IP%
    echo.
    pause
    exit /b 1
)

:: ==========================================
:: 5. INSTALLATION ET SIGNATURE AUTO
:: ==========================================
echo.
echo ========================================================
echo [3/4] Installation et redemarrage MeshCentral...
echo ========================================================
echo.

ssh %USER%@%SERVER_IP% "echo '[Server] Creation dossier agents...' && sudo mkdir -p %REMOTE_DEST% && echo '[Server] Deplacement agent custom...' && sudo mv -f %REMOTE_TEMP%/%FILE_NAME% %REMOTE_DEST%/%FILE_NAME% && echo '[Server] Application permissions...' && sudo chown root:root %REMOTE_DEST%/%FILE_NAME% && sudo chmod 755 %REMOTE_DEST%/%FILE_NAME% && echo '[Server] Redemarrage MeshCentral...' && sudo systemctl restart %SERVICE_NAME%"

if %errorlevel% neq 0 (
    color 0C
    echo.
    echo ========================================================
    echo [X] ECHEC DE L'INSTALLATION SERVEUR
    echo ========================================================
    echo.
    echo     L'installation ou le redemarrage a echoue.
    echo     Connectez-vous au serveur pour diagnostiquer :
    echo     ssh %USER%@%SERVER_IP%
    echo.
    pause
    exit /b 1
)

:: ==========================================
:: 6. VERIFICATION DU REDEMARRAGE
:: ==========================================
echo.
echo ========================================================
echo [4/5] Verification du service MeshCentral...
echo ========================================================
echo.
echo [+] Attente du demarrage du service (5 secondes)...
timeout /t 5 /nobreak >nul

ssh %USER%@%SERVER_IP% "sudo systemctl is-active %SERVICE_NAME% && echo '[OK] Service %SERVICE_NAME% est actif' || echo '[ERREUR] Service %SERVICE_NAME% non actif'"

if %errorlevel% neq 0 (
    color 0C
    echo.
    echo ========================================================
    echo [!] ATTENTION : Le service ne semble pas actif
    echo ========================================================
    echo.
    echo     Verifiez les logs :
    echo     ssh %USER%@%SERVER_IP% "sudo journalctl -u %SERVICE_NAME% -n 50"
    echo.
    set /p "CONTINUE=Continuer quand meme ? (O/N) : "
    if /i not "!CONTINUE!"=="O" if /i not "!CONTINUE!"=="OUI" (
        pause
        exit /b 1
    )
)

:: ==========================================
:: 7. VERIFICATION DE LA SIGNATURE
:: ==========================================
echo.
echo ========================================================
echo [5/5] Verification de la signature automatique...
echo ========================================================
echo.
echo [+] Attente de la signature par MeshCentral (10 secondes)...
timeout /t 10 /nobreak >nul

echo.
echo [+] Verification des agents signes...
echo.

ssh %USER%@%SERVER_IP% "if [ -d /opt/meshcentral/meshcentral-data/signedagents ]; then echo '[OK] Dossier signedagents existe' && ls -lh /opt/meshcentral/meshcentral-data/signedagents/ | grep -i mesh && echo '' && echo '[+] Nombre d agent(s) signe(s) :' && ls -1 /opt/meshcentral/meshcentral-data/signedagents/ | wc -l; else echo '[!] Dossier signedagents non trouve - La signature se fera a la premiere connexion d un agent'; fi"

if %errorlevel% neq 0 (
    color 0E
    echo.
    echo ========================================================
    echo [i] INFORMATION
    echo ========================================================
    echo.
    echo     Le dossier signedagents n'existe pas encore.
    echo     C'est normal si c'est le premier deploiement.
    echo.
    echo     MeshCentral signera automatiquement l'agent lors de
    echo     la premiere connexion d'un appareil.
    echo.
)

:: ==========================================
:: 8. SUCCES FINAL
:: ==========================================
color 0A
cls
echo.
echo ========================================================
echo      DEPLOIEMENT TERMINE AVEC SUCCES !
echo ========================================================
echo.
echo [+] Compilation         : OK
echo [+] Transfert SCP       : OK
echo [+] Installation        : OK
echo [+] Redemarrage service : OK
echo [+] Verification service: OK
echo [+] Signature auto      : En cours / OK
echo.
echo --------------------------------------------------------
echo   AGENT CUSTOM DEPLOYE
echo --------------------------------------------------------
echo.
echo   Serveur     : %SERVER_IP%
echo   Emplacement : %REMOTE_DEST%/%FILE_NAME%
echo   Signature   : AUTOMATIQUE par MeshCentral
echo.
echo --------------------------------------------------------
echo   PROCHAINES ETAPES
echo --------------------------------------------------------
echo.
echo   1. MeshCentral va automatiquement detecter le nouvel
echo      agent et le signer avec son certificat interne.
echo.
echo   2. L'agent signe sera disponible dans :
echo      /opt/meshcentral/meshcentral-data/signedagents/
echo.
echo   3. Les nouveaux appareils utiliseront automatiquement
echo      ton agent custom avec les correctifs UAC/lock screen.
echo.
echo   4. Pour forcer les agents existants a se mettre a jour :
echo      - Depuis MeshCentral ^> My Devices
echo      - Selectionner appareils ^> Actions ^> Update Agent
echo.
echo ========================================================
echo.
pause
