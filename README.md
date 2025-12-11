# 🛡️ Análisis Forense Técnico --- Campaña con Rootkit en Modo Kernel (WinSetupMon.sys) y LOLBin Abuse

## 📄 Descripción General

Este repositorio documenta un análisis completo de una campaña avanzada
que combina:

-   **Técnicas LOLBin** usando binarios firmados por Microsoft.
-   **Rootkit en modo kernel** mediante un driver malicioso
    (`WinSetupMon.sys`).
-   **Persistencia multi-capa:** a nivel usuario, servicio y kernel.
-   **Evasión de defensas:** manipulación de Windows Defender, ETW,
    AMSI, filtros de archivos, exclusiones.
-   **Infraestructura de C2 disfrazada como tráfico legítimo** (MSN,
    Firefox, Microsoft Update, Google LLC).
-   **Cadena completa de ataque reconstruida**, IoCs, reglas YARA/Sigma
    y recomendaciones de remediación.

------------------------------------------------------------------------

# 1. Técnica LOLBin --- wmpnetwk.exe como Contenedor

## Análisis Técnico

**Binario legítimo abusado:** `wmpnetwk.exe`\
**Ubicación maliciosa:**

    C:\Windows\WinS\

Atributos: `hidden + system`

**Persistencia vía Servicio (NSSM):** - NSSM ejecuta el binario legítimo
fuera de su ruta normal. - Punto crítico: diferencia entre ruta legítima
y ruta maliciosa.

**Impacto:**\
Permite ejecutar drivers maliciosos desde un proceso con contexto
privilegiado.

------------------------------------------------------------------------

# 2. Rootkit Kernel --- Driver WinSetupMon.sys

### Metadatos

    Nombre: WinSetupMon.sys
    Ruta: C:\Windows\System32\drivers\WinSetupMon.sys
    Tipo: Boot-start
    Grupo: FSFilter Bottom
    Firma: Sin firmar
    Tamaño: 187,392 bytes
    Fecha: 2024-04-15 08:32:17 UTC

### Capacidades Identificadas

-   **Hooking de disco:** intercepta `IRP_MJ_READ` / `IRP_MJ_WRITE`.
-   **Ocultamiento de archivos.**
-   **Persistencia temprana:** Start=0, carga al arranque.
-   **FSFilter Bottom:** intercepta toda E/S del sistema.
-   **Canal kernel-user mediante SymbolicLink.**

### Extracto de análisis estático (resumido)

``` asm
IoCreateDevice
IoCreateSymbolicLink
FsFilterRegister
IRP_MJ_CREATE handler
```

------------------------------------------------------------------------

# 3. Componentes Relacionados

## WinRing0x64.sys (Driver legítimo abusado)

    SHA256: 66fd615734e2b6a9160dc2c76da5f25d9a1adce51073bf9e38de73e2eaca0233
    Origen: OpenLibSys
    Firma: válida pero expirada
    Uso malicioso: acceso de bajo nivel a hardware

## AscFileFilter.sys (Driver vulnerable)

    Clasificación: PUP.Gen
    Firma: inválida
    Vector adicional de inyección

## Script wd.bat --- Deshabilitación de defensas

``` batch
powershell -Command "Add-MpPreference -ExclusionPath 'C:\Windows\WinS'"
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
netsh advfirewall set allprofiles state off
reg add "...DisableAntiSpyware" /d 1 /f
```

------------------------------------------------------------------------

# 4. Cadena de Ataque Reconstruida

## Fase 1: Infiltración

-   Phishing con CVE-2021-40444.
-   PowerShell Dropper.
-   UAC Bypass (CMSTPLUA).
-   Persistencia inicial via Run Key + Scheduled Task.

## Fase 2: Persistencia Avanzada

``` mermaid
graph TD
A[Ganar admin] --> B[Crear C:\Windows\WinS]
B --> C[Copiar wmpnetwk.exe]
C --> D[Instalar NSSM como servicio WMS]
D --> E[Ejecutar binario legítimo fuera de ruta]
E --> F[Cargar WinSetupMon.sys]
F --> G[Hooks FSFilter]
G --> H[Ocultamiento]
```

## Fase 3: Post-explotación

1.  Recon interno (Empire / BloodHound)
2.  Movimiento lateral (SMB/WMI)
3.  Exfiltración vía HTTPS
4.  Descarga de herramientas (Mimikatz, Rubeus)

## Fase 4: Evasión Continua

-   Limpieza de logs\
-   Manipulación ETW\
-   Exfiltración disfrazada

------------------------------------------------------------------------

# 5. IoCs Completo

## Hashes

  Archivo                SHA256      MD5         Notas
  ---------------------- ----------- ----------- -------------------------
  WinSetupMon.sys        9c178b...   a89f2c...   Rootkit
  wmpnetwk.exe (copia)   d41d8c...   ---         Ruta anómala
  WinRing0x64.sys        66fd61...   c7a3d8...   Con firma expirada
  nssm.exe               f8c5c8...   b5a6c7...   Usado para persistencia

## Rutas clave

``` yaml
C:\Windows\WinS\wmpnetwk.exe
C:\Windows\System32\drivers\WinSetupMon.sys
C:\Windows\Temp\WinRing0x64.sys
%programfiles%\advanced systemcare pro\drivers\AscFileFilter.sys
C:\Windows\Tasks\wd.bat
```

## Registry Keys

``` yaml
HKLM\SYSTEM\CCS\Services\WMS
HKLM\SYSTEM\CCS\Services\WinSetupMon
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsMediaService
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths
```

## Procesos maliciosos

    wmpnetwk.exe (fuera de system32)
    nssm.exe
    powershell.exe

------------------------------------------------------------------------

# 6. Infraestructura C2

## IPs

  IP               ASN       País   ISP
  ---------------- --------- ------ -----------
  104.156.51.181   AS5650    US     Frontier
  104.46.162.225   AS8075    AU     Microsoft
  108.177.10.188   AS15169   US     Google
  108.177.15.188   AS15169   US     Google

## Dominios usados

``` python
[
 "api.msn.com",
 "assets.msn.com",
 "crt.sectigo.com",
 "firefox.settings.services.mozilla.com",
 "update.microsoft.com.nsatc.net"
]
```

------------------------------------------------------------------------

# 7. Reglas de Detección

## YARA

``` yara
rule WinSetupMon_Rootkit {
    meta:
        author = "CSIRT Team"
    strings:
        $s1 = "WinSetupMon" wide
        $s2 = "FSFilter Bottom" wide
        $s3 = { 48 8B C4 48 89 58 08 }
    condition:
        uint16(0) == 0x5A4D and filesize < 200000 and 2 of them
}
```

## Sigma

``` yaml
title: WMS Service Anomaly
EventID: 7045
ServiceName: "WMS"
ImagePath|contains: "\WinS\"
level: high
```

------------------------------------------------------------------------

# 8. Remediación

## Contención inmediata

``` powershell
Stop-Service WMS -Force
sc delete WMS
sc stop WinSetupMon
sc delete WinSetupMon
Remove-Item "C:\Windows\System32\drivers\WinSetupMon.sys" -Force
Remove-Item "C:\Windows\WinS" -Recurse -Force
```

## Restauración de defensas

``` powershell
Remove-MpPreference -ExclusionPath "C:\Windows\WinS"
Set-MpPreference -DisableRealtimeMonitoring $false
```

## Hardening

-   Activar HVCI\
-   WDAC / AppLocker\
-   Bloquear rutas no estándar\
-   Monitorear drivers sin firma

------------------------------------------------------------------------

# 9. Lecciones Aprendidas

## Gaps encontrados

-   Falta de monitoreo de LOLBins
-   Falta de control de drivers no firmados
-   Poca visibilidad en creación de servicios

## Mejoras propuestas

-   EDR con visibilidad kernel (MDE / CrowdStrike)
-   Threat hunting proactivo
-   Capacitación en análisis kernel-mode

------------------------------------------------------------------------

# 10. Conclusión

Esta campaña representa un nivel de sofisticación comparable a:

-   **OPERA1ER** (uso de drivers)
-   **UNC3944 / Scattered Spider** (evasión, persistencia)

Mediante:

-   LOLBins firmados\
-   Rootkit en kernel\
-   C2 disfrazado\
-   Persistencia multinivel

Este actor demuestra capacidades avanzadas orientadas a operaciones
persistentes y evasivas.

------------------------------------------------------------------------

# 11. Anexos

-   investigation_commands.txt\
-   PCAPs y dumps de memoria (bajo solicitud)\
-   Referencias MITRE ATT&CK: T1543.003, T1547, T1014, T1562.001
