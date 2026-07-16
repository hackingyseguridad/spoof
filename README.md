### Spoof - herramientas de spoofing IPv4 e IPv6

[![GitHub](https://img.shields.io/badge/GitHub-hackingyseguridad%2Fspoof-informational?logo=github)](https://github.com/hackingyseguridad/spoof)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)](#plataformas-soportadas)
[![Languages](https://img.shields.io/badge/Languages-Python%20%7C%20Perl%20%7C%20Shell%20%7C%20C-green.svg)](#requisitos)
[![Scripts](https://img.shields.io/badge/Scripts-16%20herramientas-orange.svg)](#descripción-de-scripts)

Colección profesional de herramientas para realizar pruebas de **IP Spoofing** en entornos controlados. Incluye 16 scripts especializados en Python, Perl, Shell y C para suplantación de direcciones IPv4 e IPv6.

---

### Tabla de Contenidos

- [Descripción General](#descripción-general)
- [Advertencia Legal](#⚠️-advertencia-legal)
- [Características](#características)
- [Plataformas Soportadas](#plataformas-soportadas)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Estructura del Repositorio](#estructura-del-repositorio)
- [Descripción de Scripts](#descripción-de-scripts)
- [Tabla Comparativa de Herramientas](#tabla-comparativa-de-herramientas)
- [Ejemplos de Uso](#ejemplos-de-uso)
- [Acerca de IP Spoofing](#acerca-de-ip-spoofing)
- [Comportamiento del Enrutador](#comportamiento-del-enrutador)
- [Defensa contra Spoofing](#defensa-contra-spoofing)
- [Notas de Seguridad](#notas-de-seguridad)
- [Referencias](#referencias)

---

### Descripción

**Spoof** es una colección integral de herramientas de prueba de penetración diseñadas para realizar **IP Spoofing** (suplantación de direcciones IP). Este repositorio contiene 16 scripts especializados que permiten:

- 🎭 Suplantación de direcciones IPv4 y IPv6
- 🔌 Spoofing de múltiples protocolos (TCP, UDP, ICMP)
- 🌐 Técnicas avanzadas de spoofing privadas y reservadas
- 📊 Pruebas de robustez en infraestructuras de red
- 🔍 Análisis de filtrado Reverse Path Forwarding (RPF)
- 🛡️ Evaluación de mecanismos de seguridad anti-spoofing

**⚠️ IMPORTANTE:** Esta herramienta es solo para uso educativo y pruebas autorizadas. Cualquier uso sin autorización es ilegal.

---

##@ Advertencia legal

**DISCLAIMER:** 

Este software está diseñado únicamente para:
- ✅ Investigación académica
- ✅ Pruebas autorizadas en entornos controlados
- ✅ Evaluación de seguridad con consentimiento explícito
- ✅ Fines educativos en ciberseguridad

**Está PROHIBIDO:**
- ❌ Usar contra sistemas sin autorización
- ❌ Realizar ataques a terceros (DoS, DDoS)
- ❌ Violar leyes de ciberseguridad
- ❌ Falsificar direcciones para fraude
- ❌ Evadir mecanismos de seguridad

**Los autores NO son responsables de cualquier uso ilegal o malintencionado.**

---

### ✨ Características

| Característica | Descripción |
|---|---|
| 🐍 **Scripts Python** | Spoofing avanzado con Scapy (6 herramientas) |
| 🐚 **Scripts Shell** | Bash/shell avanzado con herramientas estándar (5 tools) |
| 📝 **Scripts Perl** | Implementaciones Perl eficientes (2 herramientas) |
| 🔧 **Código C** | UDP Spoof compilable y de alto rendimiento |
| 📊 **IPv4 & IPv6** | Soporte completo para ambas versiones de IP |
| 🔌 **Múltiples Protocolos** | TCP, UDP, ICMP, ICMPv6 |
| 📋 **Datos Integrados** | Listas de IPs reservadas para pruebas |
| 🎯 **Integraciones** | Curl, wget, nmap, netcat, T50 |
| 🚀 **Alto Rendimiento** | Técnicas optimizadas de spoofing |
| 📚 **Educativo** | Código comentado y bien documentado |

---

### Plataformas soportadas

| Sistema Operativo | Scripts | Requisitos |
|---|---|---|
| **Linux** | Todos (16) | bash, python3, perl, gcc, scapy, libnet |
| **macOS** | Python, Perl, Shell | bash, python3, perl, libnet |
| **Windows (WSL/Cygwin)** | Python, Perl | WSL2, python3, perl |
| **Windows (Nativo)** | Limitado | PowerShell, Python3 |

---

### requisitos

### Por Tipo de Script

#### **Scripts Python (61.8% del código)**

```bash
# Sistema operativo
- Python 3.6 o superior
- pip (gestor de paquetes)

# Dependencias Python
- Scapy 2.4.0+ (construcción de paquetes)
- Recomendado: IPython

# Sistema
- Permisos de administrador/sudo
```

#### **Scripts Shell (10.8% del código)**

```bash
# Sistema operativo
- Linux o macOS
- Bash 4.0 o superior

# Herramientas requeridas por script:
- nmap (spoofnmap.sh)
- netcat (spoofnetcat.sh)
- T50 tool (t50spoof.sh)
- herramientas estándar (ping, etc)

# Permisos
- sudo/root para operaciones raw socket
```

#### **Scripts Perl (7.4% del código)**

```bash
# Sistema operativo
- Perl 5.10 o superior

# Módulos Perl
- Net::RawIP
- Socket
- perllib-net-packet

# Herramientas
- libnet para compilación
- gcc para módulos compilados
```

#### **Código C (20.0% del código)**

```bash
# Compilación
- gcc o clang
- libnet-dev
- libpcap-dev
- make

# Ejecución
- sudo/root
```

### Instalación de Dependencias Globales

**Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install -y \
    python3 python3-pip python3-dev \
    perl libnet-dev \
    gcc make libpcap-dev \
    nmap netcat curl wget \
    build-essential git
    
pip install scapy
```

**CentOS/RHEL:**
```bash
sudo yum install -y \
    python3 python3-pip python3-devel \
    perl perl-devel \
    gcc make libpcap-devel \
    nmap netcat curl wget \
    libnet-devel

pip install scapy
```

**macOS:**
```bash
brew install python3 perl gcc libnet netcat nmap curl wget
pip3 install scapy
```

---

### Instalación

### 1. Clonar el Repositorio

```bash
git clone https://github.com/hackingyseguridad/spoof.git
cd spoof
```

### 2. Dar Permisos de Ejecución

```bash
# Scripts Python
chmod +x ipv6spoof.py ipv6spooficmp.py ipv6spoofprivadas.py \
         ipv6spoofudp.py spooftcp.py

# Scripts Shell
chmod +x spoofipv6.sh spoofnetcat.sh spoofnmap.sh \
         t50spoof.sh curlspoof wgetspoof

# Scripts Perl
chmod +x spoof2.pl spoofdos.pl
```

### 3. Compilar Código C (Opcional)

```bash
# Compilar UDP Spoof
gcc -o udpspoof udpspoof.c -lnet
chmod +x udpspoof

# Verificar compilación
./udpspoof -h
```

### 4. Instalar T50 (Opcional pero Recomendado)

```bash
# T50 es necesario para t50spoof.sh
git clone https://github.com/somakbl/T50.git
cd T50
chmod +x configure
./configure
make
sudo make install
```

---

### Estructura del repositorio

```
spoof/
├── README.md                      # Este archivo (documentación)
├── LICENSE                        # Licencia MIT
│
├── SCRIPTS PYTHON (61.8%)
├── ipv6spoof.py                  # Spoof IPv6 ICMP básico
├── ipv6spooficmp.py             # Spoof IPv6 ICMP especializado
├── ipv6spoofprivadas.py         # Spoof IPv6 privadas
├── ipv6spoofudp.py              # Spoof IPv6 UDP
├── spooftcp.py                   # Spoof TCP genérico
│
├── SCRIPTS PERL (7.4%)
├── spoof2.pl                     # Spoof Perl avanzado
├── spoofdos.pl                   # Spoof DoS Perl
│
├── SCRIPTS SHELL (10.8%)
├── spoofipv6.sh                 # Spoof IPv6 shell
├── spoofnetcat.sh               # Spoof con netcat
├── spoofnmap.sh                 # Spoof con nmap
├── t50spoof.sh                  # Spoof con T50
├── curlspoof                    # Spoof con curl
├── wgetspoof                    # Spoof con wget
│
├── CÓDIGO C (20.0%)
├── udpspoof.c                   # Código fuente C UDP
├── udpspoof                     # Binario compilado UDP
│
└── DATOS
    ├── ipv4reservados.txt       # Lista IPv4 reservadas
    └── ipv6reservados.txt       # Lista IPv6 reservadas
```

---

### Scripts

### Tabla Maestra de Herramientas

| # | Nombre | Tipo | Lenguaje | Protocolo | IPv4 | IPv6 | Protocolo L4 | Complejidad |
|---|--------|------|----------|-----------|------|------|--------------|------------|
| 1 | **ipv6spoof.py** | Test | Python | IPv6 | ❌ | ✅ | ICMP | 🟢 Media |
| 2 | **ipv6spooficmp.py** | Especializado | Python | IPv6 | ❌ | ✅ | ICMP | 🟡 Alta |
| 3 | **ipv6spoofprivadas.py** | Test | Python | IPv6 | ❌ | ✅ | ICMP | 🟢 Media |
| 4 | **ipv6spoofudp.py** | Especializado | Python | IPv6 | ❌ | ✅ | UDP | 🟡 Alta |
| 5 | **spooftcp.py** | Genérico | Python | IPv4/IPv6 | ✅ | ✅ | TCP | 🔴 Alta |
| 6 | **spoof2.pl** | Avanzado | Perl | IPv4 | ✅ | ❌ | Mixto | 🔴 Alta |
| 7 | **spoofdos.pl** | Ataque | Perl | IPv4 | ✅ | ❌ | Mixto | 🔴 Muy Alta |
| 8 | **spoofipv6.sh** | Test | Shell | IPv6 | ❌ | ✅ | ICMP | 🟢 Baja |
| 9 | **spoofnetcat.sh** | Genérico | Shell | IPv4/IPv6 | ✅ | ✅ | TCP | 🟡 Media |
| 10 | **spoofnmap.sh** | Integración | Shell | IPv4/IPv6 | ✅ | ✅ | Múltiple | 🟡 Media |
| 11 | **t50spoof.sh** | Avanzado | Shell | IPv4/IPv6 | ✅ | ✅ | Múltiple | 🔴 Alta |
| 12 | **curlspoof** | HTTP | Shell | IPv4 | ✅ | ❌ | TCP | 🟢 Baja |
| 13 | **wgetspoof** | HTTP | Shell | IPv4 | ✅ | ❌ | TCP | 🟢 Baja |
| 14 | **udpspoof** | UDP Raw | C | IPv4 | ✅ | ❌ | UDP | 🔴 Muy Alta |
| 15 | **udpspoof.c** | Código Fuente | C | IPv4 | ✅ | ❌ | UDP | 🔴 Muy Alta |
| 16 | Archivos .txt | Data | Texto | - | ✅ | ✅ | - | - |

---

### Script

### SCRIPTS PYTHON

#### 1️⃣ **ipv6spoof.py** - Spoof IPv6 ICMP Básico

**Descripción:** Script que prueba múltiples direcciones IPv6 reservadas y privadas contra un destino.

**Características:**
- Envío a múltiples IPs origen (20+ variaciones)
- Protocolo ICMP Echo Request
- Interfaz configuración directa

**Parámetros Configurables:**
```python
ipdestino = "2002:9140:3c01:1000:7e20:fd5d:dc94:b192"  # IP destino
iface = "enp1s12"  # Interfaz de red
count = 999  # Número de paquetes
```

**Uso:**
```bash
sudo python3 ipv6spoof.py
```

---

#### 2️⃣ **ipv6spooficmp.py** - Spoof IPv6 ICMP Especializado

**Descripción:** Spoofing IPv6 enfocado en ICMP con técnicas avanzadas.

**Características:**
- Técnicas ICMP especializadas
- Fragmentación IPv6 opcional
- Detección de filtrado

**Parametrización:**
```python
# Editar en el script:
destino = "TARGET_IPV6"
origen_falsa = "SPOOF_IPV6"
interfaz = "eth0"
```

**Uso:**
```bash
sudo python3 ipv6spooficmp.py
```

---

#### 3️⃣ **ipv6spoofprivadas.py** - Spoof IPv6 Privadas

**Descripción:** Especializado en spoofing con IPs privadas/reservadas IPv6.

**Características:**
- Prueba de rangos privados
- Detección de filtrado RPF
- Múltiples origenes

**Rangos Probados:**
- Link-Local (fe80::/10)
- Unique Local (fc00::/7)
- Multicast (ff00::/8)
- Loopback (::1)

**Uso:**
```bash
sudo python3 ipv6spoofprivadas.py
```

---

#### 4️⃣ **ipv6spoofudp.py** - Spoof IPv6 UDP

**Descripción:** Spoofing UDP sobre IPv6.

**Características:**
- Paquetes UDP personalizados
- Puerto origen aleatorio/configurado
- Payload customizable

**Parámetros:**
```python
ip_destino = "2001:db8::1"
puerto_destino = 53  # DNS
payload = "test"
```

**Uso:**
```bash
sudo python3 ipv6spoofudp.py
```

---

#### 5️⃣ **spooftcp.py** - Spoof TCP Genérico

**Descripción:** Spoofing TCP versátil para IPv4 e IPv6.

**Características:**
- Soporte dual stack (IPv4/IPv6)
- TCP flags configurables
- Sequencing avanzado

**Sintaxis:**
```bash
sudo python3 spooftcp.py <IP_ORIGEN_FALSA> <IP_DESTINO> <PUERTO>
```

**Ejemplo:**
```bash
sudo python3 spooftcp.py 192.168.1.100 10.0.0.1 80
sudo python3 spooftcp.py 2001:db8::1 2001:db8::2 443
```

---

### SCRIPTS PERL

#### 6️⃣ **spoof2.pl** - Spoof Perl Avanzado

**Descripción:** Herramienta Perl de spoofing con capacidades avanzadas.

**Características:**
- Uso de Net::RawIP
- Spoofing raw packet
- Compatibilidad multiplataforma

**Compilación:**
```bash
perl spoof2.pl
```

---

#### 7️⃣ **spoofdos.pl** - Spoof DoS Perl

**Descripción:** Script especializado en DoS mediante spoofing.

**Características:**
- Ataque DoS automatizado
- Tasa de envío configurable
- Múltiples técnicas

**Sintaxis:**
```bash
perl spoofdos.pl <TARGET_IP> <SOURCE_IP> <PACKETS>
```

---

### SCRIPTS SHELL

#### 8️⃣ **spoofipv6.sh** - Spoof IPv6 Shell

**Descripción:** Implementación bash de spoofing IPv6.

**Características:**
- Sin dependencias complejas
- Interfaz simple
- Rápido

**Sintaxis:**
```bash
./spoofipv6.sh <IPV6_DESTINO> <IPV6_ORIGEN>
```

---

#### 9️⃣ **spoofnetcat.sh** - Spoof con Netcat

**Descripción:** Spoofing aprovechando netcat para TCP/UDP.

**Características:**
- Funciona con herramientas estándar
- TCP/UDP flexible
- Bajo overhead

**Sintaxis:**
```bash
./spoofnetcat.sh <TARGET> <PORT> [OPTIONS]
```

---

#### 🔟 **spoofnmap.sh** - Spoof con Nmap

**Descripción:** Integración con nmap para spoofing avanzado.

**Características:**
- Opciones nmap completas
- Spoofing integrado
- Escaneo + spoof

**Sintaxis:**
```bash
./spoofnmap.sh <TARGET> <SPOOF_IP> [NMAP_OPTIONS]
```

**Ejemplo:**
```bash
./spoofnmap.sh 192.168.1.1 10.0.0.100 -p 22,80,443
```

---

#### 1️⃣1️⃣ **t50spoof.sh** - Spoof con T50

**Descripción:** Usa T50 (herramienta de flood) para spoofing avanzado.

**Características:**
- Múltiples protocolos
- Alto rendimiento
- Técnicas avanzadas

**Requisitos:**
- T50 debe estar instalado
- `sudo apt install t50` o compilar desde fuente

**Sintaxis:**
```bash
./t50spoof.sh <TARGET> <PROTOCOL> [OPTIONS]
```

---

#### 1️⃣2️⃣ **curlspoof** - Spoof con Curl

**Descripción:** Spoofing de solicitudes HTTP usando curl.

**Características:**
- Falsificación de User-Agent
- Headers personalizados
- Proxy integration

**Sintaxis:**
```bash
./curlspoof <URL> <SPOOF_IP>
```

---

#### 1️⃣3️⃣ **wgetspoof** - Spoof con Wget

**Descripción:** Spoofing HTTP mediante wget.

**Características:**
- Headers HTTP falsos
- Referrer spoofing
- User-Agent falso

**Sintaxis:**
```bash
./wgetspoof <URL> <FAKE_REFERRER>
```

---

### CÓDIGO C

#### 1️⃣4️⃣ **udpspoof.c & udpspoof** - UDP Spoof C

**Descripción:** Implementación C de alto rendimiento para UDP spoofing.

**Características:**
- Máximo rendimiento
- Raw socket directo
- Bajo overhead

**Compilación:**
```bash
gcc -o udpspoof udpspoof.c -lnet
```

**Sintaxis:**
```bash
sudo ./udpspoof <IP_ORIGEN> <IP_DESTINO> <PUERTO_DESTINO> <PUERTO_ORIGEN>
```

**Ejemplo:**
```bash
sudo ./udpspoof 10.0.0.100 192.168.1.1 53 5000
```

---

### ARCHIVOS DE DATOS

#### **ipv4reservados.txt**
- Lista de rangos IPv4 reservados
- Para uso en pruebas
- Ranges como 127.0.0.0/8, 10.0.0.0/8, etc.

#### **ipv6reservados.txt**
- Lista de rangos IPv6 reservados
- Para testing
- Link-local, Unique Local, etc.

---

### Comparativa 

| Aspecto | Python | Perl | Shell | C |
|--------|--------|------|-------|---|
| **Rendimiento** | 🟡 Medio | 🟡 Medio | 🟢 Bajo | 🔴 Alto |
| **Facilidad** | 🟢 Fácil | 🟡 Medio | 🟢 Fácil | 🔴 Difícil |
| **Flexibilidad** | 🔴 Muy Alta | 🟡 Alta | 🟢 Media | 🟡 Limitada |
| **Portabilidad** | 🔴 Muy Alta | 🟡 Alta | 🟡 Alta | 🟢 Baja |
| **Dependencias** | 🟡 Scapy | 🟡 Net::RawIP | 🟢 Ninguna | 🟡 libnet |
| **Prototipado** | 🔴 Excelente | 🟡 Bueno | 🟢 Rápido | ❌ Lento |
| **Producción** | 🟡 Bueno | 🟡 Bueno | 🟡 Bueno | 🔴 Óptimo |

---

##€ Ejemplos de uso

### Escenario 1: Test IPv6 Básico

```bash
# Editar destino en script
nano ipv6spoof.py

# Ejecutar
sudo python3 ipv6spoof.py
```

### Escenario 2: Spoof TCP contra Servidor

```bash
# Spoof TCP hacia puerto 80
sudo python3 spooftcp.py 192.168.1.100 10.0.0.50 80
```

### Escenario 3: Escaneo con Spoofing

```bash
# Escanear objetivo usando IP falsa como origen
./spoofnmap.sh 192.168.1.1 10.0.0.100 -sS -p 1-1000
```

### Escenario 4: UDP Flood Spoofed

```bash
# Compilar UDP spoof
gcc -o udpspoof udpspoof.c -lnet

# Ejecutar spoofing UDP
sudo ./udpspoof 192.168.1.100 10.0.0.1 53 5000
```

### Escenario 5: HTTP Spoofing

```bash
# Usar curl con User-Agent falso
./curlspoof "http://example.com" "192.168.1.1"

# Usar wget con referrer falso
./wgetspoof "http://example.com" "http://fake-referrer.com"
```

### Escenario 6: Testing con Netcat

```bash
# Enviar datos falsos
./spoofnetcat.sh 192.168.1.1 80 "GET / HTTP/1.1"
```

---

### Acerca de IP Spoofing

### ¿Qué es IP Spoofing?

**IP Spoofing** es la técnica de:
- 🎭 Falsificar la dirección IP origen de paquetes
- 📬 Hacer parecer que provienen de otra máquina
- 🔍 Evadir mecanismos de filtrado
- 🛡️ Probar defensas anti-spoofing

### Tipos de Spoofing

| Tipo | IPv4 | IPv6 | Protocolo | Complejidad |
|------|------|------|-----------|------------|
| **Blind Spoofing** | ✅ | ✅ | TCP/UDP | 🟢 Baja |
| **Non-Blind Spoofing** | ✅ | ✅ | TCP/UDP | 🟡 Media |
| **ICMP Spoofing** | ✅ | ✅ | ICMP | 🟢 Baja |
| **DNS Spoofing** | ✅ | ❌ | UDP:53 | 🟡 Media |
| **ARP Spoofing** | ✅ | ❌ | ARP | 🟢 Baja |
| **IPv6 Spoofing** | ❌ | ✅ | IPv6 | 🟡 Media |

### Aplicaciones Legítimas

✅ **Seguridad:**
- Pruebas de filtrado RPF
- Validación de políticas ACL
- Testing de IDS/IPS

✅ **Investigación:**
- Análisis de topología
- Estudio de enrutamiento
- Pruebas de seguridad

---

## 🔄 Comportamiento del Enrutador

Cuando se envía un paquete spoofed desde la LAN al router:

### Escenario 1: Filtrado RPF Activado
```
┌─ Paquete con IP origen falsa
├─ Router verifica: ¿Viene de interfaz correcta?
├─ NO CUMPLE
└─ DESCARTA ❌
```

**Resultado:** Paquete rechazado (protección activa)

### Escenario 2: Sin Filtrado - NAT Activado
```
┌─ Paquete con IP origen falsa
├─ Router NO filtra
├─ TRADUCE dirección origen → IP del router
└─ Envía paquete ✅
```

**Resultado:** Respuesta llega a router, no a origen falso

### Escenario 3: Sin Filtrado - Sin NAT
```
┌─ Paquete con IP origen falsa
├─ Router NO filtra
├─ Router NO traduce
└─ Envía paquete sin cambios ✅
```

**Resultado:** Paquete llega al destino (spoofing exitoso)

### Escenario 4: ISP Filtra Ingress (BCP 38)
```
┌─ Paquete con IP origen falsa
├─ ISP valida: ¿Origen pertenece a mi red?
├─ NO PERTENECE
└─ ISP DESCARTA ❌
```

**Resultado:** Aún si router permite, ISP puede filtrar

---

### Defensa contra Spoofing

### 1. Filtrado Ingress (BCP 38/RFC 2827)

```bash
# En el router - Entrada
iptables -A INPUT -p all -m addrtype --src-type INVALID -j DROP

# Bloquear direcciones locales desde exterior
iptables -A INPUT -i eth0 -s 10.0.0.0/8 -j DROP
iptables -A INPUT -i eth0 -s 127.0.0.0/8 -j DROP
iptables -A INPUT -i eth0 -s 192.168.0.0/16 -j DROP
```

### 2. Filtrado Egress (BCP 38/RFC 2827)

```bash
# En el router - Salida
iptables -A OUTPUT -o eth0 ! -s 192.168.1.0/24 -j DROP
```

### 3. Reverse Path Forwarding (RPF)

```bash
# Linux - Activar RPF estricto
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter

# RPF Looser (permite asymmetric routing)
echo 2 > /proc/sys/net/ipv4/conf/all/rp_filter
```

### 4. IP Source Guard (IPSG)

Configuración en switch (Cisco):
```
interface GigabitEthernet0/1
 ip verify source port-security
```

### 5. Dynamic ARP Inspection (DAI)

```
ip arp inspection vlan 1
ip arp inspection validate src-mac dst-mac ip
```

### 6. DHCP Snooping

```
ip dhcp snooping
ip dhcp snooping vlan 1
no ip dhcp snooping information option
```

---

### Notas de Seguridad

### Importantes

1. **Autorización Legal**: Obtener consentimiento escrito
2. **Ambiente Controlado**: Usar solo en redes de prueba
3. **Documentación**: Registrar todas las pruebas
4. **Responsabilidad**: Usuario responsable de sus acciones

### Mejores Prácticas

```bash
# ✅ CORRECTO: Test autorizado en red local
sudo python3 ipv6spoof.py  # En red de laboratorio

# ❌ INCORRECTO: Sin autorización
sudo python3 spooftcp.py 8.8.8.8 192.168.1.1 53  # ILEGAL

# ✅ CORRECTO: Documentar prueba
echo "Test IP Spoofing - Autorizado - $(date)" >> pruebas.log
```

### Cobertura Legal

El uso de estas herramientas sin autorización viola:
- 🇪🇸 Código Penal español (Art. 197)
- 🇺🇸 Computer Fraud and Abuse Act (CFAA)
- 🇬🇧 Computer Misuse Act 1990
- 🇪🇺 RGPD y Directiva NIS

---

### 📚 Referencias

### Documentación Técnica

- [RFC 791 - IPv4](https://tools.ietf.org/html/rfc791) - Especificación IPv4
- [RFC 8200 - IPv6](https://tools.ietf.org/html/rfc8200) - Especificación IPv6
- [BCP 38 - RFC 2827](https://tools.ietf.org/html/bcp38) - Filtrado Ingress
- [RFC 3704 - Ingress Filtering](https://tools.ietf.org/html/rfc3704)
- [Scapy Documentation](https://scapy.readthedocs.io/) - Framework Scapy

### Herramientas Relacionadas

- **Nmap**: Escáner de puertos con capacidades spoofing
- **Hping3**: Generador de paquetes IP
- **T50**: Flood tool avanzado
- **Wireshark**: Analizador de tráfico
- **Tcpdump**: Capturador de paquetes

### Lecturas Recomendadas

- "TCP/IP Illustrated" - W. Richard Stevens
- "Advanced Network Security" - Dominique Brezinski
- "The Hacker Playbook 3" - Peter Kim
- "Network Warrior" - Gary A. Donahue

---

### 📄 Licencia

Este proyecto está bajo licencia MIT. Ver archivo `LICENSE` para más detalles.

```
MIT License

Copyright (c) 2020 Antonio Taboada / hackingyseguridad

Permission is hereby granted, free of charge, to any person obtaining a copy...
```

### Tabla Resumen: Cómo Usar Correctamente

| Escenario | ¿Permitido? | Requisitos |
|-----------|-----------|-----------|
| Testing en red personal | ✅ Sí | Ser propietario |
| Testing autorizado en cliente | ✅ Sí | Autorización escrita |
| Testing en red corporativa propia | ✅ Sí | Coordinación TI |
| Testing sin autorización | ❌ No | = Delito informático |
| Uso para fraude | ❌ No | = Múltiples delitos |
| Uso para ataques DoS | ❌ No | = Cibercriminalidad |
| Investigación académica | ✅ Sí | Ambiente controlado |
| Publicación de 0-day | ⚠️ Gris | Disclosure responsable |

---

**Última actualización:** 2026  
**Versión:** 1.0 (Completa)  
**Estado:** En mantenimiento activo

---

**AVISO LEGAL:**

Este software es SOLO para investigación y educación en sistemas autorizados.

Cualquier USO NO AUTORIZADO es ILEGAL.

---

#
http://www.hackingyseguridad.com/
#

