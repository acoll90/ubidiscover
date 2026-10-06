<p align="center"><img src="assets/ubidiscover.png" width="96" alt="UbiDiscover"></p>

# UbiDiscover

Eina gratuïta per **descobrir dispositius Ubiquiti** a la xarxa (airMAX/airOS, UniFi, EdgeMAX…), alternativa a l'*Ubiquiti Discovery Tool* oficial sense necessitat de Java.

Fet per [Albert Coll Bordas](https://www.acollbordas.com).

## Descàrrega

Ves a **[Releases](https://github.com/acoll90/ubidiscover/releases/latest)** i baixa'n una:

| Fitxer | Per a |
|---|---|
| `UbiDiscover-x.y.z-setup.exe` | Instal·lador (menú Inici, desinstal·lador, sense permisos d'administrador) |
| `UbiDiscover-x.y.z-portable.exe` | Versió portable: un sol fitxer, no cal instal·lar res |

L'eina comprova a l'inici si hi ha una versió nova.

## Funcionalitats

- **Escaneig de la xarxa local** per broadcast a totes les targetes de xarxa del PC (sondes v1 i v2, port UDP 10001).
- **Escaneig d'un rang** (CIDR, p. ex. `10.20.0.0/22`) per unicast: troba equips en segments enrutats o a través de VPN.
- Mostra IP, altres IPs (incl. link-local 169.254), MAC, nom, model, firmware, SSID, mode i uptime.
- **Doble clic** per obrir l'equip al navegador: prova totes les IPs anunciades (HTTPS/HTTP) i obre la que respon.
- **IP temporal automàtica**: si l'equip és en un altre segment (p. ex. de fàbrica a 192.168.1.20, o només amb 169.254.x.x), proposa afegir una IP temporal a la targeta. Abans de quedar-se-la, comprova per ARP (detecció de duplicats de Windows) que estigui lliure, i si no, en prova una altra.
- Ordenació per columnes, copiar IP/MAC i exportació a CSV (compatible amb Excel).

## Notes d'ús

- **Tallafocs de Windows**: la primera vegada, accepta el permís (també per a xarxes privades) o no rebràs les respostes.
- **SmartScreen**: com que l'executable no està signat, Windows pot mostrar "Windows ha protegit l'equip". Clica *Més informació → Executa igualment*. Pots verificar el fitxer amb `SHA256SUMS.txt` de la release.
- **IPs temporals**: requereixen permís d'administrador (UAC). Desapareixen en reiniciar, en tancar l'eina (si ho acceptes) o amb *botó dret → Treu IPs temporals del PC*.
- Per escanejar rangs remots, els equips han de tenir el servei *Discovery* activat i l'UDP 10001 no ha d'estar filtrat.

## Executar des del codi

Només cal Python 3.8+ (sense dependències externes):

```bash
python ubidiscover.py
```

## Compilar l'executable

A Windows:

```bash
pip install pyinstaller
python build.py          # -> dist/UbiDiscover.exe
```

## Publicar una versió nova

1. Canvia `__version__` a `ubidiscover.py` (p. ex. `1.1.0`).
2. Fes commit i crea el tag amb la mateixa versió:
   ```bash
   git commit -am "v1.1.0"
   git tag v1.1.0
   git push && git push --tags
   ```
3. GitHub Actions compila l'instal·lador i la versió portable i crea la release automàticament.

## Dona suport

UbiDiscover és gratuït. Si t'estalvia temps, pots convidar-me a un cafè:
**[paypal.me/acollbordas](https://www.paypal.me/acollbordas)** ♥

Més eines i manuals a **[www.acollbordas.com](https://www.acollbordas.com)**.

## Llicència

[MIT](LICENSE). Ubiquiti, UniFi, airMAX i airOS són marques d'Ubiquiti Inc.; aquest projecte no hi està afiliat.
