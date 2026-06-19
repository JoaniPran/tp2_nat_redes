## Cambiar IP/MAC del Servidor Público (h1)
IP: 200.0.0.99
MAC: 00:00:00:01:02:03

---
## Paso 1: Ejecutar el Controlador POX

Ejecutar el controlador con nivel de log en `DEBUG`:

```bash
python3 pox/pox.py log.level --DEBUG protorouter
```

## Paso 2: Ejecutar la Topología en Mininet

Ejecutar la topología:

```bash
sudo python3 topo.py
```

En la terminal de POX debería aparecer:
`INFO:protorouter:Iniciando ProtoRouter para Switch 1`

---

## Paso 3: Iniciar Servidor en el Host Público (h1)

Levantar un servidor TCP usando `iperf` en `h1`:

```mininet
mininet> h1 iperf -s -p 5001 &
```

*Wireshark en el server público*
```mininet
mininet> h1 wireshark &
```
---

## Paso 4: Realizar Conexiones desde la Red Privada

### Conexión desde h2 (Cliente 1):
Inicia una conexión hacia la nueva IP del servidor público:

```mininet
mininet> h2 iperf -c 200.0.0.99 -p 5001 -t 5
```

**Ver en terminal de POX:**
1. **ARP dinámico**: Se verá el intercambio de ARP Request y Reply para conocer la MAC del host público `200.0.0.99` y del host privado `192.168.1.2` (ej. `[ARP] Aprendido...` y `[ARP] Solicitud...`).
2. **Asignación de puerto NAT y Reglas**: Se mostrará el detalle de traducción y la instalación de flujos en el switch:
   ```text
   [NAT-OUT] Traduciendo: 192.168.1.2:XXXX -> 200.0.0.254:1024 (Destino: 200.0.0.99:5001)
   [SWITCH] Regla de salida instalada (TCP): 192.168.1.2:XXXX -> 200.0.0.99:5001 | Traducido a: 200.0.0.254:1024
   [SWITCH] Regla de entrada instalada (TCP): 200.0.0.99:5001 -> 200.0.0.254:1024 | Mapeado a: 192.168.1.2:XXXX
   ```

**Ver en Wireshark en h1:**
- Ver que los paquetes TCP que recibe el servidor `h1` provienen de la IP del NAT `200.0.0.254` y del puerto `1024`.

---

### Conexión concurrentes desde h3 (Cliente 2):
Hacemos otra prueba desde `h3`:

```mininet
mininet> h3 iperf -c 200.0.0.99 -p 5001 -t 5
```

**Ver en terminal de POX:**
- En la terminal de POX se ve que a `h3` (`192.168.1.3`) se le asigna el puerto público `1025`:
  `[NAT-OUT] Traduciendo: 192.168.1.3:XXXX -> 200.0.0.254:1025 (Destino: 200.0.0.99:5001)`
---

## Paso 5: Demostración de Expiración de Flujos

1. En la CLI de Mininet, inmediatamente después de terminar el tráfico de iperf:
   ```mininet
   mininet> dpctl dump-flows
   ```
2. Esperar 10 segundos de inactividad.
3. En la terminal de POX, se ven los logs indicando que el switch notificó la expiración del flujo por inactividad y el controlador liberó el puerto:
   `[EXPIRADO] Flujo de salida inactivo: 192.168.1.2:XXXX -> 200.0.0.99:5001 | Puerto NAT 1024 liberado.`

4. Volver a ejecutar en la CLI de Mininet:
   ```mininet
   mininet> dpctl dump-flows
   ```
   Se ve que las reglas correspondientes a esos flujos ya no están en el switch. Los puertos quedan libres y listos para volver a ser reutilizados.
   Se cumplio el requerimiento de "minimizar el uso del controlador", las reglas solo viajan al controlador al inicio, luego el switch procesa todo, y expiran al estar inactivas.
