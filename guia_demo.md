## Cambiar IP/MAC del Servidor Público (h1)
IP: 200.0.0.99
MAC: 00:00:00:01:02:03

---
## Paso 1: Ejecutar el Controlador POX

Ejecutar el controlador con nivel de log en `DEBUG`:

   ```bash
   python3 pox/pox.py log.level --DEBUG protorouter
   ```

2. **Terminal 2: Iniciar la topología en Mininet**
   ```bash
   sudo python3 topo.py
   ```

3. **Terminal 2 (CLI de Mininet): Abrir terminales xterm**
   Para poder ejecutar comandos de forma interactiva y visualizar las salidas de cada host de forma independiente:
   ```mininet
   mininet> xterm h1 h2 h3
   ```

---

## 1. Prueba con Server y Un Cliente

### A. Iniciar Wireshark
Desde la terminal de Mininet (o desde las xterm de cada host), iniciar Wireshark redirigiendo la salida estándar para evitar que inunde la consola:
```mininet
mininet> h1 wireshark >/dev/null 2>&1 &
mininet> h2 wireshark >/dev/null 2>&1 &
```
*   **En h1 (Wireshark)**: Seleccionar la interfaz `h1-eth0`. Iniciar captura.
*   **En h2 (Wireshark)**: Seleccionar la interfaz `h2-eth0`. Iniciar captura.

---

### B. Conexión de un Cliente (TCP)

1. **Levantar el Servidor iperf (en xterm de h1)**:
   ```bash
   iperf -s
   ```
2. **Ejecutar el Cliente iperf (en xterm de h2)**:
   ```bash
   iperf -c <ip_h1>
   ```

#### Verificación Operativa
*   **En la xterm de h1 (Servidor)**: La salida del comando iperf debe mostrar una conexión aceptada proveniente de la **IP pública del NAT** (`200.0.0.254`) y un puerto público asignado dinámicamente (ej. `1024`), confirmando que la IP original del cliente (`192.168.1.2`) ha sido enmascarada.
*   **En Wireshark (h1)**: Los paquetes TCP entrantes deben tener:
    *   IP Origen: `200.0.0.254` (IP pública del NAT).
    *   IP Destino: `200.0.0.1` (IP del Servidor).
*   **En Wireshark (h2)**: Los paquetes TCP salientes deben mostrar:
    *   IP Origen: `192.168.1.2` (IP privada del Cliente).
    *   IP Destino: `200.0.0.1` (IP del Servidor).

---

### C. Conexión de un Cliente (UDP)

1. **Levantar el Servidor iperf en modo UDP (en xterm de h1)**:
   ```bash
   iperf -s -u
   ```
2. **Ejecutar el Cliente iperf en modo UDP (en xterm de h2)**:
   ```bash
   iperf -c <ip_h1> -u -b 10M
   ```

#### Verificación Operativa
*   Confirmar que la traducción de la IP privada y el puerto de origen de UDP ocurra de manera análoga al tráfico TCP, visualizando la IP pública del NAT (`200.0.0.254`) en los mensajes de conexión del servidor iperf.

---

### D. Verificación e Interpretación de Flujos en el Switch
Desde **Terminal 3 (Linux externa)**, listar las reglas de flujo instaladas en el switch OpenFlow:
```bash
sudo ovs-ofctl dump-flows s1
```

#### Interpretación de campos clave para la demo:
*   `cookie`: Identificador numérico único asignado a la regla por el controlador POX.
*   `duration`: Tiempo total (en segundos) transcurrido desde que se instaló la regla en el switch.
*   `idle_timeout=10`: Tiempo máximo de inactividad permitido para esta regla. Si pasan 10 segundos sin tráfico coincidente, la regla expira, se elimina del switch y se notifica al controlador para liberar el puerto público.
*   `n_packets` / `n_bytes`: Cantidad de paquetes/bytes procesados directamente por el switch usando esta regla de flujo (plano de datos, sin subir al controlador).
*   `nw_proto=6` (TCP) o `nw_proto=17` (UDP): Protocolo de capa de transporte que hace match con el flujo.
*   **Match de Filtro (ej. `tcp,in_port=2,vlan_tci=0x0000,dl_src=00:00:00:00:00:02,dl_dst=00:00:00:aa:aa:aa,nw_src=192.168.1.2,nw_dst=200.0.0.1,tp_src=49152,tp_dst=5001`)**: Filtro exacto para identificar paquetes de esta conexión saliente.
*   **Actions (Acciones a aplicar)**:
    *   `mod_nw_src`: Reemplaza la IP de origen por la IP pública del NAT (`200.0.0.254`).
    *   `mod_tp_src`: Reemplaza el puerto de transporte de origen por el puerto público asignado por el NAT (ej. `1024`).
    *   `mod_dl_src`: Modifica la dirección MAC origen a la MAC pública de la interfaz del NAT (`00:00:00:aa:aa:aa`).
    *   `mod_dl_dst`: Modifica la dirección MAC destino a la MAC real del servidor público (`00:00:00:00:00:01`).
    *   `output:1`: Envía el paquete modificado directamente por la interfaz pública (puerto físico 1 del switch).

---

## 2. Prueba con Múltiples Clientes

### A. Preparar terminales
Asegurar tener abiertas las terminales `xterm` de al menos 3 clientes privados (`h2`, `h3`, `h4`) y el servidor público (`h1`).

---

### B. Pruebas Simultáneas TCP

1. **Levantar el Servidor iperf (en xterm de h1)**:
   ```bash
   iperf -s
   ```
2. **Ejecutar los Clientes de forma simultánea (dentro de un intervalo de 10 segundos)**:
   *   En xterm de `h2`: `iperf -c <ip_h1> -t 10`
   *   En xterm de `h3`: `iperf -c <ip_h1> -t 10`
   *   En xterm de `h4`: `iperf -c <ip_h1> -t 10`

#### Verificación Operativa
*   **En la xterm de h1 (Servidor)**: Verificar que se reportan 3 conexiones concurrentes activas desde la IP `200.0.0.254`, distinguidas cada una por un puerto de origen diferente asignado por el PAT (ej. `1024`, `1025`, `1026`).
*   **En la Terminal de POX**: Observar en los logs la asignación secuencial y libre de colisiones de los puertos NAT para cada host de la red privada:
    ```text
    [NAT-OUT] Traduciendo: 192.168.1.2:XXXX -> 200.0.0.254:1024 (Destino: <ip_h1>:5001)
    [NAT-OUT] Traduciendo: 192.168.1.3:YYYY -> 200.0.0.254:1025 (Destino: <ip_h1>:5001)
    [NAT-OUT] Traduciendo: 192.168.1.4:ZZZZ -> 200.0.0.254:1026 (Destino: <ip_h1>:5001)
    ```

---

### C. Pruebas Simultáneas UDP

1. **Levantar el Servidor iperf UDP (en xterm de h1)**:
   ```bash
   iperf -s -u
   ```
2. **Ejecutar los Clientes de forma simultánea**:
   *   En xterm de `h2`: `iperf -c <ip_h1> -u -b 5M -t 10`
   *   En xterm de `h3`: `iperf -c <ip_h1> -u -b 5M -t 10`
   *   En xterm de `h4`: `iperf -c <ip_h1> -u -b 5M -t 10`

