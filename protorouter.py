# Import some POX stuff
from pox.core import core                       # Main POX object
import pox.openflow.libopenflow_01 as of        # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr   # Address types
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from pox.lib.packet.icmp import icmp, TYPE_ECHO_REQUEST, TYPE_ECHO_REPLY
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger()
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")


PRIVATE_SUBNET = IPAddr("192.168.1.0")      # Red interna
PRIVATE_MASK = 24                           # Máscara de la red interna
PRIVATE_IP = IPAddr("192.168.1.254")        # IP del router en la red privada
PUBLIC_IP = IPAddr("200.0.0.254")           # IP del router en la red pública
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")   # MAC del router hacia la red pública
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")  # MAC del router hacia la red privada
PUBLIC_PORT = 1                             # Puerto del switch conectado a la red pública

class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        self.tabla_arp = {} # IPAddr -> MACAddr
        self.paquetes_esperando = {}
        self.ip_to_port = {}
        self.nat_saliente = {}      # (protocol, ip_priv, port_priv, ip_dst, port_dst) -> port_pub
        self.nat_entrante = {}      # (protocol, port_pub, ip_dst, port_dst) -> (ip_priv, port_priv)
        self.proximo_puerto_publico = 50000 # creo que a partir del 49152 son libres
        connection.addListeners(self)

    def enviar_paquete_ip(self, packet, src_mac, dst_mac, out_port):
        packet.src = src_mac
        packet.dst = dst_mac
        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)
        ip_pkt = packet.payload
        log_color(CYAN, f"ENVIANDO IP: {ip_pkt.srcip} → {ip_pkt.dstip} | MAC: {src_mac} → {dst_mac} | Out Port: {out_port}")

    def obtener_prox_puerto(self, protocol, dst_ip, dst_port):
        # Buscamos un puerto libre a partir de proximo_puerto_publico
        for _ in range(65536 - 50000):
            puerto = self.proximo_puerto_publico
            self.proximo_puerto_publico += 1
            if self.proximo_puerto_publico > 65535:
                self.proximo_puerto_publico = 50000
            
            # Si el puerto no está en uso para este protocolo y destino específico, lo devolvemos
            if (protocol, puerto, dst_ip, dst_port) not in self.nat_entrante:
                return puerto
        return None

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning("[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete.")
            return

        if event.parsed.type == ethernet.IP_TYPE:
            self.ip_to_port[event.parsed.payload.srcip] = event.port
            self.handle_ip(event)
        elif event.parsed.type == ethernet.ARP_TYPE:
            self.ip_to_port[event.parsed.payload.protosrc] = event.port
            self.handle_arp(event)
        else:
            log_color(YELLOW, f"Paquete ignorado: protocolo distinto de IPv4/ARP.")

    def instalar_flujo_saliente(self, protocol, ip_priv, port_priv, ip_pub_dst, port_pub_dst, pub_port, mac_priv, port_priv_sw, mac_pub_dst):
        fm = of.ofp_flow_mod()
        fm.idle_timeout = 10
        # esto desata luego _handle_FlowRemoved
        fm.flags = of.OFPFF_SEND_FLOW_REM

        fm.match.dl_type = 0x800  # IPv4
        fm.match.nw_proto = protocol
        fm.match.nw_src = ip_priv
        fm.match.nw_dst = ip_pub_dst
        fm.match.in_port = port_priv_sw
        if port_priv is not None:
            fm.match.tp_src = port_priv
            fm.match.tp_dst = port_pub_dst

        # Acción: Modificar IP/Puerto origen, cambiar MACs y enviar a puerto público
        fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
        if pub_port is not None:
            fm.actions.append(of.ofp_action_tp_port.set_src(pub_port))
        fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(mac_pub_dst))
        fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(fm)

    def instalar_flujo_entrante(self, protocol, ip_priv, port_priv, ip_pub_dst, port_pub_dst, pub_port, mac_priv, port_priv_sw):
        fm = of.ofp_flow_mod()
        fm.idle_timeout = 10
        # esto desata luego _handle_FlowRemoved
        fm.flags = of.OFPFF_SEND_FLOW_REM

        # Filtro (Entrante)
        fm.match.dl_type = 0x800  # IPv4
        fm.match.nw_proto = protocol
        fm.match.nw_src = ip_pub_dst
        fm.match.nw_dst = PUBLIC_IP
        fm.match.in_port = PUBLIC_PORT
        if pub_port is not None:
            fm.match.tp_src = port_pub_dst
            fm.match.tp_dst = pub_port

        # Acción: Modificar IP/Puerto destino de vuelta a los originales, cambiar MACs y enviar a red privada
        fm.actions.append(of.ofp_action_nw_addr.set_dst(ip_priv))
        if port_priv is not None:
            fm.actions.append(of.ofp_action_tp_port.set_dst(port_priv))
        fm.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(mac_priv))
        fm.actions.append(of.ofp_action_output(port=port_priv_sw))
        self.connection.send(fm)

    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port

        log_color(
            YELLOW, f"RECIBIDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}")

        # Evitar procesar paquetes dirigidos a las propias interfaces IP locales del router
        if ip_pkt.dstip == PRIVATE_IP or ip_pkt.dstip == PUBLIC_IP:
            log_color(YELLOW, f"Paquete IP dirigido al router ({ip_pkt.dstip}). Ignorado.")
            return

        # Guardar valores originales antes de cualquier traducción in-place
        original_srcip = ip_pkt.srcip
        original_dstip = ip_pkt.dstip

        # Tráfico privada -> pública
        if original_srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            log_color(GREEN, f"MATCH: {original_srcip} pertenece a la red privada {PRIVATE_SUBNET}/{PRIVATE_MASK}")

            protocol = ip_pkt.protocol
            trans_pkt = ip_pkt.payload

            original_srcport = None
            original_dstport = None
            pub_port = None

            # Obtener puertos o ID según el protocolo de transporte
            if protocol in (ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL):
                original_srcport = trans_pkt.srcport
                original_dstport = trans_pkt.dstport
            elif protocol == ipv4.ICMP_PROTOCOL and trans_pkt.type == TYPE_ECHO_REQUEST:
                original_srcport = trans_pkt.payload.id
                original_dstport = trans_pkt.payload.seq

            dst_ip = ip_pkt.dstip

            # Si el protocolo requiere traducción por puertos (TCP, UDP, ICMP Echo)
            if original_srcport is not None:
                key = (protocol, original_srcip, original_srcport, dst_ip, original_dstport)
                # Si ya existe traducción activa para esta conexión, reutilizar el puerto público
                if key in self.nat_saliente:
                    pub_port = self.nat_saliente[key]
                else:
                    # De lo contrario, asignar un nuevo puerto público libre
                    pub_port = self.obtener_prox_puerto(protocol, dst_ip, original_dstport)
                    if pub_port is None:
                        log_color(RED, "[DROP] No hay puertos públicos de NAT disponibles.")
                        return
                    # Guardar la asignación bidireccional en las tablas de estado NAT
                    self.nat_saliente[key] = pub_port
                    self.nat_entrante[(protocol, pub_port, dst_ip, original_dstport)] = (original_srcip, original_srcport)

                # Modificar paquete in-place para reenvio
                ip_pkt.srcip = PUBLIC_IP
                if protocol in (ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL):
                    trans_pkt.srcport = pub_port
                elif protocol == ipv4.ICMP_PROTOCOL:
                    trans_pkt.payload.id = pub_port

                log_color(GREEN, f"NAT Saliente: {original_srcip}:{original_srcport} → {PUBLIC_IP}:{pub_port} (para {dst_ip}:{original_dstport})")
            else:
                # Si es otro protocolo, solo realizamos NAT básico de dirección IP
                ip_pkt.srcip = PUBLIC_IP
            
            # Si ya resolvimos la MAC del host público destino:
            if dst_ip in self.tabla_arp:
                dst_mac = self.tabla_arp[dst_ip]
                # Solo instalamos flujos en el switch para TCP y UDP
                if protocol in (ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL):
                    self.instalar_flujo_saliente(protocol, original_srcip, original_srcport, dst_ip, original_dstport, pub_port, packet.src, in_port, dst_mac)
                    if pub_port is not None:
                        self.instalar_flujo_entrante(protocol, original_srcip, original_srcport, dst_ip, original_dstport, pub_port, packet.src, in_port)

                # Reenviar el paquete actual con los headers modificados
                self.enviar_paquete_ip(packet, PUBLIC_MAC, dst_mac, PUBLIC_PORT)
            else:
                # No conocemos la MAC destino pública: encolar paquete y lanzar ARP Request
                log_color(YELLOW, f"MAC de {dst_ip} desconocida. Encolando paquete y mandando ARP Request...")
                if dst_ip not in self.paquetes_esperando:
                    self.paquetes_esperando[dst_ip] = []
                    self.send_arp_request(dst_ip, PUBLIC_PORT)
                self.paquetes_esperando[dst_ip].append(packet)
        else:
            # Tráfico Publica -> Privada
            log_color(GREEN, f"MATCH (Entrante): {original_srcip} → {original_dstip} (público a privado)")

            protocol = ip_pkt.protocol
            trans_pkt = ip_pkt.payload

            original_srcport = None
            original_dstport = None
            ip_priv = None
            port_priv = None

            # Leer puerto o ID según el protocolo para realizar la traducción inversa
            if protocol in (ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL):
                original_srcport = trans_pkt.srcport
                original_dstport = trans_pkt.dstport
                nat_key = (protocol, original_dstport, original_srcip, original_srcport)
                if nat_key in self.nat_entrante:
                    ip_priv, port_priv = self.nat_entrante[nat_key]
            elif protocol == ipv4.ICMP_PROTOCOL and trans_pkt.type == TYPE_ECHO_REPLY:
                original_srcport = trans_pkt.payload.id
                original_dstport = trans_pkt.payload.seq
                nat_key = (protocol, original_srcport, original_srcip, original_dstport)
                if nat_key in self.nat_entrante:
                    ip_priv, port_priv = self.nat_entrante[nat_key]

            # Si el destino no está mapeado en la tabla NAT, se descarta
            if ip_priv is None:
                log_color(RED, f"NAT Drop: Tráfico entrante no solicitado a puerto/ID {original_srcport if protocol == ipv4.ICMP_PROTOCOL else original_dstport} de {original_srcip}")
                return

            log_color(GREEN, f"NAT Entrante: {original_srcip}:{original_srcport if protocol == ipv4.ICMP_PROTOCOL else original_dstport} → {ip_priv}:{port_priv}")

            # Reescribir header para re-envio a host de la privada
            ip_pkt.dstip = ip_priv
            if protocol in (ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL):
                trans_pkt.dstport = port_priv
            elif protocol == ipv4.ICMP_PROTOCOL:
                trans_pkt.payload.id = port_priv

            out_port = self.ip_to_port.get(ip_priv)
            
            # Si conocemos tanto la MAC como el puerto físico del host privado:
            if ip_priv in self.tabla_arp and out_port is not None:
                dst_mac = self.tabla_arp[ip_priv]

                # Solo instalamos flujos para TCP y UDP
                if protocol in (ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL):
                    self.instalar_flujo_entrante(protocol, ip_priv, port_priv, original_srcip, original_srcport, original_dstport, dst_mac, out_port)

                # Reenviar el paquete actual modificado a la red privada
                self.enviar_paquete_ip(packet, PRIVATE_MAC, dst_mac, out_port)

            else:
                # No conocemos la MAC/puerto del host privado: encolar y buscar con ARP Request
                log_color(YELLOW, f"MAC o puerto de host privado {ip_priv} desconocido. Encolando y enviando ARP Request...")
                if ip_priv not in self.paquetes_esperando:
                    self.paquetes_esperando[ip_priv] = []
                    target_port = out_port if out_port is not None else of.OFPP_FLOOD
                    self.send_arp_request(ip_priv, target_port)
                self.paquetes_esperando[ip_priv].append(packet)

    def handle_arp(self, event):
        packet = event.parsed
        arp_pkt = packet.payload
        in_port = event.port

        # Aprender dinámicamente la MAC del host que lanzó la ARP Request
        self.tabla_arp[arp_pkt.protosrc] = arp_pkt.hwsrc
        log_color(GREEN, f"ARP aprendido: {arp_pkt.protosrc} -> {arp_pkt.hwsrc}")

        if arp_pkt.opcode == arp.REQUEST:
            log_color(CYAN, f"ARP REQUEST recibido de {arp_pkt.protosrc} buscando {arp_pkt.protodst}")

            # Primero checkeo que sea para una IP del router/switch
            if arp_pkt.protodst == PRIVATE_IP:
                reply_mac = PRIVATE_MAC
            elif arp_pkt.protodst == PUBLIC_IP:
                reply_mac = PUBLIC_MAC
            else:
                log_color(YELLOW, f"ARP Request para IP no gestionada: {arp_pkt.protodst}")
                return

            # Armo el ARP Reply
            r = arp()
            r.opcode = arp.REPLY
            r.hwsrc = reply_mac
            r.protosrc = arp_pkt.protodst
            r.hwdst = arp_pkt.hwsrc
            r.protodst = arp_pkt.protosrc

            # Envolver el ARP en una trama Ethernet
            e = ethernet()
            e.type = ethernet.ARP_TYPE
            e.src = reply_mac
            e.dst = arp_pkt.hwsrc
            e.payload = r

            # Enviar el paquete de vuelta por el mismo puerto
            msg = of.ofp_packet_out()
            msg.data = e.pack()
            msg.actions.append(of.ofp_action_output(port=in_port))
            self.connection.send(msg)
            log_color(GREEN, f"ARP REPLY enviado a {arp_pkt.protosrc}: {arp_pkt.protodst} es {reply_mac}")

        elif arp_pkt.opcode == arp.REPLY:
            log_color(GREEN, f"ARP REPLY recibido de {arp_pkt.protosrc} ({arp_pkt.hwsrc})")
            
            # Si tenia paquetes a la espera de esta resolución de MACAddr, los mando
            if arp_pkt.protosrc in self.paquetes_esperando:
                log_color(CYAN, f"Desencolando paquetes para {arp_pkt.protosrc}")
                for pending_pkt in self.paquetes_esperando[arp_pkt.protosrc]:
                    ip_pkt = pending_pkt.payload
                    
                    # Decidir puerto de salida y MAC origen basándose en la red destino
                    if ip_pkt.dstip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
                        # Entrante (Público -> Privado)
                        pending_pkt.src = PRIVATE_MAC
                        pending_pkt.dst = arp_pkt.hwsrc
                        out_port = self.ip_to_port.get(ip_pkt.dstip)
                    else:
                        # Saliente (Privado -> Público)
                        pending_pkt.src = PUBLIC_MAC
                        pending_pkt.dst = arp_pkt.hwsrc
                        out_port = PUBLIC_PORT
                    
                    if out_port is not None:
                        self.enviar_paquete_ip(pending_pkt, pending_pkt.src, pending_pkt.dst, out_port)
                
                del self.paquetes_esperando[arp_pkt.protosrc]

    def send_arp_request(self, target_ip, out_port):
        # Dependiendo hacia que lado voy, elijo IP+MAC publica/privada
        if out_port == PUBLIC_PORT:
            src_ip = PUBLIC_IP
            src_mac = PUBLIC_MAC
        else:
            src_ip = PRIVATE_IP
            src_mac = PRIVATE_MAC

        r = arp()
        r.opcode = arp.REQUEST
        r.hwsrc = src_mac
        r.protosrc = src_ip
        r.hwdst = EthAddr("00:00:00:00:00:00")  # MAC destino vacía en el request
        r.protodst = target_ip

        e = ethernet()
        e.type = ethernet.ARP_TYPE
        e.src = src_mac
        e.dst = EthAddr("ff:ff:ff:ff:ff:ff")    # Broadcast
        e.payload = r

        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)
        log_color(CYAN, f"ARP REQUEST enviado por puerto {out_port} buscando {target_ip}")

    def _handle_FlowRemoved(self, event):
        match = event.ofp.match
        protocol = match.nw_proto
        ip_priv = match.nw_src
        port_priv = match.tp_src
        dst_ip = match.nw_dst
        dst_port = match.tp_dst
        
        # Intentar remover por el flujo saliente
        if ip_priv is not None and port_priv is not None and dst_ip is not None and dst_port is not None:
            key = (protocol, ip_priv, port_priv, dst_ip, dst_port)
            if key in self.nat_saliente:
                pub_port = self.nat_saliente[key]
                del self.nat_saliente[key]
                ent_key = (protocol, pub_port, dst_ip, dst_port)
                if ent_key in self.nat_entrante:
                    del self.nat_entrante[ent_key]
                log_color(YELLOW, f"NAT Expired: {ip_priv}:{port_priv} → {dst_ip}:{dst_port} (pub_port {pub_port}) liberado por inactividad.")
                return

        # Si no, intentar remover por el flujo entrante
        if match.nw_src is not None and match.tp_src is not None and match.nw_dst == PUBLIC_IP and match.tp_dst is not None:
            ent_key = (protocol, match.tp_dst, match.nw_src, match.tp_src)
            if ent_key in self.nat_entrante:
                ip_priv, port_priv = self.nat_entrante[ent_key]
                del self.nat_entrante[ent_key]
                sal_key = (protocol, ip_priv, port_priv, match.nw_src, match.tp_src)
                if sal_key in self.nat_saliente:
                    del self.nat_saliente[sal_key]
                log_color(YELLOW, f"NAT Expired (reverso): {ip_priv}:{port_priv} → {match.nw_src}:{match.tp_src} (pub_port {match.tp_dst}) liberado por inactividad.")



def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)