# Import some POX stuff
from pox.core import core                       # Main POX object
import pox.openflow.libopenflow_01 as of        # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr   # Address types
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

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

    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port

        log_color(
            YELLOW, f"RECIBIDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}")

        # Tráfico privada -> pública
        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):

            log_color(GREEN, f"MATCH: {ip_pkt.srcip} pertenece a la red privada {PRIVATE_SUBNET}/{PRIVATE_MASK}")

            dst_ip = ip_pkt.dstip
            
            # Si tengo la MAC de esa IP ya resuelta:
            if dst_ip in self.tabla_arp:
                dst_mac = self.tabla_arp[dst_ip]

                # Instalar Flujo Saliente
                fm = of.ofp_flow_mod()
                fm.idle_timeout = 10

                # Filtro (Saliente)
                fm.match.nw_src = ip_pkt.srcip
                fm.match.dl_type = 0x800  # IPv4
                fm.match.in_port = in_port

                # Acción (Saliente)
                fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
                fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
                fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
                self.connection.send(fm)

                # Instalar Flujo Entrante (para respuesta)
                fm_back = of.ofp_flow_mod()
                fm_back.idle_timeout = 10

                # Filtro (Entrante)
                fm_back.match.nw_src = ip_pkt.dstip
                fm_back.match.nw_dst = ip_pkt.srcip
                fm_back.match.dl_type = 0x800  # IPv4
                fm_back.match.in_port = PUBLIC_PORT

                # Acción (Entrante)
                fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
                fm_back.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
                fm_back.actions.append(of.ofp_action_output(port=in_port))
                self.connection.send(fm_back)

                # Reenviar paquete actual con MACs actualizadas (src: mac del switch, dst: mac del host publico)
                self.enviar_paquete_ip(packet, PUBLIC_MAC, dst_mac, PUBLIC_PORT)
            else:
                # No conocemos la MAC: encolamos el paquete y enviamos un ARP Request por el puerto público
                log_color(YELLOW, f"MAC de {dst_ip} desconocida. Encolando paquete y mandando ARP Request...")
                
                if dst_ip not in self.paquetes_esperando:
                    self.paquetes_esperando[dst_ip] = []
                    self.send_arp_request(dst_ip, PUBLIC_PORT)
                
                self.paquetes_esperando[dst_ip].append(packet)
        else:
            # Tráfico Publica -> Privada
            log_color(GREEN, f"MATCH (Entrante): {ip_pkt.srcip} → {ip_pkt.dstip} (público a privado)")

            dst_ip = ip_pkt.dstip

            # Verificar si la IP destino está en nuestra red privada
            if dst_ip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
                out_port = self.ip_to_port.get(dst_ip)
                
                if dst_ip in self.tabla_arp and out_port is not None:
                    dst_mac = self.tabla_arp[dst_ip]

                    # 1. Instalar Flujo Entrante
                    fm = of.ofp_flow_mod()
                    fm.idle_timeout = 10
                    fm.match.nw_src = ip_pkt.srcip
                    fm.match.nw_dst = ip_pkt.dstip
                    fm.match.dl_type = 0x800  # IPv4
                    fm.match.in_port = in_port

                    fm.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
                    fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
                    fm.actions.append(of.ofp_action_output(port=out_port))
                    self.connection.send(fm)

                    # Reenviar el paquete reescribiendo la MAC src (a la del switch)
                    # y poniendo la mac_dst del host privado
                    self.enviar_paquete_ip(packet, PRIVATE_MAC, dst_mac, out_port)

                else:
                    log_color(YELLOW, f"MAC o puerto de host privado {dst_ip} desconocido. Encolando y enviando ARP Request...")
                    if dst_ip not in self.paquetes_esperando:
                        self.paquetes_esperando[dst_ip] = []
                        # OFPP_FLOOD manda a todos los puertos excepto por donde entró (broadcast)
                        target_port = out_port if out_port is not None else of.OFPP_FLOOD
                        self.send_arp_request(dst_ip, target_port)
                    self.paquetes_esperando[dst_ip].append(packet)
            else:
                log_color(RED, f"NO MATCH: {ip_pkt.srcip} no pertenece a {PRIVATE_SUBNET}/{PRIVATE_MASK}")

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
                    
                    # Decidir puerto de salida y MAC origen
                    if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
                        # Saliente (Privado -> Público)
                        pending_pkt.src = PUBLIC_MAC
                        pending_pkt.dst = arp_pkt.hwsrc
                        out_port = PUBLIC_PORT
                    else:
                        # Entrante (Público -> Privado)
                        pending_pkt.src = PRIVATE_MAC
                        pending_pkt.dst = arp_pkt.hwsrc
                        out_port = self.ip_to_port.get(ip_pkt.dstip)
                    
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



def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)