import binascii
import scapy.all as scapy
from config.defaults import cfg
from tools.network import Network
import logging

logging.basicConfig(format='%(levelname)s - %(asctime)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S',
                    level=logging.INFO)
FIN = 0x001
SYN = 0x002
FIN_SYN = 0x003
RST = 0x004
PSH = 0x008
FIN_PSH = 0x09
SYN_PSH = 0x0A
ACK = 0x010
FIN_ACK = 0x011
SYN_ACK = 0x012
RST_ACK = 0x014
PSH_ACK = 0x018


def remove_dup(seq):
    # Remove duplicates fom list while preserving order
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]


class Modbus:
    def __init__(self):
        self.matrix = None
        self.functions = None
        self.idx = 0.0
        self.freq = 1.0

    def pkt_callback(self, pkt):
        """
        replay method for TCP/IP communication
        :param pkt: current TCP packet need to replay
        :return:
        """
        L2 = scapy.Ether(dst=pkt['Ether'].src,
                         src=cfg.DEVICES.LOCALHOST.MAC,
                         type=0x800)
        L3 = scapy.IP(src=pkt['IP'].dst,
                      dst=pkt['IP'].src,
                      proto=pkt['IP'].proto)
        L4 = scapy.TCP(dport=pkt['TCP'].sport,
                       sport=pkt['TCP'].dport,
                       seq=pkt['TCP'].ack)
        ANS = None

        if pkt.haslayer('TCP'):
            pkt_tcp_flag = pkt['TCP'].flags.flagrepr()

            # SYN
            if pkt_tcp_flag == 'S':
                L4.flags = SYN_ACK
                L4.ack = 1

            # PSH-ACK
            elif pkt_tcp_flag == 'PA':
                L4.flags = PSH_ACK
                L4.ack = pkt['TCP'].seq + len(pkt['TCP'].load)
                ANS = self.build_modbus_answer(pkt)

            # FIN-ACK
            elif pkt_tcp_flag == 'FA':
                L4.flags = ACK
                L4.ack = pkt['TCP'].seq + 1

            # RST
            elif pkt_tcp_flag == 'R':
                L4.flags = RST_ACK
                L4.ack = 1

            scapy.sendp(L2 / L3 / L4 / ANS, verbose=0)

    def build_modbus_answer(self, pkt):
        """
        get modbus query packet and build modbus answer using interpolated functions.
        :param pkt: modbus query packet
        :return: L4 payload string
        """
        try:
            # modbus parameters
            params = Network.modbus_parser(pkt)
            registers_data = []
            # create string of modbus registers data
            for i in range(params['reference_num'], params['word_cnt'] + params['reference_num']):
                registers_data.append('{:04x}'.format(int(self.functions[i](self.idx))))
            registers_data = ''.join(registers_data)
            self.idx = (self.idx + self.freq) % self.matrix.shape[0]    # idx range = (1, # of stored transactions)
            # build full modbus answer
            ans = ''.join([
                params['trans_id'],
                params['proto_id'],
                params['length'],
                params['unit_id'],
                params['func_code'],
                params['byte_cnt'],
                registers_data])
            return binascii.unhexlify(ans)

        except Exception as e:
            logging.warning('Failed to create Modbus answer [Transaction ID: {}] '.format(
                binascii.hexlify(pkt['TCP']['Raw'].load)[0:4].decode('utf-8')))
            return None
