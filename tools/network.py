import scapy.all as scapy
import psutil
import logging
import binascii
import datetime

logging.basicConfig(format='%(levelname)s - %(asctime)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S',
                    level=logging.INFO)

class Network:
    def __init__(self, interface):
        self.interface = interface
        self.devices = {'localhost': {}, }

    @staticmethod
    def modbus_parser(pkt):
        raw_payload = binascii.hexlify(pkt['TCP']['Raw'].load)
        return {'trans_id':  raw_payload[0:4].decode('utf-8'),
                'proto_id': raw_payload[4:8].decode('utf-8'),
                'length': '{:04x}'.format(int(raw_payload[20:24].decode('utf-8'), 16) * 2 + 3),
                'reference_num': int(raw_payload[16:20].decode('utf-8'), 16),
                'word_cnt': int(raw_payload[20:24].decode('utf-8'), 16),
                'unit_id': raw_payload[12:14].decode('utf-8'),
                'func_code': raw_payload[14:16].decode('utf-8'),
                'byte_cnt': '{:02x}'.format(int(raw_payload[16:18].decode('utf-8'), 16)),
                'raw': raw_payload
                }

    def sniff(self, filter=None, timeout=None):
        """
        Simple scapy packet sniffer.
        :param filter: Berkeley Packet Filter syntax
        :param timeout: amount of time to capture
        :return: captured packets [list]
        """
        logging.info('{} - Start sniffer on [{}], with filter [{}] for [{}] sec'.format(datetime.datetime.now().strftime('%H:%M:%S'), self.interface, filter, timeout))
        packets = scapy.sniff(iface=self.interface, filter=filter, timeout=timeout)
        logging.info('{} - Done Sniffing on [{}] with filter [{}]'.format(datetime.datetime.now().strftime('%H:%M:%S'), self.interface, filter))
        return packets

    def callback_sniffer(self, filter=None, callback=None):
        """
        Callback scapy sniffer - sent each captured packet
        to function.
        :param filter: Berkeley Packet Filter syntax
        :param callback: function to run on for each packet
        :return:
        """
        scapy.sniff(iface=self.interface, prn=callback, filter=filter, store=0)

    # TODO - Assets discover
    # List network interfaces for selection
    def interface_select(self):
        """
        Select interface to work on
        :return: Interface class including - Name, MAC, IP
        """
        iface_dict = dict(psutil.net_if_addrs())
        for index, key in enumerate(iface_dict):
            print(str(index + 1) + ') ' + ' - '.join(
                [key, iface_dict[key][0].address, iface_dict[key][1].address]))
        iface_idx = input('\n[*] Select localhost interface (1 - {}): '.format(len(iface_dict)))

        interface = iface_dict[list(iface_dict)[int(iface_idx) - 1]]
        name = list(iface_dict)[int(iface_idx) - 1]
        mac = ':'.join(interface[0].address.split('-'))
        ip = interface[1].address
        logging.info('Selected:\nName: {}.\nMAC: {}\nIP: {}'.format(name, mac, ip))
        self.devices['localhost'] = {'iface': name, 'mac': mac, 'ip': ip}

    def discover(self, timeout=120):
        print('Starting assets discovery on {}... ({} seconds)'.format(self.interface.name, str(timeout)))
        packets = self.sniff(filter='tcp and port 502', timeout=timeout)
        self.analyze(packets)
        print('Done - Found {} total assets'.format(str(len(self.devices['PLC']) + len(self.devices['HMI']))))
        print('-' * 5 + ' HMI ' + '-' * 5)
        for index, value in enumerate(self.devices['HMI']):
            print(str(index + 1) + ') ' + str(value))
        print('-' * 5 + ' PLC ' + '-' * 5)
        for index, value in enumerate(self.devices['PLC']):
            print(str(index + 1) + ') ' + str(value))

    def analyze(self, packets):
        for packet in packets:
            if packet['TCP'].dport == 502:  # HMI -> PLC
                PLC_MAC = packet['Ether'].dst
                PLC_IP = packet['IP'].dst
                HMI_MAC = packet['Ether'].src
                HMI_IP = packet['IP'].src
                if [PLC_MAC, PLC_IP] not in self.devices['PLC']:
                    self.devices['PLC'].append([PLC_MAC, PLC_IP])
                if [HMI_MAC, HMI_IP] not in self.devices['HMI']:
                    self.devices['HMI'].append([HMI_MAC, HMI_IP])

            elif packet['TCP'].sport == 502:  # PLC -> HMI
                PLC_MAC = packet['Ether'].src
                PLC_IP = packet['IP'].src
                HMI_MAC = packet['Ether'].dst
                HMI_IP = packet['IP'].dst
                if [PLC_MAC, PLC_IP] not in self.devices['PLC']:
                    self.devices['PLC'].append([PLC_MAC, PLC_IP])
                if [HMI_MAC, HMI_IP] not in self.devices['HMI']:
                    self.devices['HMI'].append([HMI_MAC, HMI_IP])
