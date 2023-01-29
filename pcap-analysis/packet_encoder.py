import argparse
import os
import sys

from scapy.utils import RawPcapReader, chexdump
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr

import numpy as np
from PIL import Image

from packet_decoder import img2packet


def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    packet_imgs = []
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):

        ether_pkt = Ether(pkt_data)
        ip_pkt = ether_pkt[IP]

        s = chexdump(ip_pkt, dump=True).split(",")
        s = [t.strip() for t in s]
        s = [int(t, 16) for t in s]
        img_size = (32, 32)
        img = np.pad(
            s, (0, img_size[0] * img_size[1] - len(s)),
            "constant", constant_values=(0)).reshape(img_size)

        packet_imgs.append(img)
    return packet_imgs


def process_pcap2(file_name, d=2):
    print('Opening {}...'.format(file_name))

    packet_imgs = []
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):

        ether_pkt = Ether(pkt_data)
        ip_pkt = ether_pkt[IP]

        s = chexdump(ip_pkt, dump=True).split(",")
        s = [t.strip() for t in s]
        img_size = (32, 32)
        img = np.zeros(img_size)
        i, j = 0, 0
        for packet_byte in s:
            for half_byte in packet_byte[2:]:
                val = int(half_byte, 16) * 16 + 8
                img[i:i+d, j:j+d] = val
                j += 2
                if j >= img_size[1]:
                    j = 0
                    i += 2
        packet_imgs.append(img)
    return packet_imgs


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    parser.add_argument(
        '--alternative_encoding', metavar='<alternative encoding>',
        action="store_const", const=True, default=False,
        help='whether to use the PAC-GAN alternative encoding technique',
        required=False)
    args = parser.parse_args()

    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    if args.alternative_encoding:
        packet_imgs = process_pcap2(file_name)

    else:
        packet_imgs = process_pcap(file_name)

    img_out_path = os.path.join(
        "data", "encoder", "image", file_name.split(".")[0].split("/")[-1])

    print('Saving images to {}...'.format(img_out_path))
    for i, img in enumerate(packet_imgs):
        im = Image.fromarray(img.astype("uint8"))
        im.save(os.path.join(img_out_path, str(i)+".png"))
    images_np = np.array(packet_imgs)
    np_out_path = os.path.join("data", "encoder", "npy", file_name.split(".")[
        0].split("/")[-1]+".npy")

    #im.save(os.path.join(img_out_path, str(i)+".png"))

    print('Writing numpy output to {}...'.format(np_out_path))
    with open(np_out_path, "wb") as f:
        np.save(f, images_np)
        sys.exit(0)
