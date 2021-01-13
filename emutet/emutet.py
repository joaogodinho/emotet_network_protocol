import os
import sys
import json
import magic
import requests
import tempfile
import datetime
import logging
from hashlib import sha1, md5
from argparse import ArgumentParser

from src.bot.emotet import EmotetEmulator
import src.utils.emoutils as emoutils


def generate_file_path(output, rsa_key, mod_id, mod_action):
    OUTPUTDIR = "output"
    if output:
        OUTPUTDIR = output

    today = datetime.date.today()
    date = today.strftime("%Y%m%d")
    path = os.path.join(OUTPUTDIR, date, md5(rsa_key._key.exportKey()).hexdigest()[:20], str(mod_id), str(mod_action))
    if not os.path.exists(path):
        os.makedirs(path)

    return path

def main(options):
    if options.cape:
        print("[+] https://www.capesandbox.com/configdownload/{0}/Emotet/".format(options.cape))
        tmpf = emoutils.get_analysis_from_cape(options.cape)
    elif options.triage:
        api_key_filename = options.triage_api_key if options.triage_api_key else os.path.join(os.path.dirname(__file__), "src", "config/triage-api-key.txt")

        if not os.path.exists(api_key_filename):
            print("[!] Triage API key file {0} not found.".format(api_key_filename))
            return

        print("[+] https://tria.ge/reports/{0}/task1".format(options.triage))
        tmpf = emoutils.get_analysis_from_triage(options.triage, api_key_filename)

    if (options.cape or options.triage) and tmpf == "":
        print("[!] Error! Can't get the configuation")
        return

    if options.cape:
        emutet = EmotetEmulator(cape=tmpf)
    elif options.triage:
        emutet = EmotetEmulator(triage=tmpf)
    else:
        if options.rsa and options.ips:
            emutet = EmotetEmulator(keyfilename=options.rsa, ipsfilename=options.ips)

    modules = emutet.download(options.try_all)
    print("[+] Downloaded {n} modules".format(n=len(modules)))
    for module in modules:
        module_sha1 = sha1(module.data).hexdigest()
        ftype = magic.from_buffer(module.data)
        print("\t[+] Type: {ty} ID: {id} Action: {ac} SHA1: {sh}".format(ty=ftype, id=module.id, ac=module.action, sh=module_sha1))

        with open(os.path.join(generate_file_path(options.output, emutet.RSA_PUBLIC_KEY, module.id, module.action), module_sha1), "wb") as f:
            f.write(module.data)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-r", "--rsa", type=str, default=None, help="RSA key file (use with -i)")
    parser.add_argument("-i", "--ips", type=str, default=None, help="C2s list file (host:port per line)")
    parser.add_argument("-c", "--cape", type=int, default=None, help="Analysis ID from https://www.capesandbox.com")
    parser.add_argument("-t", "--triage", type=str, default=None, help="Analysis ID from https://www.tria.ge")
    parser.add_argument("-k", "--triage-api-key", type=str, default=None, help="Triage API key file. To get yours go to https://tria.ge and ask for an account")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", default=False, help="Verbose mode. Shows errors and debugging prints")
    parser.add_argument("-T", "--try-all", action="store_true", default=False, help="Try all C&C in the C&C list. By default the bot will stop once" \
                                                                                  "a sucess response is gotten from the C&C. This can be when it" \
                                                                                  " downloads new modules or when the C&C response is empty." \
                                                                                  " If this option is enabled the bot doesn't stop until all C&C" \
                                                                                  " responses are checked")

    options = parser.parse_args()

    if options.cape == None and options.triage == None and (options.rsa == None or options.ips == None):
        print("[!] Analysis ID and RSA and IP file not provided")
        parser.print_help()
        exit()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    main(options)
