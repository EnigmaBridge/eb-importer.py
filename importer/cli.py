from cmd2 import Cmd
import argparse
import sys
import os
import re
import math
import types
import traceback
import pid
import time
import textwrap
import errors
import utils
import types
import base64
import datetime
from blessed import Terminal
from core import Core
from card_utils import KeyShareInfo, format_data, get_2bytes, get_key_types, get_key_type
from pkg_resources import get_distribution, DistributionNotFound
from smartcard.System import readers
from smartcard.util import toHexString, toBytes
import logging, coloredlogs


logger = logging.getLogger(__name__)
coloredlogs.install()

# logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
# rootLogger = logging.getLogger()
# consoleHandler = logging.StreamHandler()
# consoleHandler.setFormatter(logFormatter)
# rootLogger.addHandler(consoleHandler)


class App(Cmd):
    """EnigmaBridge Importer command line interface"""
    prompt = '$> '

    PIP_NAME = 'ebimporter.py'
    PROCEED_YES = 'yes'
    PROCEED_NO = 'no'
    PROCEED_QUIT = 'quit'

    def __init__(self, *args, **kwargs):
        """
        Init core
        :param args:
        :param kwargs:
        :return:
        """
        Cmd.__init__(self, *args, **kwargs)
        self.core = Core()
        self.args = None
        self.last_result = 0

        self.noninteractive = False
        self.version = self.load_version()

        self.t = Terminal()
        self.update_intro()

        self.card = None
        self.connection = None

    def load_version(self):
        dist = None
        version = None
        try:
            dist = get_distribution(self.PIP_NAME)
            dist_loc = os.path.normcase(dist.location)
            here = os.path.normcase(__file__)
            if not here.startswith(dist_loc):
                raise DistributionNotFound
            else:
                version = dist.version
        except:
            version = 'Trunk'
        return version

    def update_intro(self):
        self.intro = '-'*self.get_term_width() + \
                     ('\n    Enigma Bridge Key Importer command line interface (v%s) \n' % self.version) + \
                     '\n    usage - shows simple command list'

        self.intro += '\n    More info: https://enigmabridge.com/importer \n' + \
                      '-'*self.get_term_width()

    def do_version(self, line):
        print('%s-%s' % (self.PIP_NAME, self.version))

    def do_usage(self, line):
        """TODO: Writes simple usage hints"""
        print('init   - TODO:fix')
        print('add    - adds a new key share')
        print('list   - lists all key shares')
        print('erase  - removes all key shares')
        print('usage  - writes this usage info')

    def do_init(self, line):
        """
        test
        """
        if self.bootstrap() != 0:
            return self.return_code(1)

        res, sw = self.transmit(toBytes('b631000026a900110011111111111111111111111111111111ad000f74657374206d6573736167653a2030'))
        print(format_data(res), '%04X' % sw)

        # res, sw = self.send_get_logs()
        # print(format_data(res), '%04X' % sw)
        #
        # res, sw = self.send_get_shares()
        # print(format_data(res), '%04X' % sw)

        # Continue...
        code, res, sw = self.add_share()
        print(format_data(res), '%04X' % sw)
        return self.return_code(0)

    def do_add(self, line):
        """Adds a new share to the card"""
        if self.bootstrap() != 0:
            return self.return_code(1)

        code, res, sw = self.add_share()
        if code == 0:
            print(self.t.green('New share added successfully!'))
        return self.return_code(0)

    def do_list(self, line):
        """List all shares"""
        if self.bootstrap() != 0:
            return self.return_code(1)

        shares = self.get_shares()
        for idx, share in enumerate(shares):
            print('\nShare idx %d: ' % (idx+1))
            if not share.used:
                print(' - EMPTY')
                continue

            type_str = get_key_type(share.key_type)
            print(' - Type: %s' % (type_str if type_str is not None else '?'))
            print(' - Used: %s' % share.used)
            print(' - Share length: %d' % share.share_len)
            print(' - KCV1: %04X' % share.kcv1)
            print(' - KCV2: %04X' % share.kcv2)
            print(' - Message: %s' % share.message_str)
        print('')

    def do_erase(self, line):
        """Deletes all shares present"""
        if self.bootstrap() != 0:
            return self.return_code(1)

        # Warning
        print(self.t.underline_red('! WARNING !'))
        print('This is a destructive operation, all shares will be unrecoverably deleted from the token')
        if not self.ask_proceed('Do you really want to remove all key shares? (y/n): ', support_non_interactive=True):
            return self.return_code(1)

        # Erase
        resp, sw = self.send_erase_shares()
        if sw != 0x9000:
            logger.error('Could not erase all shares, code: %04X' % sw)
            return self.return_code(1)

        print('All shares erased successfully')
        return self.return_code(0)

    def bootstrap(self):
        if not self.check_root() or not self.check_pid():
            return self.return_code(1)

        # Pick card to use
        self.select_card()
        self.connect_card()
        self.select_importcard()
        return self.return_code(0)

    def add_share(self, share_idx=None):
        # Enter key share
        key_types = get_key_types()
        key_type, key_share, key_share_bin, key_share_arr, kcv = None, None, None, None, None

        print('\nAdd new key share procedure started\n')

        # Ask for share idx
        if share_idx is None:
            print('Please, pick the key share index you are going to add:')
            while True:
                try:
                    share_idx = int(raw_input('Key share (1/2/3): ').strip())
                    if share_idx <= 0 or share_idx > 3:
                        continue
                    break
                except Exception as e:
                    pass
            print('')

        # Ask for key type
        print('Please, select the key type: ')
        while True:
            try:
                key_type = self.select(enumerate(key_types), 'Key type ID: ')
                break
            except Exception as e:
                pass
        print('')

        # Ask for key value
        while True:
            try:
                question = 'Now please enter your key share in hex-coded form: \n'
                key_share = raw_input(question).strip().upper()
                key_share = key_share.replace(' ', '')
                key_share_bin = base64.b16decode(key_share)
                key_share_arr = toBytes(key_share)
                if key_type == 0:
                    kcv = utils.compute_kcv_aes(key_share_bin)
                elif key_type == 1:
                    kcv = utils.compute_kcv_3des(key_share_bin)
                else:
                    raise ValueError('Unknown key type, cannot compute KCV')

                print('\nYou entered the following key share: \n  %s\n  KVC: %s\n'
                      % (format_data(key_share_arr), format_data(kcv[0:3])))

                ok = self.ask_proceed_quit('Is it correct? (y/n/q): ')
                if ok == self.PROCEED_QUIT:
                    return self.return_code(1)
                elif ok == self.PROCEED_YES:
                    break

                print('\n')
            except Exception as e:
                logger.error('Error in adding a new key share: %s' % e)
                if self.args.debug:
                    traceback.print_exc()
        pass

        # Get more detailed info on the share - for the audit
        # date, time, name, key ID, key source
        print('\nNow please enter auxiliary key share information for audit.')

        dt, key_id = None, None
        while True:
            # Date, device does not have a local time
            dt = self.ask_date(' - Enter date in the format YY/MM/DD: ', ask_correct=False)

            # Key ID
            key_id = raw_input(' - Key ID (10 chars max): ').strip()
            if len(key_id) > 10:
                key_id = key_id[0:10]

            print('\nDate: %d/%d/%d, key ID: %s' % (dt[0], dt[1], dt[2], key_id))
            ok = self.ask_proceed('Is this correct? (y/n): ')
            if ok:
                break

        txt_desc = '%d%d%d%s' % (dt[0], dt[1], dt[2], key_id)
        txt_desc_hex = [ord(x) for x in txt_desc]

        print('-'*self.get_term_width())
        print('\nSummary of the key to import:')
        print(' - Share index: %d' % share_idx)
        print(' - Key type: %s' % key_types[key_type])
        print(' - Key: %s\n - KVC: %s' % (format_data(key_share_arr), format_data(kcv[0:3])))
        print('\n - Date: %d/%d/%d' % (dt[0], dt[1], dt[2]))
        print(' - Key ID: %s' % key_id)
        print(' - Text descriptor: %s' % txt_desc)
        print('\n')

        ok = self.ask_proceed('Shall the key share be imported? (y/n): ')
        if not ok:
            logger.error('Key import aborted')
            return self.return_code(1)

        # Add share to the card - format the data.
        # 0xa9 | <key length - 2B> | <share index - 1 B> | <share value> | 0xad | <message length - 2B> | <text message>
        data_buff = 'a9%04x%02x' % ((len(key_share_arr) + 1) & 0xffff, (share_idx-1) & 0xff)
        data_buff += key_share
        data_buff += 'ad%04x' % len(txt_desc_hex)
        data_buff += ''.join(['%02x' % x for x in txt_desc_hex])
        data_arr = toBytes(data_buff)

        logger.debug('Import Msg: %s' % data_buff)
        res, sw = self.send_add_share(data_arr)
        if sw == 0x808f:
            logger.error('Share %d already exists (code %04X)' % (share_idx, sw))
        elif sw != 0x9000:
            logger.error('Invalid card return code: %04x' % sw)
            return 1, res, sw

        return 0, res, sw

    def get_shares(self):
        res, sw = self.send_get_shares()
        if sw != 0x9000:
            logger.error('Could not get key shares info, code: %04X' % sw)
            raise errors.InvalidResponse('Could not get key shares info, code: %04X' % sw)

        key_shares = []
        cur_share = None

        # TLV parser
        tlen = len(res)
        tag, clen, idx = 0, 0, 0
        while idx < tlen:
            tag = res[idx]
            clen = get_2bytes(res, idx+1)
            idx += 3
            cdata = res[idx: (idx + clen)]

            if tag == 0xa9:
                # KeyShare info
                if cur_share is not None:
                    key_shares.append(cur_share)

                cur_share = KeyShareInfo()
                cur_share.parse_info(cdata)

            elif tag == 0xad:
                # KeyShare message
                cur_share.parse_message(cdata)

            idx += clen
        pass

        if cur_share is not None:
            key_shares.append(cur_share)

        return key_shares

    def connect_card(self):
        try:
            self.connection = self.card.createConnection()
            self.connection.connect()
        except Exception as e:
            logger.error('Exception in opening a connection: %s' % e)
            if self.args.debug:
                traceback.print_exc()
            raise e

    def select_importcard(self):
        resp, sw = self.select_applet([0x31, 0x32, 0x33, 0x34, 0x35, 0x36])
        if sw != 0x9000:
            logger.error('Could not select import card applet. Error: %04X' % sw)
            raise errors.InvalidResponse('Could not select import card applet. Error: %04X' % sw)

        return resp, sw

    def select_applet(self, id):
        select = [0x00, 0xA4, 0x04, 0x00, len(id)]

        resp, sw = self.transmit(select + id)
        logger.debug('Selecting applet, response: %s, code: %04X' % (resp, sw))
        return resp, sw

    def send_add_share(self, data):
        res, sw = self.transmit([0xb6, 0x31, 0x0, 0x0, len(data)] + data)
        return res, sw

    def send_get_logs(self):
        res, sw = self.transmit([0xb6, 0xe7, 0x0, 0x0, 0x0])
        return res, sw

    def send_get_shares(self):
        res, sw = self.transmit([0xb6, 0x35, 0x0, 0x0, 0x0])
        return res, sw

    def send_erase_shares(self):
        res, sw = self.transmit([0xb6, 0x33, 0x0, 0x0, 0x0])
        return res, sw

    def transmit(self, data):
        logger.debug('Data: %s' % format_data(data))
        resp, sw1, sw2 = self.connection.transmit(data)
        sw = (sw1 << 8) | sw2
        return resp, sw

    def select_card(self):
        rlist = readers()
        available_readers = []
        for reader in rlist:
            try:
                connection = reader.createConnection()
                connection.connect()
                available_readers.append(reader)
            except:
                pass

        if len(available_readers) == 0:
            logger.error("No card readers in the system")
            return self.return_code(1)

        selected = 0
        if len(available_readers) > 1:
            while True:
                try:
                    selected = self.select(enumerate(available_readers),
                                           'Please select the card reader number that should be used: ')
                    if selected < 0:
                        raise ValueError('Negative')

                    ok = self.ask_proceed('\nYou choose card reader "%d. %s", is it correct? (y/n): '
                                          % (selected+1, available_readers[selected]),
                                          support_non_interactive=True, non_interactive_return=True)
                    if ok:
                        print('\n')
                        break

                except Exception as e:
                    pass

        self.card = available_readers[selected]
        print('\nGoing to use the card: %s' % self.card)
        return 0

    def return_code(self, code=0):
        self.last_result = code
        return code

    def cli_sleep(self, iter=5):
        for lines in range(iter):
            print('')
            time.sleep(0.1)

    def ask_proceed_quit(self, question=None, support_non_interactive=False, non_interactive_return=PROCEED_YES, quit_enabled=True):
        """Ask if user wants to proceed"""
        opts = 'Y/n/q' if quit_enabled else 'Y/n'
        question = question if question is not None else ('Do you really want to proceed? (%s): ' % opts)

        if self.noninteractive and not support_non_interactive:
            raise errors.Error('Non-interactive mode not supported for this prompt')

        if self.noninteractive and support_non_interactive:
            if self.args.yes:
                print(question)
                if non_interactive_return == self.PROCEED_YES:
                    print('Y')
                elif non_interactive_return == self.PROCEED_NO:
                    print('n')
                elif non_interactive_return == self.PROCEED_QUIT:
                    print('q')
                else:
                    raise ValueError('Unknown default value')

                return non_interactive_return
            else:
                raise errors.Error('Non-interactive mode for a prompt without --yes flag')

        # Classic interactive prompt
        confirmation = None
        while confirmation != 'y' and confirmation != 'n' and confirmation != 'q':
            confirmation = raw_input(question).strip().lower()
        if confirmation == 'y':
            return self.PROCEED_YES
        elif confirmation == 'n':
            return self.PROCEED_NO
        else:
            return self.PROCEED_QUIT

    def ask_proceed(self, question=None, support_non_interactive=False, non_interactive_return=True):
        """Ask if user wants to proceed"""
        ret = self.ask_proceed_quit(question=question,
                                    support_non_interactive=support_non_interactive,
                                    non_interactive_return=self.PROCEED_YES if non_interactive_return else self.PROCEED_NO,
                                    quit_enabled=False)

        return ret == self.PROCEED_YES

    def ask_date(self, question=None, ask_correct=True):
        while True:
            answer = raw_input(question).strip()
            match = re.match('^([0-9]{2})/([0-9]{2})/([0-9]{2})$', answer)
            if not match:
                print('Date not in the valid format, please, try again')
                continue

            yy, mm, dd = int(match.group(1)), int(match.group(2)), int(match.group(3))

            # Date test
            try:
                tt = datetime.date(2000+yy, mm, dd)
            except Exception as ex:
                logger.error('Date format is not valid: %s' % ex)
                continue

            dt = yy, mm, dd

            if not ask_correct:
                return dt

            ok = self.ask_proceed('You entered: \"%s\". Is this correct? (y/n): ' % answer)
            if ok:
                return dt
        pass

    def check_root(self):
        """Checks if the script was started with root - we need that for file ops :/"""
        uid = os.getuid()
        euid = os.geteuid()
        if uid != 0 and euid != 0:
            print('Error: This action requires root privileges')
            print('Please, start the client with: sudo -E -H ebaws')
            return False
        return True

    def check_pid(self, retry=True):
        """Checks if the tool is running"""
        first_retry = True
        attempt_ctr = 0
        while first_retry or retry:
            try:
                first_retry = False
                attempt_ctr += 1

                self.core.pidlock_create()
                if attempt_ctr > 1:
                    print('\nPID lock acquired')
                return True

            except pid.PidFileAlreadyRunningError as e:
                return True

            except pid.PidFileError as e:
                pidnum = self.core.pidlock_get_pid()
                print('\nError: CLI already running in exclusive mode by PID: %d' % pidnum)

                if self.args.pidlock >= 0 and attempt_ctr > self.args.pidlock:
                    return False

                print('Next check will be performed in few seconds. Waiting...')
                time.sleep(3)
        pass

    def get_term_width(self):
        try:
            width = self.t.width
            if width is None or width <= 0:
                return 80

            return width
        except:
            pass
        return 80

    def wrap_term(self, text="", single_string=False, max_width=None):
        width = self.get_term_width()
        if max_width is not None and width > max_width:
            width = max_width

        res = textwrap.wrap(text, width)
        return res if not single_string else '\n'.join(res)

    def app_main(self):
        # Backup original arguments for later parsing
        args_src = sys.argv

        # Parse our argument list
        parser = argparse.ArgumentParser(description='EnigmaBridge AWS client')
        parser.add_argument('-n', '--non-interactive', dest='noninteractive', action='store_const', const=True,
                            help='non-interactive mode of operation, command line only')
        parser.add_argument('-r', '--attempts', dest='attempts', type=int, default=3,
                            help='number of attempts in non-interactive mode')
        parser.add_argument('-l','--pid-lock', dest='pidlock', type=int, default=-1,
                            help='number of attempts for pidlock acquire')
        parser.add_argument('--debug', dest='debug', action='store_const', const=True,
                            help='enables debug mode')
        parser.add_argument('--verbose', dest='verbose', action='store_const', const=True,
                            help='enables verbose mode')
        parser.add_argument('--force', dest='force', action='store_const', const=True, default=False,
                            help='forces some action (e.g., certificate renewal)')

        parser.add_argument('--email', dest='email', default=None,
                            help='email address to use instead of prompting for one')

        parser.add_argument('--yes', dest='yes', action='store_const', const=True,
                            help='answers yes to the questions in the non-interactive mode, mainly for init')

        parser.add_argument('--allow-update', action='store_const', const=True,
                            help='Inherited option from auto-update wrapper, no action here')
        parser.add_argument('--no-self-upgrade', action='store_const', const=True,
                            help='Inherited option from auto-update wrapper, no action here')
        parser.add_argument('--os-packages-only', action='store_const', const=True,
                            help='Inherited option from auto-update wrapper, no action here')

        parser.add_argument('commands', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='commands to process')

        self.args = parser.parse_args(args=args_src[1:])
        self.noninteractive = self.args.noninteractive

        # Fixing cmd2 arg parsing, call cmdLoop
        sys.argv = [args_src[0]]
        for cmd in self.args.commands:
            sys.argv.append(cmd)

        # Terminate after execution is over on the non-interactive mode
        if self.noninteractive:
            sys.argv.append('quit')

        self.cmdloop()
        sys.argv = args_src

        # Noninteractive - return the last result from the operation (for scripts)
        if self.noninteractive:
            sys.exit(self.last_result)


def main():
    app = App()
    app.app_main()


if __name__ == '__main__':
    main()
