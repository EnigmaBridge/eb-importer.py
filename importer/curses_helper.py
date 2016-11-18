from __future__ import division, print_function
import curses
import curses.ascii
import logging
import math


logger = logging.getLogger(__name__)


__author__ = 'dusanklinec'


class KeyBox(object):
    """Editing widget using the interior of a window object.
     Supports the following Emacs-like key bindings:

    Ctrl-A      Go to left edge of window.
    Ctrl-B      Cursor left, wrapping to previous line if appropriate.
    Ctrl-D      Delete character under cursor.
    Ctrl-E      Go to right edge (stripspaces off) or end of line (stripspaces on).
    Ctrl-F      Cursor right, wrapping to next line when appropriate.
    Ctrl-G      Terminate, returning the window contents.
    Ctrl-H      Delete character backward.
    Ctrl-J      Terminate if the window is 1 line, otherwise insert newline.
    Ctrl-K      If line is blank, delete it, otherwise clear to end of line.
    Ctrl-L      Refresh screen.
    Ctrl-N      Cursor down; move down one line.
    Ctrl-O      Insert a blank line at cursor location.
    Ctrl-P      Cursor up; move up one line.

    Move operations do nothing if the cursor is at an edge where the movement
    is not possible.  The following synonyms are supported where possible:

    KEY_LEFT = Ctrl-B, KEY_RIGHT = Ctrl-F, KEY_UP = Ctrl-P, KEY_DOWN = Ctrl-N
    KEY_BACKSPACE = Ctrl-h
    """
    def __init__(self, win, insert_mode=False, hide_input=True, auto_format=True,
                 auto_format_block_size=4, max_input_len=None, placeholder='*',
                 stripspaces=1):
        self.win = win
        self.insert_mode = insert_mode
        (self.maxy, self.maxx) = win.getmaxyx()
        self.maxy = self.maxy - 1
        self.maxx = self.maxx - 1
        self.stripspaces = stripspaces
        self.lastcmd = None
        self.buffer = []
        self.hide_input = hide_input
        self.placeholder = placeholder
        self.auto_format = auto_format
        self.auto_format_block_size = auto_format_block_size
        self.max_input_len = max_input_len
        self.last_x = 0
        self.last_y = 0
        win.keypad(1)
        self._init_state()

    def goto_last(self):
        """
        Moves cursor to the last position.

        :return:
        """
        try:
            self.win.move(self.last_y, self.last_x)
        except:
            pass

    def reinit(self):
        """
        Reinitializes key box dimensions
        :return:
        """
        self.last_x = 0
        self.last_y = 0
        (self.maxy, self.maxx) = win.getmaxyx()
        self.maxy = self.maxy - 1
        self.maxx = self.maxx - 1
        self._init_state()

    def _init_state(self):
        # in case of auto-format adapt the size of the window so the complete tuple is on
        # the line + space
        if self.auto_format:
            w = self.auto_format_block_size + 1
            new_maxx = self.maxx - ((self.maxx+1) % w)

            # if new dimension is too small to fit data in - log an warning
            data_on_line = ((new_maxx+1)/w) * self.auto_format_block_size
            if self.max_input_len is not None and data_on_line * (self.maxy+1) < self.max_input_len:
                logger.warning('Not enough space for %d characters' % self.max_input_len)

            else:
                self.win.resize(self.maxy+1, new_maxx+1)
                self.maxx = new_maxx

        self._init_buffer()

    def _init_buffer(self):
        self.buffer = []
        for y in range(0, self.maxy+1):
            self.buffer.append([curses.ascii.SP] * (self.maxx+1))

    def _map_coords(self, y=None, x=None, to_buffer=True):
        """
        Map absolute coordinates between data buffer and screen.
        :param to_buffer: if true: screen coords -> buffer coords
        :return:
        """
        pass

    def _end_of_line(self, y):
        """Go to the location of the first blank on the given line,
        returning the index of the last non-blank character."""
        last = self.maxx
        while True:
            if curses.ascii.ascii(self.win.inch(y, last)) != curses.ascii.SP:
                last = min(self.maxx, last+1)
                break
            elif last == 0:
                break
            last = last - 1
        return last

    def _translate(self, y, x, cur_y=None, cur_x=None):
        """
        Position overlay - for auto-formatting

        :param y:
        :param x:
        :param cur_y:
        :param cur_x:
        :return:
        """
        if not self.auto_format:
            return y, x

        # Determine direction of the movement.
        # By default, assume positive movement direction.
        # Strange: when in insert mode, positive movement returns
        # current x as the last position (len)
        cdir = 1
        if cur_y is not None and cur_x is not None:
            if y == cur_y and cur_x-x == 1 or cur_x-x == 2:
                cdir = -1
            elif y == cur_y-1:
                cdir = -1

        # Skipping over the delimiter positions w.r.t. moving direction.
        if cdir > 0:
            # Moving to the right
            if ((x+1) % (self.auto_format_block_size+1)) == 0:
                x += 1
        else:
            # moving to the left
            if ((x+1) % (self.auto_format_block_size+1)) == 0:
                x -= 1

        # line movements
        if x > self.maxx and y < self.maxy:
            x = 0
            y += 1
        elif x < 0 and y > 0:
            x = self._end_of_line(y-1)
            y -= 1
        else:
            y = min(y, self.maxy)
            x = min(x, self.maxx)

        return max(y, 0), max(0, x)

    def _add_char(self, y, x, ch):
        """
        Prints character to the terminal, hiding the original user input.

        :param y:
        :param x:
        :param ch:
        :return:
        """
        if curses.ascii.isprint(ch):
            orig_y, orig_x = y, x
            y, x = self._translate(y, x)

            # Store the original character to the appropriate buffer position
            self.buffer[y][x] = ch

            if not self.hide_input or ch == curses.ascii.SP:
                self.win.addch(y, x, ch)
            else:
                self.win.addch(y, x, self.placeholder)
        else:
            self.win.addch(y, x, ch)

    def _getyx(self):
        return self.win.getyx()

    def _inch(self, *args):
        """
        Getting character at the given position.

        :param args:
        :return:
        """
        y, x = self._getyx()
        if len(args) == 2:
            y, x = args
        y, x = self._translate(y, x)

        # old way, traditional.
        # return self.win.inch(*args)

        # Now work over the buffer, screen has placeholders
        try:
            return self.buffer[y][x]
        except:
            return curses.ascii.SP

    def _move(self, y, x):
        """
        Move with taking internal position mapping into account.
        Remembering the last position of the moved cursor.

        :param y:
        :param x:
        :return:
        """
        y, x = self._translate(y, x, self.last_y, self.last_x)
        try:
            res = self.win.move(y, x)
            self.last_x = x
            self.last_y = y
            return res
        except Exception as e:
            logger.error('Error move %d %d %s' % (y, x, e))
            return None

    def _del_printable_char(self, y, x):
        if y >= self.maxy and x >= self.maxx-1:
            self._add_char(y, x, curses.ascii.SP)
            return

        if y >= self.maxy and x >= self.maxx:
            return

        newch = self._inch(y, x+1)
        self._add_char(y, x, newch)

        next_y, next_x = self._translate(y, x+1, y, x)
        self._del_printable_char(next_y, next_x)

    def _delch(self, y, x):
        """
        Deleting a character at given position.
        Reimplemented because of the internal buffering and character hiding, auto-formatting

        :param y:
        :param x:
        :return:
        """
        x -= 1
        if x < 0 and y > 0:
            x = self.maxx
            y -= 1

        y, x = self._translate(y, x, self.last_y, self.last_x+2)

        # Recursive character deletion
        self._del_printable_char(y, x)

        # Move to the correct position after delete
        self.win.move(y, x)

    def _insert_printable_char(self, ch, from_user=False):
        (y, x) = self._getyx()

        # if max length is set, check if it is already done.
        if self.auto_format:
            num_chars = self._num_characters_in_autoformat(y=y, x=x)
            if self.max_input_len is not None and self.max_input_len <= num_chars:
                return

        if y < self.maxy or x < self.maxx:
            if self.insert_mode:
                oldch = self._inch(y, x)
            # The try-catch ignores the error we trigger from some curses
            # versions by trying to write into the lowest-rightmost spot
            # in the window.
            try:
                self._add_char(y, x, ch)
            except curses.error:
                pass
            if self.insert_mode:
                # Recursive shifting all characters to the right.
                (backy, backx) = self._getyx()
                if curses.ascii.isprint(oldch):
                    self._insert_printable_char(oldch)
                    if backy <= self.maxy and backx <= self.maxx:
                        self._move(backy, backx)
                        self.last_y, self.last_x = y, x
                    else:
                        logger.warning('Out of bounds: %d %d max %d %d' % (backy, backx, self.maxy, self.maxx))

    def _num_characters_in_autoformat(self, y, x):
        """
        Estimates number of entered characters if autoformat is enabled from the given coordinates.
        :param y:
        :param x:
        :return:
        """
        w = self.auto_format_block_size
        res = int(y*((self.maxx+1)/(w+1) * w))  # all previous lines filled with data
        res += x - math.floor(x / (w+1))  # on the current line
        return int(res)

    def do_command(self, ch):
        "Process a single editing command."
        (y, x) = self._getyx()
        self.last_y, self.last_x = y, x
        self.lastcmd = ch
        if curses.ascii.isprint(ch):
            # Ignore white spaces in auto-formatting mode
            if self.auto_format and ch == curses.ascii.SP:
                return 1

            if y < self.maxy or x < self.maxx:
                self._insert_printable_char(ch, from_user=True)

        elif ch == curses.ascii.SOH:                           # ^a
            self._move(y, 0)
        elif ch in (curses.ascii.STX, curses.KEY_LEFT, curses.ascii.BS, curses.KEY_BACKSPACE, curses.ascii.DEL):
            if x > 0:
                self._move(y, x-1)
            elif y == 0:
                pass
            elif self.stripspaces:
                self._move(y-1, self._end_of_line(y-1))
            else:
                self._move(y-1, self.maxx)
            if ch in (curses.ascii.BS, curses.KEY_BACKSPACE, curses.ascii.DEL):
                self._delch(y, x)
        elif ch == curses.ascii.EOT:                           # ^d
            self._delch(y, x)
        elif ch == curses.ascii.ENQ:                           # ^e
            if self.stripspaces:
                self._move(y, self._end_of_line(y))
            else:
                self._move(y, self.maxx)
        elif ch in (curses.ascii.ACK, curses.KEY_RIGHT):       # ^f
            if x < self.maxx:
                if self.stripspaces:
                    self._move(y, min(x+1, self._end_of_line(y)))
                else:
                    self._move(y, x+1)
            elif y == self.maxy:
                pass
            elif not self.auto_format:
                self._move(y+1, 0)
            elif self._end_of_line(y) >= self.maxx:
                self._move(y+1, 0)
        elif ch == curses.ascii.BEL:                           # ^g
            return 0
        elif ch == curses.ascii.NL:                            # ^j
            if self.maxy == 0 or self.auto_format:
                return 0
            elif y < self.maxy:
                self._move(y+1, 0)
        elif ch == curses.ascii.VT:                            # ^k
            if x == 0 and self._end_of_line(y) == 0:
                self.win.deleteln()
            else:
                # first undo the effect of self._end_of_line
                self._move(y, x)
                self.win.clrtoeol()
        elif ch == curses.ascii.FF:                            # ^l
            self.win.refresh()
        elif ch in (curses.ascii.SO, curses.KEY_DOWN):         # ^n
            if y < self.maxy:
                if not self.auto_format or self._end_of_line(y) >= self.maxx:
                    self._move(y+1, min(x, self._end_of_line(y+1)))
        elif ch == curses.ascii.SI:                            # ^o
            self.win.insertln()
        elif ch in (curses.ascii.DLE, curses.KEY_UP):          # ^p
            if y > 0:
                self._move(y-1, x)
                if x > self._end_of_line(y-1):
                    self._move(y-1, self._end_of_line(y-1))
        return 1

    def collect_buffer(self):
        """
        Collects data in the multiline buffer without line separation.
        Buffer lines are concatenated.
        :return:
        """
        result = ""
        for y in range(self.maxy+1):
            result += ''.join([chr(x) for x in self.buffer[y]])
        return result

    def gather(self):
        """Collect and return the contents of the window."""
        result = ""
        if self.auto_format or self.hide_input:
            return self.collect_buffer()

        for y in range(self.maxy+1):
            self._move(y, 0)
            stop = self._end_of_line(y)
            if stop == 0 and self.stripspaces:
                continue
            for x in range(self.maxx+1):
                if self.stripspaces and x > stop:
                    break
                result = result + chr(curses.ascii.ascii(self.win.inch(y, x)))
            if self.maxy > 0:
                result = result + "\n"
        return result

    def edit(self, validate=None):
        """Edit in the widget window and collect the results."""
        while 1:
            ch = self.win.getch()
            if validate:
                ch = validate(ch)
            if not ch:
                continue
            if not self.do_command(ch):
                break
            self.win.refresh()
        return self.gather()


class curses_screen(object):
    def __init__(self):
        self.red_pair = None
        pass

    def get_red_attr(self):
        if self.red_pair is None:
            self.red_pair = 10
            curses.init_pair(self.red_pair, curses.COLOR_RED, -1)

        red_attr = curses.color_pair(self.red_pair) | curses.A_NORMAL
        return red_attr

    def __enter__(self):
        self.stdscr = curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        curses.cbreak()
        curses.noecho()
        self.stdscr.keypad(1)
        SCREEN_HEIGHT, SCREEN_WIDTH = self.stdscr.getmaxyx()
        return self.stdscr

    def __exit__(self,a,b,c):
        curses.nocbreak()
        self.stdscr.keypad(0)
        curses.echo()
        curses.endwin()


if __name__ == '__main__':
    import sys, coloredlogs
    coloredlogs.install()
    screen_wrapper = curses_screen()

    # initializes curses for dialog
    with screen_wrapper as win:
        win.addstr(0, 0, 'Enter here some keys please')
        win.refresh()

        maxy, maxx = win.getmaxyx()

        win_key = curses.newwin(2, 40, 3, 0)
        maxy, maxx = win_key.getmaxyx()
        pary, parx = win_key.getparyx()

        keybox = KeyBox(win_key, True, hide_input=False, max_input_len=38)
        res = keybox.edit().strip()

    print('Result: \n%s||\n' % res)


