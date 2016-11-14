from __future__ import division, print_function
import curses
import curses.ascii
import logging


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
    def __init__(self, win, insert_mode=False):
        self.win = win
        self.insert_mode = insert_mode
        (self.maxy, self.maxx) = win.getmaxyx()
        self.maxy = self.maxy - 1
        self.maxx = self.maxx - 1
        self.stripspaces = 1
        self.lastcmd = None
        self.buffer = []
        self.hide_input = True
        self.placeholder = '*'
        self.auto_format = True
        self.auto_format_block_size = 4
        self.last_x = 0
        self.last_y = 0
        win.keypad(1)

    def goto_last(self):
        """
        Moves cursor to the last position.

        :return:
        """
        try:
            self.win.move(self.last_y, self.last_x)
        except:
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
            if y == cur_y and cur_x-x == 1:
                cdir = -1

        # Skipping over the delimiter positions w.r.t. moving direction.
        if cdir > 0:
            # Moving to the right
            if x > 0 and ((x+1) % (self.auto_format_block_size+1)) == 0:
                x += 1
        else:
            # moving to the left
            if x > 0 and ((x+1) % (self.auto_format_block_size+1)) == 0:
                x -= 1

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
            # Initialize buffer with spaces.
            while len(self.buffer) <= x:
                self.buffer.append(curses.ascii.SP)
            self.buffer[x] = ch

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
            return self.buffer[x]
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
        cur_y, cur_x = self.win.getyx()
        y, x = self._translate(y, x, cur_y, cur_x)
        try:
            res = self.win.move(y, x)
            self.last_x = x
            self.last_y = y
            return res
        except Exception as e:
            logger.error('Error move %d %d %s' % (y, x, e))
            return None

    def _delch(self, y, x):
        """
        Deleting a character at given position.
        Reimplemented because of the internal buffering and character hiding, auto-formatting

        :param y:
        :param x:
        :return:
        """
        cur_y, cur_x = self.win.getyx()
        cur_x += 2

        x -= 1
        y, x = self._translate(y, x, cur_y, cur_x)

        # update buffer
        self.buffer = self.buffer[0:x] + self.buffer[x+1:] + [curses.ascii.SP]

        # delete the character
        self.win.delch(y, x)

        if not self.auto_format:
            return

        # Fix buffer spaces re-alignment, move space to 1 to the right
        # Buffer contains input string also with spaces.
        self._move_delim(x)

        # Raw repainting from the buffer
        # Buffer contains spaces also, thus can be rerendered without coordinate remapping
        self.win.move(y, x)
        self._redraw_buff(x)
        self.win.move(y, x)
        pass

    def _move_delim(self, x, to_right=True):
        # Fix buffer spaces re-alignment, move space to 1 to the right
        # Buffer contains input string also with spaces.
        ln = len(self.buffer)
        i = x

        loop_end = ln-1
        if not to_right:
            i += 1
            loop_end = ln

        while i < loop_end:
            c = self.buffer[i]
            if c == curses.ascii.SP:
                n = self.buffer[i+1 if to_right else i-1]
                self.buffer[i] = n
                self.buffer[i+1 if to_right else i-1] = c
                if to_right:
                    i += 1
            i += 1
        pass

    def _redraw_buff(self, x=0):
        ln = len(self.buffer)
        for i in range(x, ln):
            c = self.buffer[i]
            if self.hide_input and c != curses.ascii.SP:
                c = self.placeholder
            self.win.addch(c)

    def _insert_printable_char(self, ch, from_user=False):
        (y, x) = self._getyx()
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
                    else:
                        logger.warning('Out of bounds: %d %d max %d %d' % (y,x, self.maxy, self.maxx))

    def do_command(self, ch):
        "Process a single editing command."
        (y, x) = self._getyx()
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
            else:
                self._move(y+1, 0)
        elif ch == curses.ascii.BEL:                           # ^g
            return 0
        elif ch == curses.ascii.NL:                            # ^j
            if self.maxy == 0:
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
                self._move(y+1, x)
                if x > self._end_of_line(y+1):
                    self._move(y+1, self._end_of_line(y+1))
        elif ch == curses.ascii.SI:                            # ^o
            self.win.insertln()
        elif ch in (curses.ascii.DLE, curses.KEY_UP):          # ^p
            if y > 0:
                self._move(y-1, x)
                if x > self._end_of_line(y-1):
                    self._move(y-1, self._end_of_line(y-1))
        return 1

    def gather(self):
        """Collect and return the contents of the window."""
        result = ""
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


