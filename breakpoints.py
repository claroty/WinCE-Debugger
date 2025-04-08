from textual import work
from textual.app import *
from textual.widgets import *
from textual.strip import Strip
from textual.containers import *
from textual.geometry import Size
from textual.message import Message
from textual.reactive import reactive
from textual.scroll_view import ScrollView
from rich.text import Text
from rich.style import Style
from rich.jupyter import JupyterMixin
from rich.segment import Segment, Segments


class BreakpointWidget(Static):
    class RemoveBP(Message):
        def __init__(self, addr, *args, **kwargs):
            self.addr = addr
            super().__init__(*args, **kwargs)

    def __init__(self, addr, *args, **kwargs):
        self.addr = addr
        super().__init__(*args, **kwargs)

    def compose(self):
        yield Label(f'{hex(self.addr)}')
        yield Button('Delete')

    def on_button_pressed(self, event):
        self.post_message(self.RemoveBP(self.addr))

class BreakpointsView(ScrollableContainer):
    breakpoints = reactive([], recompose=True)

    def compose(self):
        for bp in self.breakpoints:
            yield BreakpointWidget(bp)