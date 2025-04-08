import re

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


class SelectProcess(Widget):
    class ProcessLabel(Label):
        def __init__(self, *args, **kwargs):
            self.process_name = kwargs.pop('process_name')
            self.pid = kwargs.pop('pid')
            super().__init__(*args, **kwargs)

    def __init__(self, result_msg_cls, processes):
        super().__init__()
        self.result_msg_cls = result_msg_cls
        self.processes = processes

    def compose(self):
        with ListView():
            for process in self.processes:
                yield ListItem(self.ProcessLabel(f'{str(process.process_name).ljust(20)} --- {hex(process.pid)}', process_name=process.process_name, pid=process.pid))

    def on_list_view_selected(self, msg):
        process_name, pid = msg.item.children[0].process_name, msg.item.children[0].pid
        self.post_message(self.result_msg_cls((process_name, pid)))
        self.remove()


class InputPop(Widget):
    def __init__(self, result_msg_cls, *args, **kwargs):
        self.result_msg_cls = result_msg_cls
        super().__init__(*args, **kwargs)

    def key_escape(self):
        self.remove()

    def compose(self):
        yield Input(restrict='[x0-9a-fA-F]+')

    def on_mount(self):
        self.query_one("Input").focus()

    def on_input_submitted(self, msg):
        if re.match('^0x.+?', msg.value):
            result = int(msg.value, 16)
        elif re.findall('[a-fA-F]', msg.value):
            result = int('0x'+msg.value, 16)
        else:
            result = int(msg.value, 10)
        self.post_message(self.result_msg_cls(result))
        self.remove()
