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

class RegisterWidget(Static):
    class RegisterChanged(Message):
        def __init__(self, tid, register_name, value, *args, **kwargs):
            self.tid = tid
            self.register_name = register_name
            self.value = value
            super().__init__(*args, **kwargs)

    def __init__(self, *args, **kwargs):
        self.thread_id = kwargs.pop('thread_id')
        self.register_name = kwargs.pop('register_name')
        self.register_value = kwargs.pop('register_value')
        super().__init__(*args, **kwargs)

    def compose(self):
        yield Label(self.register_name)
        yield Input(hex(self.register_value), id=f'thread-{self.thread_id}-register-{self.register_name}-input')

    def set_value(self, value):
        self.query_one(f'#thread-{self.thread_id}-register-{self.register_name}-input').value=hex(value)

    def on_input_submitted(self, msg):
        if re.match('^0x.+?', msg.value):
            value = int(msg.value, 16)
        elif re.findall('[a-fA-F]', msg.value):
            value = int('0x'+msg.value, 16)
        else:
            value = int(msg.value, 10)
        self.post_message(self.RegisterChanged(self.thread_id, self.register_name, value))


class ThreadContextWidget(ScrollableContainer):
    def __init__(self, *args, **kwargs):
        self.thread_id = kwargs.pop('thread_id')
        self.thread_context = kwargs.pop('thread_context')
        super().__init__(*args, **kwargs)

    def compose(self):
        for register_name,register_value in self.thread_context.items():
            yield RegisterWidget(thread_id=self.thread_id, register_name=register_name, register_value=register_value, id=f'thread-{self.thread_id}-register-{register_name}')

    def update_thread_context(self, thread_context):
        for register_name,register_value in thread_context.items():
            self.query_one(f'#thread-{self.thread_id}-register-{register_name}').set_value(register_value)
