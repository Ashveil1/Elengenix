from textual.app import App, ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Static
from textual import events
from rich.panel import Panel

class DummyAgent:
    pass

from tools.overlay_menu import SettingsOverlay

class OverlayBridge(Static, can_focus=True):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.overlay = SettingsOverlay(DummyAgent(), None, target="test")

    def on_mount(self):
        self.update(self.overlay.render())

    def on_key(self, event: events.Key) -> None:
        # map textual key to character
        char = event.character
        if event.key == "escape":
            char = "\x1b"
        elif event.key == "enter":
            char = "\n"
        elif event.key == "up":
            char = "k"
        elif event.key == "down":
            char = "j"
            
        if char:
            res = self.overlay.handle_char(char)
            if res == "exit":
                self.app.exit()
            else:
                self.update(self.overlay.render())

class TestApp(App):
    def compose(self):
        yield OverlayBridge()

    def on_mount(self):
        self.query_one(OverlayBridge).focus()

if __name__ == "__main__":
    print("Bridge syntax OK")
