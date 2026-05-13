from textual.app import App, ComposeResult
from textual.screen import ModalScreen
from textual.containers import Container
from textual.widgets import Static, OptionList
from textual.widgets.option_list import Option
import os

class SettingsModal(ModalScreen):
    CSS = """
    SettingsModal { align: center middle; }
    #modal_box {
        width: 60;
        height: 25;
        background: #0a0a0a;
        border: solid #cc4444;
        padding: 1 2;
    }
    """
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.layer = "main"

    def compose(self) -> ComposeResult:
        with Container(id="modal_box"):
            yield Static("[bold #cc4444]ELENGENIX SETTINGS[/bold #cc4444]\n", id="modal_title", markup=True)
            yield OptionList(id="menu_list")

    def on_mount(self) -> None:
        self.show_main()

    def show_main(self):
        self.layer = "main"
        self.query_one("#modal_title", Static).update("[bold #cc4444]ELENGENIX SETTINGS[/bold #cc4444]\n")
        opts = self.query_one("#menu_list", OptionList)
        opts.clear_options()
        opts.add_options([
            Option("1. Mode Settings", id="mode"),
            Option("2. Agent Setup (Team Aegis)", id="agent"),
            Option("3. API Keys Status", id="keys"),
            Option("4. Target Configuration", id="target"),
            Option("5. Exit Settings", id="exit"),
        ])

    def show_mode(self):
        self.layer = "mode"
        self.query_one("#modal_title", Static).update("[bold #cc4444]MODE SETTINGS[/bold #cc4444]\n")
        opts = self.query_one("#menu_list", OptionList)
        opts.clear_options()
        opts.add_options([
            Option("1. Auto-Detect", id="m_auto"),
            Option("2. Research", id="m_research"),
            Option("3. Security Chat", id="m_security_chat"),
            Option("4. Scan (Omni-Scan)", id="m_scan"),
            Option("5. Back", id="back"),
        ])

    def show_agent(self):
        self.layer = "agent"
        self.query_one("#modal_title", Static).update("[bold #cc4444]AGENT SETUP (ACTIVE_MODELS)[/bold #cc4444]\n")
        opts = self.query_one("#menu_list", OptionList)
        opts.clear_options()
        opts.add_options([
            Option("1. Single: Gemini 3.1 Pro", id="a_gemini"),
            Option("2. Single: Claude Sonnet 4.6", id="a_claude"),
            Option("3. Single: DeepSeek V3", id="a_deepseek"),
            Option("4. Team: Gemini + Claude", id="a_team_gc"),
            Option("5. Team: Triple Threat", id="a_team_all"),
            Option("6. Back", id="back"),
        ])

    def show_keys(self):
        self.layer = "keys"
        self.query_one("#modal_title", Static).update("[bold #cc4444]API KEYS STATUS[/bold #cc4444]\n")
        opts = self.query_one("#menu_list", OptionList)
        opts.clear_options()
        providers = ["GEMINI", "ANTHROPIC", "OPENAI", "DEEPSEEK", "NVIDIA"]
        for p in providers:
            k = os.environ.get(f"{p}_API_KEY", "")
            status = "[OK]" if k else "[WARN] Not Set"
            opts.add_option(Option(f"{p}: {status}", id=f"k_{p}", disabled=True))
        opts.add_option(Option("Back", id="back"))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        val = event.option_id
        if val == "exit":
            self.dismiss()
        elif val == "back":
            self.show_main()
        elif self.layer == "main":
            if val == "mode":
                self.show_mode()
            elif val == "agent":
                self.show_agent()
            elif val == "keys":
                self.show_keys()
            elif val == "target":
                self.app.query_one("#user_input").value = "/target "
                self.app.query_one("#user_input").focus()
                self.dismiss()
        elif self.layer == "mode":
            mode_name = val.replace("m_", "")
            self.app.mode = mode_name
            self.app._update_mode_bar()
            self.app._update_sidebar()
            self.app._chat_write_system(f"Mode set to: {mode_name}")
            self.dismiss()
        elif self.layer == "agent":
            model_map = {
                "a_gemini": "gemini/gemini-3.1-pro",
                "a_claude": "anthropic/claude-3-7-sonnet-latest",
                "a_deepseek": "deepseek/deepseek-chat",
                "a_team_gc": "gemini/gemini-3.1-pro,anthropic/claude-3-7-sonnet-latest",
                "a_team_all": "gemini/gemini-3.1-pro,anthropic/claude-3-7-sonnet-latest,deepseek/deepseek-chat"
            }
            if val in model_map:
                os.environ["ACTIVE_MODELS"] = model_map[val]
                self.app._chat_write_system(f"Active models set to: {model_map[val]}")
                self.app._update_sidebar()
                self.dismiss()

print("Syntax OK")
