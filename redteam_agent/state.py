import json
from pathlib import Path


class MissionState:
    """Manages the shared blackboard state for the redteam agents."""

    def __init__(self, state_file: str = "logs/mission_state.json"):
        self.state_file = Path(state_file)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.reset()
        self.load()

    def reset(self):
        self.data = {
            "objective": "",
            "targets": [],
            "discovered_intel": {},
            "tasks": [],
            "history": [],
        }

    def load(self):
        if self.state_file.exists():
            try:
                self.data = json.loads(self.state_file.read_text(encoding="utf-8"))
            except Exception:
                self.reset()

    def save(self):
        self.state_file.write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def update_objective(self, obj: str):
        self.data["objective"] = obj
        self.save()

    def add_intel(self, key: str, val: any):
        self.data["discovered_intel"][key] = val
        self.save()

    def add_task(self, description: str, status: str = "pending"):
        self.data["tasks"].append({"description": description, "status": status})
        self.save()

    def update_task_status(self, index: int, status: str):
        if 0 <= index < len(self.data["tasks"]):
            self.data["tasks"][index]["status"] = status
            self.save()

    def clear_tasks(self):
        self.data["tasks"] = []
        self.save()

    def add_history(self, agent_role: str, action: str, result_summary: str):
        self.data["history"].append(
            {"agent": agent_role, "action": action, "result": result_summary}
        )
        self.save()

    def get_summary_prompt(self) -> str:
        """Format the entire state blackboard into a clean string for the LLM context."""
        summary = []
        summary.append(f"Mission Objective: {self.data['objective']}")

        summary.append("\n[Tasks]")
        if not self.data["tasks"]:
            summary.append("  (No tasks generated yet)")
        for i, t in enumerate(self.data["tasks"]):
            summary.append(f"  {i}. [{t['status'].upper()}] {t['description']}")

        summary.append("\n[Discovered Intel]")
        if not self.data["discovered_intel"]:
            summary.append("  (No intelligence discovered yet)")
        for k, v in self.data["discovered_intel"].items():
            summary.append(f"  • {k}: {v}")

        summary.append("\n[Command History (Recent)]")
        if not self.data["history"]:
            summary.append("  (No execution history yet)")
        # Show last 10 history items to prevent context bloat but provide enough history
        for h in self.data["history"][-10:]:
            summary.append(f"  - {h['agent']} executed: {h['action']}")
            summary.append(f"    -> Result: {h['result'].strip()}")

        return "\n".join(summary)
