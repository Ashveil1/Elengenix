import os

def load_knowledge_base(knowledge_dir="knowledge"):
    """
    Loads all text and markdown files from the knowledge directory 
    to provide the AI with extra context/training.
    """
    if not os.path.exists(knowledge_dir):
        return ""
    
    knowledge_content = "\n\n### ADDITIONAL KNOWLEDGE BASE:\n"
    found = False
    for filename in os.listdir(knowledge_dir):
        if filename.endswith(".txt") or filename.endswith(".md"):
            found = True
            with open(os.path.join(knowledge_dir, filename), "r") as f:
                content = f.read()
                knowledge_content += f"--- Knowledge from {filename} ---\n{content}\n"
    
    return knowledge_content if found else ""
