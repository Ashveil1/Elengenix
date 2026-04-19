import os
import shutil

def get_new_items(current_list, history_file):
    """
    Compares the current list with the stored history file.
    Returns only the NEW items found.
    """
    if not os.path.exists(history_file):
        # First time scanning, everything is new
        with open(history_file, "w") as f:
            f.write("\n".join(current_list))
        return current_list

    with open(history_file, "r") as f:
        old_items = set(line.strip() for line in f.readlines())

    new_items = [item for item in current_list if item not in old_items]

    # Update history file with new items
    if new_items:
        with open(history_file, "a") as f:
            for item in new_items:
                f.write(f"\n{item}")

    return new_items
