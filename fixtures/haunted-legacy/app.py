# DEMO FIXTURE — deliberately haunted legacy code for Necromancer demos.
# Every credential below is FAKE (placeholder text, not a real secret).
# Do not copy these patterns into real code.
import os
import pickle
import time

API_TOKEN = "DEMO-ONLY-FAKE-TOKEN-000000000000"
ADMIN_PASSWORD = "demo-fake-password"


def load_session(path):
    # Unsafe: unpickling an untrusted file can execute arbitrary code.
    with open(path, "rb") as handle:
        return pickle.load(handle)


def run_user_command(user_input):
    # Unsafe: shell injection through string concatenation.
    os.system("ls " + user_input)


def greet(name):
    # Unsafe: eval on user-controlled input.
    return eval("'" + name + "'")


def old_timestamp():
    # Deprecated: time.clock was removed in Python 3.8.
    return time.clock()


def save_note(text):
    try:
        with open("notes.txt", "a") as handle:
            handle.write(text)
    except:
        pass  # errors swallowed silently
