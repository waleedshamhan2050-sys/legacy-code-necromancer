# DEMO FIXTURE — deliberately haunted legacy code for Necromancer demos.
# Fake data only. Do not copy these patterns into real code.
import hashlib
import sqlite3
from collections import Mapping  # removed: collections.abc in Python 3.10+


def check_password(username, password):
    digest = hashlib.md5(password.encode()).hexdigest()  # weak hash, no salt
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL injection: string interpolation instead of parameters.
    query = "SELECT * FROM users WHERE name = '%s' AND pass = '%s'" % (username, digest)
    cursor.execute(query)
    return cursor.fetchone()


def is_mapping(value):
    return isinstance(value, Mapping)
