#!/usr/bin/env python3
import sbase

with open("sbase.py", "r") as f:
    solver_base = f.read()

with open("payload.py", "rb") as f:
    payload = "\nsolver_entry(" + sbase.create_bytes(f.read()) + ")\n"

with open("solve.py", "w+") as f:
    f.write(solver_base)
    f.write(payload)
