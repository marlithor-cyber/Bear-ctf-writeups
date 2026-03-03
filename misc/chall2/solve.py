#!/usr/bin/env python3
import ast
import re
import socket
import sys
from typing import Dict, List, Tuple


PROMPT = b"Where is the battleship > "


class Remote:
    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""

    def sendline(self, line: str) -> None:
        self.sock.sendall(line.encode() + b"\n")

    def recv_until(self, marker: bytes) -> Tuple[bytes, bool]:
        while marker not in self.buf:
            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not data:
                out = self.buf
                self.buf = b""
                return out, False
            self.buf += data
        idx = self.buf.index(marker) + len(marker)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out, True

    def close(self) -> None:
        self.sock.close()


def load_levels(path: str = "battleship.py"):
    with open(path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=path)

    levels = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.name != "main":
            continue
        for stmt in node.body:
            if not isinstance(stmt, ast.Assign):
                continue
            if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
                continue
            name = stmt.targets[0].id
            if name in {"easy", "medium", "hard"}:
                levels[name] = ast.literal_eval(stmt.value)
    return levels["easy"], levels["medium"], levels["hard"]


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def extract_board(chunk: bytes, n: int) -> List[List[str]]:
    text = strip_ansi(chunk.decode("utf-8", errors="ignore"))
    lines = [ln.rstrip("\r") for ln in text.splitlines()]
    idx = -1
    for i, ln in enumerate(lines):
        if ln.startswith("Attempts left:"):
            idx = i
    if idx < 0:
        raise RuntimeError("Could not find board in output chunk")
    board_lines = lines[idx + 1 : idx + 1 + n]
    if len(board_lines) != n:
        raise RuntimeError("Incomplete board output")
    board = [row.split() for row in board_lines]
    if any(len(row) != n for row in board):
        raise RuntimeError("Malformed board row")
    return board


def basis_inverse(n: int, basis: Tuple[int, ...]):
    inv = [None] * (n * n)
    for idx, val in enumerate(basis):
        inv[val] = (idx // n, idx % n)
    zr, zc = inv[0]
    return inv, zr, zc


def solve_round(
    conn: Remote,
    n: int,
    basis: Tuple[int, ...],
    start_chunk: bytes,
) -> Tuple[bool, bytes, bool]:
    inv, target_orow, target_ocol = basis_inverse(n, basis)
    known_rows: Dict[int, int] = {}
    known_cols: Dict[int, int] = {}
    prev_guess = None
    next_diag = 0
    chunk = start_chunk

    while True:
        if b"Try again" in chunk or b"Sorry skipper" in chunk:
            return False, chunk, True

        board = extract_board(chunk, n)

        if prev_guess is not None:
            r, c = prev_guess
            tok = board[r][c]
            if not tok.isdigit():
                raise RuntimeError(f"Expected revealed value at ({r},{c}), got: {tok!r}")
            val = int(tok)
            orow, ocol = inv[val]
            known_rows[r] = orow
            known_cols[c] = ocol

        if next_diag < n - 1:
            guess_r = next_diag
            guess_c = next_diag
            next_diag += 1
        else:
            if target_orow in known_rows.values():
                guess_r = next(r for r, orow in known_rows.items() if orow == target_orow)
            else:
                guess_r = next(r for r in range(n) if r not in known_rows)

            if target_ocol in known_cols.values():
                guess_c = next(c for c, ocol in known_cols.items() if ocol == target_ocol)
            else:
                guess_c = next(c for c in range(n) if c not in known_cols)

        prev_guess = (guess_r, guess_c)
        conn.sendline(f"{guess_r} {guess_c}")
        chunk, has_prompt = conn.recv_until(PROMPT)

        if b"Yay you won!" in chunk:
            return True, chunk, has_prompt
        if not has_prompt:
            return False, chunk, False


def extract_flag(text: str) -> str:
    m = re.search(r"[A-Za-z0-9_]+\{[^}\n]+\}", text)
    return m.group(0) if m else ""


def main():
    host = "chal.bearcatctf.io"
    port = 45457
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])

    easy, medium, hard = load_levels("battleship.py")
    stages = [easy] * 10 + [medium] * 10 + [hard] * 10

    conn = Remote(host, port, timeout=10.0)
    try:
        _, ok = conn.recv_until(b"5. Exit")
        if not ok:
            raise RuntimeError("Disconnected before menu")
        conn.sendline("4")

        chunk, has_prompt = conn.recv_until(PROMPT)
        if not has_prompt:
            raise RuntimeError("Disconnected before first round")

        for idx, stage in enumerate(stages, 1):
            n, _, basis = stage
            print(f"[+] Solving round {idx}/30 (size {n}x{n})", file=sys.stderr, flush=True)
            won, chunk, has_prompt = solve_round(conn, n, basis, chunk)
            if not won:
                text = chunk.decode("utf-8", errors="ignore")
                print(text)
                raise RuntimeError(f"Failed on round {idx}")

            if not has_prompt:
                text = chunk.decode("utf-8", errors="ignore")
                print(text)
                flag = extract_flag(text)
                if flag:
                    print(f"FLAG: {flag}")
                return

        tail, _ = conn.recv_until(b"")
        text = tail.decode("utf-8", errors="ignore")
        print(text)
        flag = extract_flag(text)
        if flag:
            print(f"FLAG: {flag}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
