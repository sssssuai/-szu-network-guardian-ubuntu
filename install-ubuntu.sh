#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ "${1:-}" != "" && "${1:-}" != "--desktop" ]]; then
    printf 'Usage: bash install-ubuntu.sh [--desktop]\n' >&2
    exit 2
fi
if [[ "$EUID" -eq 0 ]]; then
    printf '请用普通用户运行此脚本，依赖安装时会调用 sudo。\n' >&2
    exit 2
fi
desktop=false
if [[ "${1:-}" == "--desktop" ]]; then
    desktop=true
fi
packages=(python3 python3-venv python3-pip iproute2 ca-certificates)
if "$desktop"; then
    packages+=(python3-tk xdg-utils fonts-noto-cjk)
fi
sudo apt-get update
sudo apt-get install -y "${packages[@]}"
# apt's python3-venv / python3-tk belong to the distro interpreter, not to
# whichever `python3` Conda or another environment has placed first in PATH.
system_python=/usr/bin/python3
env -u PYTHONHOME -u PYTHONPATH "$system_python" -c 'import sys; assert sys.version_info >= (3, 10), "需要系统 Python 3.10+，Ubuntu 20.04 默认 Python 不适用"'
system_prefix=$(env -u PYTHONHOME -u PYTHONPATH "$system_python" -c 'import sys; print(sys.base_prefix)')
system_version=$(env -u PYTHONHOME -u PYTHONPATH "$system_python" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
if [[ -e .venv || -L .venv ]]; then
    if [[ ! -x .venv/bin/python ]] || ! env -u PYTHONHOME -u PYTHONPATH .venv/bin/python -c 'import os, sys; assert os.path.realpath(sys.base_prefix) == os.path.realpath(sys.argv[1]); assert "%d.%d" % sys.version_info[:2] == sys.argv[2]' "$system_prefix" "$system_version"; then
        printf '现有 .venv 与系统 Python 不匹配或不可用。请先将它改名备份，再重新运行安装脚本。\n' >&2
        exit 2
    fi
fi
env -u PYTHONHOME -u PYTHONPATH "$system_python" -m venv .venv
requirements=requirements-core.txt
if "$desktop"; then
    requirements=requirements.txt
fi
env -u PYTHONHOME -u PYTHONPATH .venv/bin/python -m pip install -r "$requirements"
if "$desktop"; then
    env -u PYTHONHOME -u PYTHONPATH .venv/bin/python -c 'import tkinter; print("Tkinter:", tkinter.TkVersion)'
fi
env -u PYTHONHOME -u PYTHONPATH .venv/bin/python -c 'import sys; print("项目 Python:", sys.executable, sys.version.split()[0])'
printf '\n安装完成。接下来运行：\n'
printf '  .venv/bin/python main.py --check-security\n'
printf '  .venv/bin/python main.py --configure --zone office\n'
printf '  .venv/bin/python main.py --once\n'
if "$desktop"; then
    printf '  .venv/bin/python main.py\n'
else
    printf '  .venv/bin/python main.py --headless\n'
fi
