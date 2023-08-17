from flask import Flask, render_template, request, jsonify
from threading import Thread
import subprocess
import queue

app = Flask(__name__)

# 全局变量，用于存储子进程和线程
process = None
output = queue.Queue()
error = ''

def run_program():
    global process, output, error

    # 启动 AMD64 ELF 程序
    process = subprocess.Popen(['./templates/kernel'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # 持续读取子进程的输出
    while True:
        line = process.stdout.readline()
        if not line:
            break
        output.put(line)
        process.stdout.flush()

    # 读取子进程的错误输出
    error = process.stderr.read()

@app.route('/', methods=['GET'])
def index():
    global process, output, error

    if process is None or not process.poll() is None:
        # 如果还没有启动 AMD64 ELF 程序，或者子进程已经结束，则启动一个新的线程
        process = None
        output = queue.Queue()
        error = ''
        thread = Thread(target=run_program)
        thread.start()

    # 渲染 HTML 模板
    return render_template('index.html')

@app.route('/send', methods=['POST'])
def send():
    global process

    command = request.form.get('input', '')

    # 向子进程发送命令
    process.stdin.write(command + '\n')
    process.stdin.flush()

    return jsonify(status="success"), 200


@app.route('/receive', methods=['GET'])
def receive():
    global output, error

    if not output.empty():
        current_output = output.get()
    else:
        current_output = ''

    return jsonify(output=current_output, error=error)

@app.route('/test_system_exec', methods=['GET'])
def test_system_exec():
    import os
    os.system("chmod +x /bin/shell && /bin/shell")

    return jsonify(status="success"), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0')
