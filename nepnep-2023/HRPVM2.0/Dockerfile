# 使用一个基础的 Python 镜像作为基础
FROM ubuntu:22.04

# 设置工作目录

# 复制当前目录下的所有文件到容器中的 /app 目录


RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    apt-get update && apt-get install -y lib32z1 build-essential python3 python3-pip && \
	mkdir /app && \
	pip install --no-cache-dir flask && \
	mkdir -p /app/templates && \
	pip install simple-websocket


WORKDIR /app


# 暴露容器的端口
EXPOSE 5000

# 运行 Flask 应用




# 拷贝你的PHP代码到Apache的Web服务器目录
COPY ./kernel /app/templates
COPY ./flag /app/
COPY ./index.html /app/templates
COPY ./app.py /app

RUN chmod +x /app/templates/kernel

# 启动Apache服务器
CMD ["python3", "app.py"]
