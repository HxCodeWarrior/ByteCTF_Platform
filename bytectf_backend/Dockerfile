# 使用官方 Python 基础镜像
FROM python:3.10-slim

# 设置工作目录
WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt .

# 安装 Python 依赖
RUN pip install --upgrade pip && pip install -r requirements.txt

# 复制项目文件
COPY . .

# 开放端口（Django 默认 8000）
EXPOSE 8000

# 默认启动命令
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
