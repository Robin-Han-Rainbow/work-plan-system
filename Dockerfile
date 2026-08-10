FROM node:18-alpine
WORKDIR /app
COPY package.json ./
COPY server/ ./server/
COPY deploy/ ./deploy/
EXPOSE 3000
# 持久化账号数据：运行容器时把宿主机目录挂载到 /app/server/data
#   docker run -p 3000:3000 -v /host/data:/app/server/data work-plan-system
CMD ["node", "server/server.js"]
