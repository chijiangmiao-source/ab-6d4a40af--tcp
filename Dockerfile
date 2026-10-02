FROM node:20-alpine

WORKDIR /app

# 应用只有原生 Node 依赖，无需 npm install；直接拷贝源码与样例
COPY package.json ./
COPY lib ./lib
COPY public ./public
COPY src ./src
COPY samples ./samples
COPY verify ./verify

# 构建期生成“本题捕获样例”（good/conflict PCAP 的 Base64 与期望清单）
RUN node samples/generate.mjs

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

# 容器启动前先确保样例存在（已随镜像提供，此步幂等），再提供静态服务
CMD ["node", "src/server.js"]
