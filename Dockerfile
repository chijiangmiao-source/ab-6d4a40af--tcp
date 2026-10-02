FROM node:20-alpine

WORKDIR /app

# 零依赖：只拷贝运行与复核所需文件
COPY package.json ./
COPY server.mjs ./
COPY public ./public
COPY verify ./verify

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.mjs"]
