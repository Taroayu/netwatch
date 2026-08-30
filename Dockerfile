# ==============================================================================
#  NetWatch Enterprise — image de production (multi-étapes)
# ------------------------------------------------------------------------------
#  Étape 1 : compilation du front React/TypeScript (Node).
#  Étape 2 : image Python finale servant l'API + le SPA compilé.
#
#  ⚠ La capture/émission de trames ARP exige des privilèges réseau. Lancez le
#    conteneur avec accès à la pile réseau de l'hôte, par ex. :
#        docker run --rm -it \
#          --network host --cap-add NET_RAW --cap-add NET_ADMIN \
#          -e NETWATCH_PASSWORD=change-me \
#          netwatch
#    (voir docker-compose.yml pour une configuration prête à l'emploi)
# ==============================================================================

# --- Étape 1 : build du front ------------------------------------------------
FROM node:20-alpine AS frontend
WORKDIR /front
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# --- Étape 2 : runtime Python ------------------------------------------------
FROM python:3.11-slim AS runtime

# libpcap : requis par Scapy pour la capture de trames.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Code backend + front compilé (depuis l'étape 1).
COPY app.py config.py ./
COPY core/ ./core/
COPY --from=frontend /front/dist ./frontend/dist

# Données persistantes (inventaire, alertes, clé de session, certificats).
VOLUME ["/app/data"]
ENV NETWATCH_HOST=0.0.0.0 \
    NETWATCH_PORT=5000
EXPOSE 5000

CMD ["python", "app.py"]
