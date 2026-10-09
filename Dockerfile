# Dependency resolution happens during image build; runtime installs offline from wheels.
FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels '.[api]'

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    ATTESTFORGE_TRUST_DIR=/etc/attestforge/trust \
    ATTESTFORGE_POLICY_PATH=/etc/attestforge/policy.json
RUN groupadd --gid 10001 attestforge && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin attestforge
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels 'attestforge[api]==0.1.0' && rm -rf /wheels
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "attestforge.api:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
