ARG KIL_IMAGE
FROM ${KIL_IMAGE}
WORKDIR /opt/campaign
COPY lab/agent_client.py /opt/campaign/agent_client.py
USER 65532:65532
ENTRYPOINT ["python", "-c", "import time; time.sleep(3600)"]
HEALTHCHECK NONE
