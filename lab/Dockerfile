ARG KIL_IMAGE
FROM ${KIL_IMAGE}
WORKDIR /opt/campaign
COPY lab/campaign_bridge.py /opt/campaign/lab/campaign_bridge.py
COPY lab/g15_earning.py /opt/campaign/lab/g15_earning.py
ENV PYTHONPATH=/opt/campaign
EXPOSE 8443
HEALTHCHECK NONE
ENTRYPOINT ["python", "-m", "lab.campaign_bridge"]
