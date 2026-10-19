FROM python:3.12-alpine

LABEL io.hass.version="0.4.8" \
      io.hass.type="addon"

ENV PYTHONUNBUFFERED=1

# Tools the gate_run_command tool is likely to need inside its own container.
RUN apk add --no-cache bash git curl jq coreutils findutils grep sed diffutils tar

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY gate.py /app/gate.py
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
