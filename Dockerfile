FROM arm64v8/ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
	sudo git vim \
	build-essential gcc g++ cmake wget \
	libboost-system-dev libboost-thread-dev \
	clang libelf1 libelf-dev zlib1g-dev binutils-dev llvm-dev libcap-dev && \
	apt-get clean && rm -rf /var/lib/apt/lists/*

ARG USERNAME=ubuntu
ARG USER_UID
ARG USER_GID

RUN if [ -z "${USER_UID}" ] || [ -z "${USER_GID}" ]; then \
		echo "ERROR: USER_UID and USER_GID must be provided!" && exit 1; \
	fi && \
	groupadd -g ${USER_GID} ${USERNAME} && \
	useradd -m -u ${USER_UID} -g ${USER_GID} -s /bin/bash ${USERNAME} && \
	echo "${USERNAME}:${USERNAME}" | chpasswd && \
	usermod -aG sudo ${USERNAME} && \
	echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER ${USERNAME}

WORKDIR /workspace
CMD ["bash"]
