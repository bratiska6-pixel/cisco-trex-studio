#!/usr/bin/env bash
# ==============================================================================
# Cisco TRex & TRex Studio Web UI Automated Installer
# Target OS: Ubuntu 20.04 / 22.04 / 24.04 LTS
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}    Cisco TRex v3.08 & TRex Studio Web UI: Автоматический установщик    ${NC}"
echo -e "${BLUE}==================================================================${NC}"

# 1. Проверка прав root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERROR] Скрипт должен быть запущен с правами суперпользователя root (sudo ./install.sh)!${NC}"
  exit 1
fi

TREX_VERSION="v3.08"
INSTALL_DIR="/opt/trex"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 2. Установка системных пакетов
echo -e "\n${YELLOW}[1/7] Установка системных зависимостей (APT)...${NC}"
apt-get update -qq
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-yaml \
    python3-requests \
    net-tools \
    pciutils \
    iproute2 \
    curl \
    wget \
    zlib1g-dev \
    pciutils \
    ethtool \
    libpam0g-dev

# Установка Flask для Python 3
echo -e "${YELLOW}--> Установка Flask и вспомогательных библиотек...${NC}"
pip3 install flask pyyaml requests --quiet || apt-get install -y -qq python3-flask

# 3. Настройка памяти HugePages (2048 МБ)
echo -e "\n${YELLOW}[2/7] Настройка памяти Hugepages (1024 x 2MB = 2048 MB)...${NC}"
sysctl -w vm.nr_hugepages=1024
mkdir -p /mnt/huge
mountpoint -q /mnt/huge || mount -t hugetlbfs nodev /mnt/huge

cat << 'EOF' > /etc/sysctl.d/99-trex-hugepages.conf
vm.nr_hugepages = 1024
EOF

if ! grep -q "/mnt/huge" /etc/fstab; then
    echo "nodev /mnt/huge hugetlbfs defaults 0 0" >> /etc/fstab
fi
echo -e "${GREEN}[OK] Hugepages настроены и зафиксированы в fstab.${NC}"

# 4. Загрузка модулей ядра Linux для DPDK
echo -e "\n${YELLOW}[3/7] Загрузка модулей ядра Linux (uio, uio_pci_generic)...${NC}"
modprobe uio || true
modprobe uio_pci_generic || true

cat << 'EOF' > /etc/modules-load.d/trex-uio.conf
uio
uio_pci_generic
EOF
echo -e "${GREEN}[OK] Модули uio_pci_generic добавлены в автозагрузку.${NC}"

# 5. Скачивание и распаковка Cisco TRex v3.08
echo -e "\n${YELLOW}[4/7] Проверка дистрибутива Cisco TRex ${TREX_VERSION}...${NC}"
mkdir -p "${INSTALL_DIR}"

if [ ! -d "${INSTALL_DIR}/${TREX_VERSION}" ]; then
    echo -e "${YELLOW}--> Скачивание официального архива Cisco TRex ${TREX_VERSION}...${NC}"
    cd "${INSTALL_DIR}"
    TAR_URL="https://trex-tgn.cisco.com/trex/release/${TREX_VERSION}.tar.gz"
    
    if curl --output /dev/null --silent --head --fail "$TAR_URL"; then
        wget -q --show-progress "$TAR_URL" -O "${TREX_VERSION}.tar.gz"
        echo -e "${YELLOW}--> Распаковка архива...${NC}"
        tar -xzf "${TREX_VERSION}.tar.gz"
        rm -f "${TREX_VERSION}.tar.gz"
        echo -e "${GREEN}[OK] Дистрибутив TRex ${TREX_VERSION} успешно распакован в ${INSTALL_DIR}/${TREX_VERSION}${NC}"
    else
        echo -e "${RED}[WARN] Не удалось скачать TRex с официального сайта Cisco напрямую.${NC}"
        echo -e "${YELLOW}Пожалуйста, поместите архив v3.08.tar.gz в ${INSTALL_DIR} вручную.${NC}"
    fi
else
    echo -e "${GREEN}[OK] Каталог ${INSTALL_DIR}/${TREX_VERSION} уже существует.${NC}"
fi

# 6. Установка Web UI (TRex Studio)
echo -e "\n${YELLOW}[5/7] Развертывание веб-панели TRex Studio...${NC}"
mkdir -p "${INSTALL_DIR}/webui"
cp "${SCRIPT_DIR}/app.py" "${INSTALL_DIR}/webui/app.py"
chmod +x "${INSTALL_DIR}/webui/app.py"

# Создание скрипта запуска движка
cat << 'EOF' > "${INSTALL_DIR}/start_trex_engine.sh"
#!/bin/bash
set -e

# 1. Выделение Hugepages
sysctl -w vm.nr_hugepages=1024 2>/dev/null || true
mkdir -p /mnt/huge
mountpoint -q /mnt/huge || mount -t hugetlbfs nodev /mnt/huge

# 2. Запуск ядра TRex в режиме ASTF
cd /opt/trex/v3.08
tail -f /dev/null | ./t-rex-64 -i --astf
EOF
chmod +x "${INSTALL_DIR}/start_trex_engine.sh"

# 7. Установка служб Systemd
echo -e "\n${YELLOW}[6/7] Установка служб Systemd...${NC}"
cp "${SCRIPT_DIR}/systemd/trex-engine.service" /etc/systemd/system/
cp "${SCRIPT_DIR}/systemd/trex-webui.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable trex-engine.service
systemctl enable trex-webui.service

# 8. Создание шаблона /etc/trex_cfg.yaml
echo -e "\n${YELLOW}[7/7] Настройка конфигурации /etc/trex_cfg.yaml...${NC}"
if [ ! -f /etc/trex_cfg.yaml ]; then
    cp "${SCRIPT_DIR}/config/trex_cfg.yaml.example" /etc/trex_cfg.yaml
    echo -e "${GREEN}[OK] Создан шаблон /etc/trex_cfg.yaml${NC}"
else
    echo -e "${GREEN}[OK] Файл /etc/trex_cfg.yaml уже существует (не перезаписан).${NC}"
fi

# Итог
SERVER_IP=$(hostname -I | awk '{print $1}')
echo -e "\n${GREEN}==================================================================${NC}"
echo -e "${GREEN}    Установка успешно завершена!                                  ${NC}"
echo -e "${GREEN}==================================================================${NC}"
echo -e "Следующие шаги для первого запуска:"
echo -e "1. Определите PCI-адреса ваших сетевых карт:"
echo -e "   ${BLUE}cd /opt/trex/v3.08 && python3 dpdk_nic_bind.py --status${NC}"
echo -e "2. Привяжите адаптеры к DPDK:"
echo -e "   ${BLUE}python3 dpdk_nic_bind.py --bind=uio_pci_generic <PCI_PORT0> <PCI_PORT1>${NC}"
echo -e "3. Проверьте или отредактируйте ${BLUE}/etc/trex_cfg.yaml${NC}"
echo -e "4. Запустите службы:"
echo -e "   ${BLUE}systemctl start trex-engine.service${NC}"
echo -e "   ${BLUE}systemctl start trex-webui.service${NC}"
echo -e ""
echo -e "Веб-интерфейс TRex Studio будет доступен по адресу:"
echo -e "${GREEN}👉 http://${SERVER_IP}:8080/${NC}"
echo -e "(Авторизация: системный логин и пароль пользователя Linux в ОС)"
echo -e "=================================================================="
