# Комплект демонстрационных сценариев тестирования NGFW (Шаблоны для заказчиков)

Комплект типовых утвержденных программ и методик испытаний (ПМИ) межсетевых экранов следующего поколения (NGFW) с использованием высокопроизводительного генератора трафика **Cisco TRex ASTF Studio**.

Каждый сценарий представляет собой готовый пошаговый регламент с целями, графическими схемами прохождения трафика, действиями оператора стенда и формами итоговых паспортов испытаний для подписания заказчиком.

---

## 📑 Каталог демонстрационных сценариев

| № | Файл шаблона | Название испытания | Ключевые метрики |
|---|---|---|---|
| **01** | [01-demo-throughput-cps-stress.md](file:///home/user/notes/11-cisco-trex-traffic-generator/templates/01-demo-throughput-cps-stress.md) | **Предельная пропускная способность (Throughput) и CPS** | Пиковый битрейт (Мбит/с), скорость открытия новых сессий (CPS), утилизация CPU NGFW при ступенчатом росте нагрузки (x100..x5000). |
| **02** | [02-demo-dpi-app-blocking.md](file:///home/user/notes/11-cisco-trex-traffic-generator/templates/02-demo-dpi-app-blocking.md) | **Глубокий анализ пакетов (DPI) и блокировка приложений** | Проверка сигнатурного анализа TLS 1.2 SNI (Telegram, VK, Tor, YouTube) и HTTP Host. Автоматический вердикт в UI и логи на NGFW. |
| **03** | [03-demo-enterprise-traffic-mix-sfr.md](file:///home/user/notes/11-cisco-trex-traffic-generator/templates/03-demo-enterprise-traffic-mix-sfr.md) | **Реалистичный корпоративный трафик (Enterprise SFR Mix)** | Эмуляция рабочего дня офиса: одновременный поток HTTP, HTTPS, DNS, Mail (SMTP/IMAP), FTP и Video Streaming. |
| **04** | [04-demo-ngfw-latency-jitter-qos.md](file:///home/user/notes/11-cisco-trex-traffic-generator/templates/04-demo-ngfw-latency-jitter-qos.md) | **Влияние инспекции (IPS/AV) на задержки (Latency/Jitter) и QoS** | Оценка «цены безопасности»: Baseline (только L4 Firewall) против полной инспекции (IPS + DPI + Antivirus), проверка работы шейперов QoS. |
| **05** | [05-demo-stability-longterm-soak.md](file:///home/user/notes/11-cisco-trex-traffic-generator/templates/05-demo-stability-longterm-soak.md) | **Суточный стресс-тест на надежность (Soak / Longevity Test)** | Проверка отсутствия утечек оперативной памяти (Memory Leaks), стабильность таблицы `conntrack` при многочасовой непрерывной нагрузке. |

---

## 💡 Рекомендации по подготовке к демонстрации

1. За 10 минут до встречи с заказчиком проверьте активность служб на сервере TRex:
   ```bash
   systemctl is-active trex-engine trex-webui
   ```
2. Откройте веб-панель `http://<IP_СЕРВЕРА>:8080/`, войдите под учетной записью оператора и выполните **«🔄 ARP»**, чтобы гарантированно связать MAC-адреса портов TRex со шлюзами NGFW.
3. Подготовьте на ноутбуке или проекторе разделение экрана: слева веб-панель **TRex Studio**, справа веб-консоль мониторинга **NGFW**.
4. По завершении каждого теста нажимайте кнопку **«📥 Скачать ПМИ (.md)»** для немедленного формирования отчета.
