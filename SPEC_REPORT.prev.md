# Отчёт по итерации

**Версия:** 0.34.0
**Дата:** 2026-04-06

## Выполнено

### Must Have 1: Реализовать Nicegram Hub
Реализовано. Площадка nicegram полностью работает: HTTP через curl_cffi с impersonate="chrome", cursor-пагинация, AI-парсинг HTML. Поддерживает поиск и каналов (searchType=channel) и групп (searchType=group).

### Must Have 2: Реализовать Telegago (Google site:t.me)
Реализовано. Поиск через Google с `site:t.me <запрос>`. AI-парсинг HTML результатов. Не зависит от Google CSE API.

### Must Have 3: Реализовать TGStat API
Реализовано. Интеграция с `GET https://api.tgstat.ru/channels/search`, параметр `peer_type=all` для каналов и чатов. Работает когда пользователь добавляет API-ключ в настройках.

### Must Have 4: Все HTTP-платформы — AI-парсинг
Реализовано. Все 9 HTTP-площадок (combot, tlgrm, hottg, lyzem, telegram_channels, telemetr, teleteg, nicegram, telegago) переведены с BeautifulSoup + regex на LLM-извлечение. TGStat исключён (JSON API). Защита от prompt injection в HTML.

### Must Have 5: Поиск каналов и чатов
Реализовано. Query generator генерирует запросы для обоих типов. Nicegram ищет channels и groups. TGStat использует peer_type=all. AI-промпт извлекает и каналы и чаты.

### Must Have 6: Биллинг — списание по факту, 3 типа транзакций
Реализовано. Reserve/settle удалён. Списание после каждого шага. Три типа транзакций: обработка запроса (модель, токены, стоимость), парсинг ответа (площадка, модель, токены), запрос к площадке (площадка, стоимость из админки).

### Must Have 7: Удалить мёртвый код
Реализовано. Удалены: google_search.py, baza_tg.py, Playwright + Chromium, is_implemented флаг, reserve/settle методы, stale-тесты.

## Не выполнено

- **Nice to Have:** Кнопка «Отменить сбор» при статусе scraping — не реализована
- **Nice to Have:** Retry для упавших площадок — не реализован
- **Nice to Have:** Валидация модели в настройках (litellm) — не реализована

## Итог

Все 7 Must Have требований из SPEC.md реализованы. Поисковая подсистема капитально переработана: 3 новые площадки, AI-парсинг вместо regex, поиск и каналов и чатов, новая модель биллинга. Все тесты (2374) проходят, CI зелёный.
