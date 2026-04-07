# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.34.5] - 2026-04-07

### Fixed
- Analysis: группа застревала в IN_PROGRESS после завершения анализа — движок не записывал финальный статус (COMPLETED/FAILED) в БД, полагаясь на вычисление из чатов (сломалось в v0.34.2 при переходе на явные статусы)

## [0.34.4] - 2026-04-07

### Fixed
- Live updates: карточка анализа не обновлялась в реальном времени — morphdom заменял pending→in_progress карточку, но group-card.js не переинициализировался (скрипты не выполняются при DOM-патчинге). Добавлен `reinitGroupCards` event после morphdom.

## [0.34.3] - 2026-04-07

### Fixed
- Scraping: дедупликация refs внутри каждой платформы (6 запросов к combot давали x6 дублей в прогрессе)
- Scraping: полное WARNING-логирование пайплайна — per-query счётчики, AI-парсинг, intra/cross-platform dedup, итог сохранения

## [0.34.2] - 2026-04-07

### Fixed
- Scraping: группа показывала "Pending — no chats found" сразу после создания вместо статуса scraping (compute_group_status перезатирал DB-статус)
- Scraping: Playwright-платформы могли зависнуть навсегда — добавлен таймаут 120с на платформу
- tlgrm: API-ключ Typesense теперь парсится с сайта при первом запросе и обновляется при 401 (ротация ключа)
- Диагностика: экспорт логов показывал INFO-шум — теперь только WARNING/ERROR/CRITICAL
- Все платформы: добавлен exc_info в логи ошибок для полного traceback

### Changed
- Карточка группы: статус "Ready to analyze" вместо "pending" когда чаты найдены
- Карточка группы: при 0 чатах скрыты кнопки "Configure" и "Start", только "Delete"

## [0.34.1] - 2026-04-07

### Fixed
- Биллинг: стоимость берётся из ответа OpenRouter (реальная цена), а не fallback $5/$15 за миллион токенов — переплата ~60x для новых моделей
- AI HTML-парсинг: HTML очищается от тегов перед обрезкой до 50K — страницы вроде Nicegram (282KB) теряли все результаты
- tlgrm: переписан на Typesense API (старый URL /channels/search/ = 404)
- telegram_channels: curl_cffi + правильный параметр `?search=` (было 403 + неверный `?q=`)
- hottg: curl_cffi вместо httpx (бот UA блокировался)

### Added
- Playwright для площадок требующих JS-рендеринг (telegago, combot)
- telemetr.io: переписан как API-клиент (x-api-key, поиск Channel + Group)
- Извлечение `tg://resolve?domain=` ссылок из HTML (telegram_channels)

### Removed
- Площадка teleteg (платный сервис без API, невозможно интегрировать)

## [0.34.0] - 2026-04-06

### Added
- Nicegram Hub — новая площадка (крупнейшая база Telegram, 8M чатов), cursor-пагинация, поиск каналов и групп
- Telegago — поиск через Google `site:t.me`, без зависимости от Google CSE API
- TGStat API — полноценная интеграция (channels/search, peer_type=all для каналов и чатов)
- AI HTML-парсинг — все HTTP-площадки переведены с regex на LLM-извлечение (устойчивость к смене вёрстки)
- Биллинг: 3 типа транзакций — обработка запроса, парсинг ответа, запрос к площадке (с моделью, токенами, стоимостью)
- Поиск ищет и каналы и чаты (query_generator генерирует запросы для обоих типов)
- Защита AI-парсера от prompt injection в HTML

### Changed
- Биллинг: списание по факту вместо reserve/settle — списание после каждого шага
- Оркестратор: charge-per-step логика в collect endpoint

### Removed
- `google_search.py` — дубликат telegago, удалён
- `baza_tg.py` — API за $300, нецелесообразно
- Playwright + Chromium — зависимость удалена
- `is_implemented` флаг и фильтрация stub-платформ
- reserve/settle методы биллинга (мёртвый код)

### Fixed
- AI-парсинг: silent failure при невалидной модели — теперь пользователь видит ошибку
- TGStat: добавлен `peer_type=all` — ищет и каналы и чаты
- Тесты: удалены stale-тесты, ссылающиеся на удалённые reserve/settle методы
- CI: исправлены ошибки линтера, типизации и i18n

### Security
- URL-encode пользовательских запросов во всех URL платформ
- TOCTOU race condition в проверке баланса

## [0.33.0] - 2026-04-06

### Added
- Scraping feedback: toast-уведомление по завершении сбора («найдено X чатов с Y площадок» / «не удалось найти чаты»)
- Специальное состояние карточки группы при 0 найденных чатов (вместо молчаливого PENDING)
- Предупреждение при fallback на прямой поиск (если AI-генерация запросов не сработала)
- Сброс залипших SCRAPING-групп при запуске сервера
- Блокировка кнопки «Собрать» + спиннер во время отправки модалки

### Fixed
- Биллинг: мультипликатор стоимости не применялся в settle() — расхождение reserve vs settle
- Биллинг: search-транзакция показывала model/tokens вместо площадок и найденных чатов
- Биллинг: баланс списывался при нулевой фактической стоимости (0 чатов → нет refund)
- UI при сборе: скрыты кнопки «Настроить анализ», «Удалить», «Начать анализ» во время scraping
- Новая карточка группы не появлялась после collect без ручного обновления страницы
- Race condition: morphdom удалял карточку при быстром переходе scraping → pending
- morphdom skip logic блокировал переход scraping → pending навсегда
- Stub-платформы (nicegram, google_search) ошибочно считались успешными поисками

### Security
- TOCTOU: reserve() перемещён до asyncio.create_task() в collect endpoint
- Неатомарный topup: заменён read-modify-write на SQL INCREMENT

## [0.32.1] - 2026-04-03

### Added
- Админка: навигация по табам (Пользователи / Площадки / Система) с HTMX-переключением
- Раздел «Пользователи»: пагинация, поиск по username/email, форма создания с email
- Поле email в модели User (Alembic-миграция, nullable, unique)
- Раздел «Система»: настройки ИИ (мультипликатор стоимости, ключ OpenRouter, модели, fallback chain) и настройки анализа
- Раздел «Площадки»: вынесен в отдельный таб
- Пустое состояние при пустом результате поиска пользователей
- Сохранение активного таба в URL через hx-push-url

### Fixed
- Тёмная тема: модалка сбора чатов — hardcoded цвета заменены на CSS-переменные
- Перевод вкладки «Система» на русский язык
- Перевод кнопки «Пред.» (Prev) на русский
- Отсутствие версии в футере админки
- SQLite LIKE: использование LOWER() для регистронезависимого поиска
- IntegrityError при создании пользователя с дублирующим email/username
- Безопасность: проверка _require_admin на всех новых GET-эндпоинтах
- CI: ruff linter/formatter и mypy ошибки

## [0.32.0] - 2026-04-03

### Added
- Кнопка «Собрать чаты» + модальное окно с выбором площадок и текстовым запросом
- Новый статус группы `scraping` с индикатором прогресса по площадкам
- Спецификации 12 площадок поиска (TGStat, Telemetr, Teleteg, Nicegram Hub, Baza-TG, Combot, Hottg, TelegramChannels.me, Tlgrm.ru, Lyzem, Telegago, Google Search)
- Движок поиска: AI генерирует поисковые запросы → поиск по площадкам → дедупликация → создание группы
- Админка: настройки площадок (API-ключи, стоимость за запрос, вкл/выкл)
- Глобальный мультипликатор стоимости для AI-операций
- Биллинг поиска: проверка баланса перед стартом, списание по факту, транзакции type="search"

### Fixed
- CI: lint & type check — ошибки форматирования и mypy в scraper
- API: CSRF token missing в тестах collect endpoint
- Visual: список площадок в модалке обрезался на мобильных
- Backend: мультипликатор некорректно начислял при значении > 1.0
- Backend: InsufficientBalance вызывал settle() refund — баланс пользователя увеличивался вместо ошибки

## [0.31.2] - 2026-04-03

### Added
- Toast-уведомления: универсальный компонент для всех user actions (success/error/info/warning)
- Toast: auto-dismiss через 5 секунд, stacking, dark/light тема, мобильная адаптация
- Toast: интеграция с HTMX через HX-Trigger response header
- Toast: миграция flash→toast в admin.py и profile.py
- Skeleton loading: placeholder-блоки для таблицы каталога с shimmer-анимацией
- Микроанимации: fade-in для HTMX-контента, slide-down для dropdown и бургер-меню

### Fixed
- Skeleton: hardcoded light colors заменены на CSS-переменные (--bg-skeleton)
- Toast: удалён дублирующий showToast listener из htmx-error-handler.js
- Toast: XSS-защита — использование textContent вместо innerHTML
- Toast: корректная обработка смешанных форматов HX-Trigger
- Toast: предотвращение дублирования при refresh с flash URL-параметрами
- CI: ruff formatter — исправлены ошибки форматирования
- CI: 9 упавших тестов — исправлены
- Admin: html.escape(username) вызывал отображение &lt;admin&gt; — убран

## [0.31.1] - 2026-04-02

### Fixed
- Баг: хедер — перекрытие элементов на мобильных (375px), добавлено бургер-меню
- Баг: top-up форма — поле не очищалось после начисления, добавлен visual feedback (зелёная подсветка)
- Баг: Export CSV возвращал 500 вместо 422 при ошибке валидации
- Баг: Ruff formatter — неформатированные файлы в CI
- Баг: Неиспользуемый импорт SESSION_COOKIE_NAME в lint
- Баг: Green flash timing — использование htmx:afterSettle вместо after-request

### Changed
- UX: кнопки — современный стиль с padding, иконками, hover/active/focus transitions
- UX: Export CSV — иконка + текст, спиннер при экспорте, вписан в фильтр-панель
- UX: формы и инпуты — консистентный padding, focus-состояние, labels spacing
- UX: таблицы — zebra-striping, padding ячеек, визуальное отделение хедера
- UX: мобильная адаптация — responsive layout, touch targets (min 44px), full-width элементы
- UX: общий visual polish — spacing система (16/24/32px), тени, скругления, transitions
- UX: пустые состояния для основных таблиц данных
- UX: стилизованная модалка подтверждения вместо native hx-confirm
- Серверная валидация суммы top-up

## [0.31.0] - 2026-04-02

### Added
- AI-сервис: модуль `src/chatfilter/ai/` — обёртка над LiteLLM для вызовов OpenRouter
- AI-сервис: Pydantic-модели конфигурации (модель, fallback-список, API key)
- AI-биллинг: проверка баланса, списание стоимости, блокировка при ≤ 0
- Баланс пользователей: Alembic-миграция `ai_balance_usd` + таблица `ai_transactions`
- Админка: настройки OpenRouter (API key, модель, fallback-модели)
- Админка: управление балансом пользователей (начисление USD)
- Профиль: таблица транзакций AI (дата, тип, модель, токены, стоимость, баланс)
- Редизайн хедера: логическая группировка, AI-баланс бейдж, профиль-dropdown, иконки тема/язык
- Новые зависимости: `litellm`, `playwright`, `beautifulsoup4`, `lxml`
- CI/CD: установка и кэширование Playwright browsers

### Fixed
- CI: исправлены ошибки тестов и типов
- Профиль: исправлен 500 Internal Server Error
- Биллинг: стартовый баланс нового пользователя $1.00 (было $0.00)
- Нелокализованные строки на страницах профиля и админки (RU)

### Security
- Атомарная проверка баланса для предотвращения overdraft при конкурентных запросах
- OpenRouter API key скрыт из логов и API-ответов
- Обработка missing/null cost в ответе LiteLLM для предотвращения бесплатных запросов

## [0.30.1] - 2026-04-02

### Added
- Экспорт каталога в CSV с текущими фильтрами, сортировкой и поиском
- Alembic миграция: автозаполнение telegram_id и last_check для ранних записей
- UX: состояние «exporting...» на кнопке CSV для предотвращения двойного клика
- UX: кнопка Export CSV отключена при пустых результатах фильтрации

### Security
- Защита от CSV formula injection (санитизация ячеек)

## [0.30.0] - 2026-04-01

### Added
- Каталог: серверная пагинация (LIMIT/OFFSET + UI навигация по страницам через HTMX)
- Каталог: серверная сортировка (ORDER BY в SQL вместо Python sorted())
- Каталог: серверный поиск (LIKE в SQL вместо Python-фильтрации)
- Каталог: публичный accessor для GroupDatabase (замена engine._db)
- Каталог: пустое состояние при отсутствии результатов
- Каталог: HTMX loading indicator при загрузке таблицы
- Регрессионные тесты: NULL captcha filter + ChatTypeEnum type filter

### Fixed
- Каталог: фильтр типов чатов приведён в соответствие с ChatTypeEnum (group/forum/channel/channel+)
- Каталог: фильтр "без капчи" теперь включает чаты с captcha=NULL
- Каталог: гиперссылки для всех чатов (t.me/c/{telegram_id} для чатов без username)
- Каталог: двойной URL / title в href ссылок
- Каталог: активность 0.0 больше не сохраняется как NULL
- Worker: contextlib.suppress заменён на try/except с логированием
- CI: pipeline исправлен на main

### Security
- SQL injection protection: allowlist ORDER BY column перед интерполяцией
- Валидация chat_type в _row_to_catalog_chat

## [0.29.1] - 2026-03-31

### Added
- Персистентные сессии (SQLite SessionStore) — сессии переживают рестарт сервера
- Каталог: название чата как кликабельная гиперссылка на Telegram
- Каталог: компактные цветные бейджи типов чатов (group, chat, forum, channel, channel+)
- Каталог: полная переработка дизайна таблицы (zebra striping, ellipsis, мобильный скролл)
- Каталог: состояние ошибки для HTMX-запросов

### Fixed
- Каталог: сортировка теряла 700+ строк из-за None значений в sort key
- Каталог: HTMX sort/filter терял строки при пустых параметрах
- SessionStore: thread safety — переход с SingletonThreadPool на правильный engine
- SessionStore: cleanup_expired() не удаляла сессии при мутации last_accessed
- CI: Ruff formatter check на main

### Security
- SessionStore: сериализация через JSON вместо pickle
- Session cookie: настраиваемый secure flag через переменную окружения

## [0.29.0] - 2026-03-31

### Added
- Единая таблица чатов (каталог) — все проанализированные чаты в одном месте с фильтрацией
- Страница «Каталог чатов» с фильтрацией по всем полям (тип, подписчики, активность, модерация и т.д.)
- Управление подписками аккаунтов — аккаунт остаётся в чате, FIFO-ротация при лимите
- Фоновый scheduler автообновления метрик чатов каждые 24 часа (EMA-усреднение)
- Упрощённые настройки анализа: 2 режима (Быстрый/Глубокий) вместо 6 галочек
- Управляемые параметры в админке (макс. чатов на аккаунт, срок актуальности анализа)
- Индикатор «заморозки» чатов в каталоге (аккаунт вышел)
- Отображение cache-hit при повторном анализе чата из БД

### Fixed
- Каталог: пустые строки в фильтрах вызывали ошибку 422 (Pydantic validation)
- Каталог: значения «N/A» вызывали ошибку Pydantic при отображении
- Каталог: таблица не скроллилась на мобильных устройствах
- Каталог: навигационная ссылка не переведена на русский
- Админка: ошибка 500 из-за отсутствия таблицы app_settings
- Безопасность: /catalog и /api/catalog доступны без аутентификации
- Безопасность: эндпоинты обновления/настроек групп без проверки владельца
- Безопасность: эндпоинты системных параметров без admin-only доступа
- CI: ошибки ruff formatter, mypy import-untyped, тесты

## [0.28.0] - 2026-03-30

### Added
- SSE connection failure warning — предупреждение пользователю при проблемах с SSE-соединением
- Pending-состояние после нажатия кнопок подключения сессии / запуска анализа группы (UX)

### Fixed
- SSE streaming через BaseHTTPMiddleware — события теперь доходят до клиента в реальном времени
- Утечка мёртвых subscriber queues в ProgressTracker при отключении SSE-клиента
- Незавершённые asyncio-задачи при SSE cleanup на странице групп
- Верификация frontend SSE event handling после исправления

## [0.27.5] - 2026-03-26

### Fixed
- Переключение темы на мобильном: setAttribute('data-theme', 'light') вместо removeAttribute — теперь и иконка, и цвета меняются корректно

### Changed
- CSS: объединены дублирующиеся блоки тёмных переменных ([data-theme="dark"] + @media prefers-color-scheme) в один блок
- JS: удалён deprecated fallback `mediaQuery.addListener` в theme-switcher.js

## [0.27.4] - 2026-03-26

### Fixed
- CI: удалены неиспользованные импорты (model_validator, tempfile) — ruff lint pass

## [0.27.3] - 2026-03-26

### Added
- Toggle админских прав в админке (POST `/admin/users/{user_id}/toggle-admin`)
- Страница профиля `/profile` со сменой пароля
- Ссылка на профиль в навбаре (клик на имя пользователя)
- Защита: нельзя снять админ-права с самого себя (toggle disabled)
- Flash-сообщения об успехе/ошибке при смене пароля
- Тесты для новых auth-эндпоинтов (toggle-admin, profile, change-password)

### Fixed
- Мобильная навигация: убраны data-tooltip со всех элементов навбара (корневая причина блокировки тапов)
- Dev server не запускался (исправлена конфигурация)
- test_settings_requires_credentials: тест ожидал ValidationError, но Settings допускает None

### Changed
- Увеличены клик-таргеты на мобильном (минимум 44px)
- `_require_admin` перечитывает is_admin из БД для предотвращения stale session после toggle

## [0.27.2] - 2026-03-25

### Changed
- api_id/api_hash перенесены из per-session хранения в глобальные ENV переменные (CHATFILTER_API_ID, CHATFILTER_API_HASH)
- Приложение требует CHATFILTER_API_ID и CHATFILTER_API_HASH при старте (fail-fast)
- TelegramConfig и loader берут api_id/api_hash из ENV, не из per-session данных
- SecureCredentialManager: store_credentials/retrieve_credentials переименованы (хранит только proxy_id)
- AuthState больше не содержит api_id/api_hash

### Removed
- Поля api_id/api_hash из UI форм (auth_start_form, session_import, session_config, import_validation_result)
- api_id/api_hash из per-session config.json и encrypted storage
- Парсинг api_id/api_hash из импорта (telegram_expert, upload, validation)
- TelegramConfig.from_json_file

### Fixed
- Fail-fast валидация ENV переменных при старте приложения
- 13 тестовых файлов обновлены для соответствия новой архитектуре

## [0.27.1] - 2026-03-23

### Fixed
- 28 session test fixtures создавали директории без user_id scope
- Tests создавали MagicMock и None директории в production sessions/
- ensure_data_dir в auth_reconnect.py и auth_reconnect_helpers.py без user_id
- ensure_data_dir в auth_device.py без user_id

### Changed
- [Security] ensure_data_dir(user_id) теперь обязательный параметр (убран default None)
- [Security] Санитизация user_id в ensure_data_dir() для предотвращения path traversal
- [Security] Проверка ownership auth_id против session user_id в auth endpoints
- user_id добавлен в AuthState и проброшен в background tasks auth_initial
- [UX] Ошибки background auth flow теперь показываются пользователю
- [UX] Пустое состояние для списка прокси — новые пользователи начинают без прокси

### Removed
- Мониторинг (мёртвая фича): роутер, сервис, модели, database class
- migrate_legacy_sessions() и все вызовы
- Legacy proxy migration code (_migrate_legacy_proxy, _get_legacy_proxy_path, константы)
- Тест-файлы мониторинга (устранён pytest ImportError blocker)

## [0.27.0] - 2026-03-22

### Added
- CLI-команда `chatfilter reset-password <user> <password>` для сброса пароля из терминала
- Регрессионный тест CSRF на POST /login (form-field token)
- Тесты для CLI reset-password команды

### Fixed
- CSRF блокирует логин — POST /login возвращал 403 Forbidden (токен не находился в сессии)
- Светлая тема на странице логина отображалась некорректно
- /login убран из CSRF exempt paths (устранена login CSRF уязвимость)

### Changed
- [Security] Минимальная длина пароля в CLI reset-password
- [Security] Пароль не отображается в списке процессов при reset-password
- [Reliability] Обработка блокировки SQLite при reset-password когда приложение запущено
- [UX] Понятное сообщение об ошибке при неверных учётных данных на странице логина

## [0.26.1] - 2026-03-22

### Fixed
- Login form card stays white in dark theme — labels unreadable (CSS --card-bg not defined in dark theme)
- Proxy pool log spam: downgraded "Updated proxy in pool" to DEBUG
- Login error message styling broken in dark theme
- Timing attack in login: always run bcrypt even for unknown usernames

### Changed
- Refactored login.html to extend base_minimal.html (theme/language switchers, logo)
- Admin password logged via logger.warning instead of print()
- Login form: mobile responsive layout
- i18n translations for login page labels (username, password, submit)

## [0.26.0] - 2026-03-22

### Added
- Система аутентификации: логин-форма, сессионная кука, middleware проверки на всех роутах
- Таблица `users` в SQLite (id, username, password_hash, is_admin, created_at)
- Изоляция данных: все сессии, прокси и группы привязаны к user_id
- Админ-панель: управление пользователями (создание, удаление, смена пароля)
- Автоматическое создание админа из переменных окружения (`CHATFILTER_ADMIN_LOGIN`, `CHATFILTER_ADMIN_PASSWORD`)
- Генерация случайного пароля при первом запуске без переменных окружения
- Активный реестр Telethon-клиентов для безопасного удаления пользователя
- Fail-fast при ошибке инициализации users.db или создания админа
- Минимальная длина пароля при создании/смене пароля
- Регенерация session ID при логине и уничтожение при логауте

### Fixed
- Админ-таблица пользователей переполнялась на мобильном viewport (375px)
- SSE stream ошибка в test_new_group_auto_discovered_after_sse_connection
- mock_get_proxy_by_id() несовпадение сигнатуры
- resume_group_analysis: отсутствующий аргумент group_id
- test_proxy_retest_escapes_malicious_name возвращал 500 вместо 200
- load_proxy_pool() без аргумента user_id (legacy migration)
- remove_proxy вызывался с неожиданным 'default' user_id
- TestCheckSingleProxy/TestRetestProxy: отсутствующий аргумент user_id
- /api/version/check-updates возвращал 302 вместо 200
- TestUpdateProxyHealth: отсутствующий аргумент user_id
- /ready endpoint возвращал 302 вместо 200
- 114 тестов сломаны — CSRF fixture без аутентификации после добавления auth middleware
- test_verify_code_2fa_auto_fails_shows_manual_modal падал после добавления auth

### Changed
- ChatAnalysisService принимает user_id для per-user session paths

## [0.25.1] - 2026-03-21

### Added
- Единая система i18n: JS переводы из .po каталогов (inline через `window.__i18n__`), удалены отдельные JSON файлы
- Модуль маппинга JS ключей (`js_translations`) для генерации переводов из gettext
- CI-ready тест полноты переводов (`test_i18n_completeness`)
- Визуальная обратная связь при переключении языка (reload-based flow)
- Conftest fixture для автокомпиляции .mo файлов перед pytest
- Graceful fallback если компиляция .mo не удалась при старте

### Fixed
- SSE endpoints рендерят шаблоны без locale — сессии/чаты показывали английский в RU режиме
- `window.__i18n__` был пустым — JS переводы не инжектились в base template
- Language switcher показывал сырые i18n ключи вместо переведённого текста
- `polib` отсутствовал в dev-зависимостях — `test_i18n_completeness.py` не мог импортировать
- Браузерный кэш отдавал старый `i18n.js` — добавлен cache-busting для JS скриптов
- `i18n.js` читал `window.__i18n__` до HTTP fetch
- GET `/api/sessions` рендерился без locale context

### Changed
- Рефакторинг I18n JS класса для работы с inline данными вместо HTTP fetch
- Обновлён language-switcher для reload-based flow
- Удалены статические JSON locale файлы (`en.json`, `ru.json`)
- XSS-защита: `textContent` вместо `innerHTML` для переведённых строк в JS
- XSS-защита: экранирование inline JSON переводов против `</script>` инъекции

## [0.25.0] - 2026-03-21

### Added
- **Auto-retry ERROR chats**: After main queue completes, ERROR chats are automatically re-queued once (no infinite loop)
- **Instant card loading overlay**: Clicking Start/Resume/Reanalyze immediately shows spinner overlay on group card
- **Retry phase in progress counter**: Shows retry progress during auto-retry phase

### Changed
- **i18n full audit**: All msgids converted to English; Russian and English .po files fully translated
- **i18n JS files**: Fixed hardcoded Russian strings in JavaScript locale files
- **Badge simplification**: Group card now shows only chat type badges (Groups, Forums, Channels+, Channels, Dead); removed status badges (Pending, Done, Error, Skipped)
- **Type badges hidden before analysis**: Chat type badges only shown when analysis data exists

### Fixed
- **i18n RU mode**: Fixed English strings appearing on Sessions, Chats, and Proxies pages in Russian mode
- **i18n flood_wait namespace**: Fixed renamed i18n namespace in flood-wait-countdown.js
- **i18n missing 'Needs API ID'**: Added missing translation to Russian messages.po
- **Auto-retry security**: Scoped auto-retry query to current group_id
- **Auto-retry guard**: Prevented infinite loop and double finalize_group calls
- **Spinner error handling**: Instant spinner handles 4xx/5xx errors to avoid stuck UI
- **Test regressions**: Updated test_overwrite_resets_chat_statuses for auto-retry

## [0.24.0] - 2026-03-20

### Changed
- **Non-blocking analysis endpoints**: Start/Resume/Reanalyze endpoints now return immediately; heavy validation runs in background task
- **Loading states on all buttons**: All interactive buttons across /chats, /sessions, /proxies show instant feedback (spinner, disabled state)
- **Group card auto-update on completion**: Card automatically transitions to "completed" when analysis finishes (SSE complete event + morphdom fix)
- **Concurrent analysis guard**: Prevents duplicate analysis starts after async refactor
- **Background task crash handling**: Prevents group stuck in IN_PROGRESS if background task fails

### Removed
- **Elapsed timer**: Removed glitchy M:SS timer from group card (startElapsedTimer, stopElapsedTimer, formatElapsed, elapsed-{id} element)
- **Network status indicator**: Removed green/red internet connection indicator from header (network-status.js, .network-status CSS, related i18n keys)
- **executeScripts()**: Removed from refreshGroups polling (no longer needed after timer removal)

### Fixed
- **Test regressions**: Fixed resume_group_analysis tests after session validation refactor (mock get_info to return SessionState.CONNECTED)
- **Test regressions**: Fixed start_analysis tests after sync-to-async refactor
- **i18n JSON trailing commas**: Fixed broken translations caused by trailing commas in JSON locale files
- **Proxies page mobile clipping**: Fixed content clipped on mobile viewport (375px)
- **Import save form**: Added hx-disabled-elt to prevent double-submit
- **Proxy delete button**: Disabled delete button during fetch in proxy-form.js

## [0.23.0] - 2026-03-19

### Fixed
- **Create Group form submission**: Fixed HTMX `hx-post` not firing in import chats modal — form now submits correctly via POST `/api/groups`
- **Modal re-open JS error**: Wrapped inline JS in `create_group_modal.html` in IIFE to prevent `const` re-declaration error on repeated modal opens
- **Export modal scope pollution**: Wrapped inline JS in `export_modal.html` in IIFE to prevent scope pollution on re-open
- **Settings modal scope pollution**: Wrapped inline JS in `settings_modal.html` in IIFE to prevent scope pollution on re-open
- **Keydown event listener leak**: Fixed keydown listener not being cleaned up when create group modal is closed
- **Error message swap target**: Fixed error messages swapping into wrong target in create group form

### Changed
- **Loading state for Create Group**: Submit button now shows spinner + "Creating..." during form submission
- **CSRF error handling**: Added explicit error handling for CSRF token failures in create group form with user-facing toast message
- **Error message UX**: Improved error message display in Create Group modal — errors now appear inline in modal
- **Audit: buttons and JS**: Full audit of all interactive elements across /chats, /sessions, /proxies — all buttons confirmed working
- **Audit: modal inline JS**: Verified all HTMX-loaded modals use IIFE pattern to prevent scope issues
- **E2E tests**: Added automated functional tests for import chats modal flow

## [0.22.0] - 2026-03-19

### Fixed
- **Edit button fix**: Fixed non-working "Edit" (Редактировать) button in session row on /sessions page
  - Root cause: JavaScript `htmx:afterSwap` event listener in `sessions-list.js` was not executing despite HTMX successfully loading config form
  - Fix: Corrected Edit button click handler and HTMX flow so config panel (`config-row`) toggles visibility correctly
  - Config form with API ID, API Hash, Proxy fields now loads and displays properly
  - Toggle behavior works: repeated click collapses the panel

## [0.21.0] - 2026-03-17

### Changed
- **ProxyConfig extraction**: Extracted `ProxyType`, `ProxyStatus`, `ProxyConfig` from `config.py` to dedicated `config_proxy.py` module
- **Import migration (12 files)**: Updated all consumers (6 src/ + 6 tests/) to use direct `from chatfilter.config_proxy import ...` paths
- Backward-compatible re-exports preserved in `config.py`

### Fixed
- **Test mock paths**: Fixed `get_event_bus` patch paths in auth_flow_fixes tests after sessions package refactor
- **Version sync**: Fixed `__init__.py` version stuck at 0.19.1

## [0.20.0] - 2026-03-17

### Changed
- **config.py decomposition**: Extracted filesystem utilities (`_is_path_readonly`, `_format_permission_error`, `_get_default_data_dir`, platform checks) to `config_filesystem.py`
- **error_mapping.py cleanup**: Extracted `_format_duration` and `_extract_wait_time` utilities to `telegram/error_utils.py`
- **utils/logging.py split into package**: Replaced monolithic `utils/logging.py` (546 lines) with `utils/logging/` package:
  - `sanitizer.py` — LogSanitizer, SanitizingFormatter, SENSITIVE_PATTERNS
  - `context.py` — Correlation ID, chat ID context management
  - `formatting.py` — JSONFormatter, TimingContext, timing decorator
- **Import migration (54 imports, 38 files)**: Updated all consumers to use direct submodule paths:
  - `telegram.session_manager` → `telegram.session` (src/ + tests/)
  - `telegram.client` → `telegram.client.loader/messages/chats/config/membership` (src/ + tests/)
  - Simplified `client/__init__.py` and `helpers.py` re-exports after migration
- **Deleted deprecated stub**: Removed `telegram/session_manager.py` compatibility stub

## [0.19.1] - 2026-03-16

### Fixed
- **Missing re-exports after module split**: Fixed missing `get_settings` re-export in `sessions/helpers.py`, `get_rate_limiter` and private functions (`_parse_chat_reference`, `_telethon_message_to_model`, `_get_forum_topics`) in `telegram/client/__init__.py`
- **Test mock paths**: Fixed 17+ test failures caused by mock patches targeting old module paths after helpers.py split (device confirmation, session upload, forum messages, join rotation, 2FA, legacy sessions)
- **Build command**: Fixed build failure after module decomposition
- **Server startup**: Fixed dev server startup failures after refactoring

### Changed
- **Session module structure**: Simplified `telegram/session/` to 2 modules (`models.py`, `manager.py`) instead of 4, keeping SessionManager class intact as designed in SPEC

## [0.19.0] - 2026-03-16

### Changed
- **telegram/client.py split into modules**: Replaced monolithic `telegram/client.py` (2,099 lines) with `telegram/client/` package containing 5 focused modules:
  - `config.py` — Configuration and credential management
  - `loader.py` — Client creation and initialization
  - `chats.py` — Dialog fetching and chat operations
  - `messages.py` — Message fetching and streaming
  - `membership.py` — Join/leave operations and account info
- **telegram/session_manager.py split into modules**: Replaced monolithic `telegram/session_manager.py` (1,228 lines) with `telegram/session/` package containing 4 focused modules:
  - `manager.py` — Session connection management
  - `auth.py` — Authentication flows
  - `validators.py` — Session validation
  - `cleanup.py` — Cleanup and recovery
- **sessions/helpers.py split into modules**: Split monolithic `sessions/helpers.py` (847 lines) into 3 focused modules:
  - `helpers.py` — Core helper functions
  - `io.py` — I/O operations
  - `listing.py` — List formatting

### Fixed
- **Private function re-exports**: Re-exported private functions in `telegram/client/__init__.py` to maintain backward compatibility after module split

## [0.18.0] - 2026-03-16

### Changed
- **JS extraction: base.html**: Extracted ~950 lines of inline JS from `base.html` into 7 separate modules:
  - `static/js/csrf-config.js` — CSRF token setup for HTMX
  - `static/js/toast-manager.js` — ToastManager + global error/rejection handlers
  - `static/js/modal-manager.js` — ModalManager (confirm dialogs, focus trap)
  - `static/js/htmx-error-handler.js` — HTMX responseError, sendError, timeout, swapError handlers
  - `static/js/network-status.js` — NetworkStatusMonitor (health polling, online/offline, TabSync)
  - `static/js/sse-status-banner.js` — SSEStatusBanner (show/hide banner, CSS moved to style.css)
  - `static/js/analysis-state-tracker.js` — AnalysisStateTracker + beforeunload protection
- **JS extraction: sessions_list.html**: Extracted ~680 lines of inline JS into `static/js/sessions-list.js` (SSE handling, operation timers, code/2FA modals, MutationObserver)
- **JS extraction: proxies.html**: Extracted ~310 lines of inline JS into `static/js/proxy-form.js` (ProxyFormModal, form validation, edit/delete handlers)
- **i18n keys**: Added translation keys for all extracted JS modules to `static/locales/en.json` and `static/locales/ru.json`
- **XSS protection**: Added sanitization to ToastManager.createToastHTML() and ModalManager confirm dialogs

### Fixed
- **proxy-form.js crash**: Fixed proxy-form.js crashing on non-proxy pages (sessions, chats) due to missing DOM elements
- **i18n race condition**: Fixed raw i18n keys showing in error toasts before translations loaded
- **Missing sessions_list translations**: Added missing translation keys for sessions list page
- **Test assertion path**: Updated test_template_has_sse_htmx_integration to check sessions-list.js instead of template after JS extraction

## [0.17.0] - 2026-02-27

### Changed
- **JS extraction: group_card.html**: Extracted ~370 lines of inline JS from `group_card.html` into `static/js/group-card.js` (SSE handler, stale detection, timers, DOM updates, AbortController cleanup)
- **JS extraction: session_row.html**: Extracted FloodWait countdown timer from `session_row.html` into `static/js/flood-wait-countdown.js`
- **JS extraction: chats.html**: Extracted ~220 lines of inline JS from `chats.html` into `static/js/chats-page.js` (SSE error/reconnect handling, polling fallback, group refresh)
- **Test restructuring**: Split monolithic `test_sessions_router.py` (4,002 lines) into `tests/sessions/` package with focused modules (test_routes, test_connect, test_auth, test_upload, test_sse, test_helpers, conftest)

### Fixed
- **SSE current chat display**: Current analyzed chat title now shown in group card during analysis
- **SSE DOM jitter**: Fixed screen jitter on SSE updates by updating individual DOM elements instead of full card re-render
- **SSE false stale warning**: Fixed false "analysis hung" warning when heartbeat ping correctly resets stale timer

## [0.16.0] - 2026-02-26

### Changed
- **sessions.py split into modules**: Replaced monolithic `sessions.py` (5,281 lines, 52 functions) with `routers/sessions/` package containing 13 focused modules (each < 800 lines)
  - `routes.py` — HTTP endpoints and TemplateResponse
  - `connect.py` — connect/disconnect/reconnect flows
  - `auth_initial.py` — initial auth (send_code, verify_code, verify_2fa)
  - `auth_reconnect.py` — reconnect auth flow
  - `auth_reconnect_helpers.py` — reconnect auth helpers
  - `auth_device.py` — device confirmation polling
  - `auth_errors.py` — auth error handling
  - `upload.py` — upload, import, validate
  - `validation.py` — config validation
  - `helpers.py` — shared utilities (sanitize, validate, SessionListItem, locks)
  - `background.py` — background tasks
  - `sse.py` — SSE endpoint
  - `__init__.py` — re-export router + backward compatibility
- **Template deduplication**: Removed `session_actions.html` and `session_connection_button.html` — session state rendering now handled by `session_row.html` only

### Fixed
- Fix test mock paths after sessions/ package refactor
- Fix mock path: get_event_bus in 2FA manual modal test
- Fix mock path: ensure_data_dir in 2FA auto-entry tests
- SMOKE: Missing import _finalize_reconnect_auth blocks 7 tests
- SMOKE: Fix test imports after sessions.py refactoring
- SMOKE: Connect/disconnect endpoints failing — 14 tests
- SMOKE: Auth flow doesn't return session row after 2FA
- SMOKE: Session factory not found in background tasks
- SMOKE: Connect flow state transitions failing
- SMOKE: SSE event publishing not working after refactor
- SMOKE: auth_reconnect missing get_event_bus import
- SMOKE: Save account without connect failing

## [0.15.1] - 2026-02-26

### Fixed
- **STOP button bypass**: Added status check before auto-resume in `_wait_for_accounts_and_resume()` — paused groups no longer restart automatically
- **STOP button cancellation**: Registered waiting coroutine in `_active_tasks` so STOP cancels it immediately instead of waiting for next polling cycle
- **FloodWait badge on sessions**: Added `flood_wait_until` to all 19 `SessionListItem` constructors — FloodWait badge no longer disappears after HTMX actions
- **FloodWait initial render**: Added FloodWait badge to `sessions_list.html` initial page render (was only visible via SSE updates)
- **SSE error banner on navigation**: Added debounce to sessions page SSE error handler — no more false "connection lost" banners during page navigation
- **Loading placeholder persists**: Fixed `no-groups` placeholder remaining visible alongside loaded group cards on /chats page
- **Test timeouts**: Fixed 4 test timeouts in `test_waiting_for_accounts.py` caused by unshutdown ThreadPoolExecutor

### Changed
- **FloodWait cleanup events**: `get_blocked_accounts()` now publishes `flood_wait_cleared` events when removing expired entries
- **STOP/Resume toasts**: Added user feedback toasts for STOP and Resume operations
- **FloodWait countdown**: Added JavaScript countdown timer for FloodWait on sessions page
- **Regression tests**: Added web regression tests for SSE progress, resume, CSV export

## [0.15.0] - 2026-02-25

### Added
- **SSE error event handler**: Shows analysis failures in real-time via SSE error events in group cards
- **Safety polling fallback**: 30-second interval polling as fallback when SSE is active, preventing UI freeze if SSE breaks

### Fixed
- **Stale DOM references in SSE listener**: SSE event handler now uses `getElementById` on each event instead of cached references, fixing progress bar/numbers not updating after `refreshGroups()` innerHTML swap
- **Listener leak on card refresh**: Named function + AbortController for SSE listener cleanup — old listeners no longer accumulate on `document.body` when cards are re-rendered
- **Test isolation from production DB**: Tests now use isolated temporary databases via `conftest.py` fixture override, preventing test data from polluting `~/Library/Application Support/ChatFilter/groups.db`
- **SSE keepalive when no analysis running**: Fixed SSE endpoint exiting immediately when no groups had active status (carried over from 0.14.1)

## [0.14.1] - 2026-02-25

### Fixed
- **SSE connection spam when no active groups**: SSE endpoint exited immediately when no groups had IN_PROGRESS/WAITING_FOR_ACCOUNTS status, causing infinite "Connection lost" notifications. Now keeps connection alive with heartbeat pings regardless of active group count.

## [0.14.0] - 2026-02-24

### Added
- **Randomized rate limiting for all Telegram API calls**: `get_entity`, `get_full_channel` now pass through rate limiter with randomized delays (5-10s between chats, 0.5-2s between requests within a chat)
- **FloodWait account lockout**: In-memory registry tracks FloodWait per account; pre-request check blocks all Telegram API calls from locked account until timer expires
- **WAITING_FOR_ACCOUNTS group status**: When all accounts are in FloodWait, group enters "Wait For Accounts" state with auto-resume polling loop (~30s) that resumes analysis when an account becomes available or a new account is added
- **Health tracker ignores dead chats**: "Username not found", "Channel private/banned" no longer count as account failures; FloodWait exhaustion also excluded from health score
- **FloodWait countdown in sessions UI**: Sessions page shows "FloodWait до HH:MM" with live countdown timer via SSE
- **FloodWait status in group card**: Group card renders `flood_wait_until` and WAITING_FOR_ACCOUNTS status with countdown to nearest account unlock
- **Pause/Stop button for WAITING_FOR_ACCOUNTS**: Users can stop analysis while waiting for accounts
- **Confirmation dialog for stopping WAITING_FOR_ACCOUNTS**: Prevents accidental stop during wait
- **FloodWait persistence**: FloodWait state survives app restarts
- **Thread safety for rate limiter**: Safe for concurrent multi-account workers
- **TTL cleanup for expired FloodWait entries**: Automatic garbage collection
- **Error modal when starting analysis with zero accounts**: Clear feedback instead of silent failure

### Fixed
- **FloodWait does NOT stop worker**: Worker now checks `flood_tracker.is_blocked()` before each chat and breaks the loop, leaving remaining chats PENDING
- **test_only_8_states_in_templates false-positives**: Fixed substring matching that falsely flagged `flood_wait` in templates

### Changed
- **Rate limiter architecture**: Extended existing `rate_limiter.py` with `get_entity` and `get_full_channel` operations and randomized delay ranges
- **Health tracker error classification**: Distinguishes dead-chat errors from real account errors
- **FloodWait error log sanitization**: Phone numbers stripped from FloodWait log messages
- **Network binding validation**: Warning for non-localhost deployments

## [0.13.0] - 2026-02-24

### Added
- **Unified SSE channel for groups**: Single `/api/groups/events` endpoint multiplexes progress events for all groups through one SSE connection, replacing per-group SSE connections that exhausted browser connection limit (6 on HTTP/1.1)
- **Resume live update**: Clicking "Continue analysis" immediately transitions group card to active state with real-time SSE progress updates — no page reload needed
- Integration tests for unified SSE with 10+ simultaneous groups
- SSE reconnect scenario tests
- Smoke test for group analysis pipeline

### Fixed
- SMOKE: SSE unified endpoint tests fail due to mock mismatch (get_all_groups → list_groups)
- SMOKE: SSE endpoint crashes with AttributeError (ChatGroup.group_id → ChatGroup.id)
- SMOKE: Unified SSE endpoint immediately fails with AttributeError
- SMOKE: /api/groups/events returns 404 due to route ordering
- SMOKE: 6 test files have import errors after dead code cleanup

### Changed
- **SSE architecture**: Moved from per-card `sse-connect` to page-level SSE container — one connection handles all group cards
- Input validation for unified SSE endpoint
- Error handling to prevent SSE data leakage
- CSP header to prevent XSS escalation
- Group ownership validation in unified SSE endpoint

### Removed
- **Dead code cleanup**: Removed old per-chat analysis system
  - `/{task_id}/progress` SSE endpoint
  - `/api/analysis/start`, `/api/analysis/{task_id}/cancel` and related routes
  - `analysis_progress.html` template
  - Old per-group SSE endpoint `/api/groups/{id}/progress`
  - Unused TaskQueue and task_execution modules (after dependency audit)

## [0.11.1] - 2026-02-22

### Fixed
- Fix integration/test_group_analysis.py: adapt 16 tests to new schema
- Fix pytest config: add pythonpath=[src] for src-layout
- Fix test_group_database.py: remove group_results references, use new columns
- Fix test_reanalysis.py: adapt to new schema (metrics as columns)
- SMOKE: [Backend] 25 tests fail due to database schema mismatch (group_results removed)
- SMOKE: [Backend] 3 test files cannot load due to missing imports (_ResolvedChat, CAPTCHA_BOTS)
- SMOKE: [Backend] Group status computation not implemented — 8 test failures
- SMOKE: [Backend] group_tasks table not tested
- SMOKE: [Backend] Migration v5 not tested — risk of data loss
- SMOKE: [Backend] New data model (metrics as columns) not validated
- SMOKE: [Must Have] Progress bar counts only DONE, ignores ERROR chats

## [0.11.0] - 2026-02-21

### Added
- Chat reassignment on ban — try other accounts before marking DEAD
- Live badges via SSE — progress events include status breakdown

### Fixed
- Fix stale test: test_time_window_limits_message_fetch expects old broken behavior
- SMOKE: [Tests] time_window validation incomplete - enum vs range
- SMOKE: [Backend] Missing partial_data parameter in moderation check
- SSE completion — engine sends None sentinel, JS stops timer
- Fix offset_date in iter_messages — activity will stop being 0

### Changed
- [UX] Add error states and retry UI for failed chats
- [Security] Validate time_window parameter to prevent resource exhaustion
- [Reliability] Add timeout to iter_messages for massive chats
- [UX] Show INCREMENT scope preview before analysis
- [Reliability] Handle late SSE subscriber after completion
- Add metrics_version to activity results for INCREMENT recount

## [0.10.9] - 2026-02-21

### Fixed
- Fix: test_startup_smoke uses system chatfilter instead of venv
- SMOKE: [Backend] INCREMENT mode counts DONE chats as analyzed instead of skipping
- SMOKE: [Backend] Progress counter not monotonic - decreases during multi-account analysis
- SMOKE: [Must Have] group_card.html scripts not executed - innerHTML bypass
- SMOKE: [Must Have] SSE events not dispatched - missing sse-swap attributes in group_card.html

## [0.10.8] - 2026-02-19

### Fixed
- Fix: Add 5-minute timeout to Phase 2 activity analysis
- Fix: pyproject.toml version out of sync (0.10.6 vs 0.10.7)
- SMOKE: [Backend] GroupStats model lost status breakdown (test failure)
- SMOKE: [Backend] Missing tests for 5-minute chat analysis timeout
- SMOKE: [Backend] Missing tests for SSE heartbeat & stale detection
- SMOKE: [Backend] Resume concurrent requests return 400 instead of 409
- SMOKE: [Backend] Resume nonexistent group HTTPException not caught

### Changed
- [Architecture] Clarify: SSE vs polling for live progress — choose one approach
- [Architecture] Use SSE instead of polling for live progress updates
- [OPS] Add smoke test for SSE progress endpoint
- [Reliability] Add idempotency check for concurrent resume requests
- [Reliability] Add server-side empty state validation in resume endpoint
- [Reliability] Add SSE fallback to polling on connection failure
- [Reliability] Add SSE heartbeat and client-side reconnection logic
- [Reliability] Graceful shutdown: cancel in-progress analysis tasks before startup recovery
- [Security] Add DB lock for startup recovery to prevent race condition
- [Security] Add group existence and status validation to resume endpoint
- [Security] Add structured logging for chat timeout events
- [UX] Add empty state check before resume analysis
- [UX] Auto-refresh card state when user returns to /chats page
- [UX] Design and implement 'stale analysis' warning UI element
- [UX] Show 'Starting analysis...' state immediately after start button click
- [UX] Show failed chat details with retry option

## [0.10.7] - 2026-02-19

### Added
- **Resume paused groups**: POST /api/groups/{group_id}/resume endpoint for resuming paused analyses
  - 'Продолжить анализ' button for paused groups
  - Atomic status transitions with conflict detection (409 for concurrent requests)
  - Validation: 404 for non-existent groups, 400 for non-paused or empty groups
  - Only pending and failed chats reanalyzed (done chats skipped)
- **SSE real-time progress**: Group cards now update via Server-Sent Events instead of polling
  - Current chat name and elapsed time visible during analysis
  - Progress bar updates in real-time
  - Card auto-updates to completed/paused/failed status without page reload
- **Startup crash recovery**: Server restart detection with automatic state recovery
  - Orphaned in_progress groups automatically reset to paused
  - Stale analyzing chats reset to pending
  - Recovery logged at startup

### Changed
- **Status localization**: Group status badges now show translated text (in_progress → Анализируется)
  - Russian translations: pending→Ожидание, in_progress→Анализируется, paused→Приостановлен, completed→Завершён, failed→Ошибка

### Fixed
- **Phase 1 timeout**: Added 5-minute per-chat timeout in Phase 1 analysis
  - Chats stuck in analyzing state now marked as failed with timeout error
  - Analysis continues for remaining chats instead of hanging entire group

## [0.10.6] - 2026-02-19

### Fixed
- SMOKE: [Server] Dev server failed to start
- SMOKE: [Must Have] Retest endpoint returns JSON instead of HTML
- SMOKE: [Must Have] Static CSS served stale — spinner fix not applied to browser
- SMOKE: [Backend] Proxy retest saves UNTESTED status prematurely
- SMOKE: [Visual] Retest endpoint returns English labels instead of user locale
- SMOKE: [Must Have] Status text does not change to Testing... during proxy retest

### Changed
- [Security] Sanitize error messages in retest endpoint
- [OPS] Add smoke test: verify app starts and responds
- [UX] Add empty state to proxy pool page when no proxies configured
- [OPS] Add unit tests for retest_proxy and update_proxy_health
- [UX] Ensure spinner clears and new status appears after successful retest

## [0.10.5] - 2026-02-19

### Fixed
- HTMX loading state: spinner on status icon + disabled button during test
- Retest endpoint now returns HTML <tr> instead of JSON for proper HTMX swap
- retest_proxy: don't save UNTESTED status before health check completes
- update_proxy_health: propagate storage write errors

### Changed
- [OPS] Add unit tests for retest_proxy and update_proxy_health
- [Architecture] Consolidate spinner CSS: replace spinner-sm with spinner-small

## [0.10.4] - 2026-02-19

### Fixed
- SMOKE: [Must Have] Pre-connect proxy diagnostic doesn't update session_manager state — session stuck in Connecting

### Changed
- [Reliability] Add explicit timeout for SOCKS5 handshake in health check
- [OPS] Integration test for real SOCKS5 proxy health check
- [Security] Add SOCKS5 auth failure handling without credential exposure
- [UX] Document error message UI delivery for pre-connect diagnostic
- [Security] Sanitize proxy credentials in logs and error messages
- [UX] Add loading states for SOCKS5 health check and pre-connect diagnostic
- [Reliability] Pre-connect proxy test must timeout faster than full connect
- Tests for SOCKS5 health check and pre-connect diagnostics
- Pre-connect proxy diagnostic in _do_connect_in_background_v2
- SOCKS5 health check: replace TCP-only with full SOCKS5 handshake + Telegram DC tunnel
- Plan reviewed
- Planning complete: v0.10.4 proxy diagnostics

## [0.10.3] - 2026-02-19

### Fixed
- Fix: __init__.py __version__ stuck at 0.9.12, should be 0.10.2
- Fix: test_orphan_safety_net_fills_missing_results timeout (>30s regression)
- SMOKE: [Backend] Phase 1 retry logic missing floodwait_retry_count initialization

### Changed
- [Security] Verify FloodWait exception sanitization in logs
- [Security] Add global analysis timeout to prevent DoS via FloodWait
- Fix INCREMENT early-exit: all-DONE must proceed to Phase 2
- Increase MAX_FLOODWAIT_SECONDS to 1800 and base join delay to 5s
- Phase 2: Handle RateLimitedJoinError with proper wait
- Add RateLimitedJoinError subclass to preserve FloodWait seconds

## [0.10.2] - 2026-02-18

### Fixed
- SMOKE: [Backend] AttributeError: 'State' object has no attribute 'session_manager'
- SMOKE: [Backend] Test failure: test_start_returns_hx_trigger_header
- SMOKE: [Export] CSV export crashes with ValueError on string messages_per_hour
- SMOKE: [Must Have] Card does not update to in_progress on Start analysis click
- SMOKE: [Must Have] Error toast swallowed by hx-swap=none on start/reanalyze buttons
- SMOKE: [Must Have] Reanalyze endpoint crashes: cannot access local variable json
- [Backend] Fix INCREMENT progress counter: count only chats-to-process, not all done+failed
- [Backend] Make start/reanalyze endpoints non-blocking (asyncio.create_task)
- [Frontend] Add toast on analysis start + trigger polling after button click

## [0.10.1] - 2026-02-17

### Fixed
- Fix account task exception: save dead results after asyncio.gather failure
- Fix outer exception handler: save dead results for remaining chats
- SMOKE: [Regression] test_overwrite_resets_chat_statuses broken by orphan safety net
- SMOKE: [Must Have 4] test_all_chats_get_results_pass_or_dead times out (>30s)
- Add orphan safety net: verify all chats have group_results after Phase 1

### Changed
- [Reliability] Atomic database updates in exception handlers
- [OPS] Add assertion: verify result count matches chat count before completion
- [OPS] Add regression test: 100+ chats must all get results
- [UX] Show account recovery notification in analysis progress
- [Reliability] Handle FloodWaitError in outer exception handler
- Add tests for account-level exception recovery
- Add test for outer exception handler in _phase1_resolve_account
- Plan reviewed
- Planning complete: v0.10.1 analysis completion fix

## [0.10.0] - 2026-02-17

### Added
- Add re-analysis mode parameter to start_analysis()

### Fixed
- SMOKE: [Backend] Missing tests: re-analysis feature (100% untested)
- SMOKE: [Backend] Missing tests: all chats get results guarantee
- SMOKE: [Backend] API signature mismatch in _save_phase1_result()
- SMOKE: [Backend] Database schema missing subscribers column
- SMOKE: [Backend] Missing test: FloodWait continuation
- SMOKE: [Backend] Missing tests: exclude_dead checkbox removal
- SMOKE: [Backend] Database migration fails to remove duplicates
- SMOKE: [Backend] CSV export includes error_reason when not selected
- Ensure save_result() called for every chat (dead included)
- Add retry mechanism to Phase 2 activity analysis
- Replace break with retry queue in Phase 1 FloodWait handler

### Changed
- Resolve rebase conflict: Add retry mechanism to Phase 2 activity analysis
- [Security] Add MAX_RETRY_COUNT constant to prevent DoS
- [Reliability] Re-check account health before retry attempts
- [Reliability] Add per-chat timeout to prevent retry queue stalls
- [Architecture] Add unique constraint on (group_id, chat_ref) for group_results
- [Reliability] Add UNIQUE constraint on group_results (group_id, chat_ref)
- [OPS] Add FloodWait monitoring and statistics
- [Security] Add UNIQUE index on group_results to prevent race condition
- [OPS] Add integration tests for retry mechanism and incremental analysis
- [Security] Prevent concurrent re-analysis on same group (409/429)
- [UX] Add confirmation modal for 'Перезапустить анализ' button
- [UX] Add detailed retry progress messages in SSE stream
- Add re-analysis API endpoints
- Implement skip logic for already-collected metrics in analysis loop
- Add upsert_result() to group_database for incremental analysis

## [0.9.12] - 2026-02-17

### Fixed
- FloodWait retry mechanism no longer silently skips chats after exhausting retries
- All chats now saved in group_results table, including dead/failed chats

### Removed
- Removed 'Exclude dead' checkbox from export modal (dead chats filterable via Chat Types)

### Added
- Incremental re-analysis mode (supplement existing metrics without clearing data)
- Full re-analysis mode (overwrite all metrics, clear existing data)
- Re-analysis buttons on group card UI ('Дополнить анализ' and 'Перезапустить анализ')

## [0.9.11] - 2026-02-16

### Fixed
- SMOKE: [Server] Dev server failed to start
- Bug #2: Publish SSE progress events during analysis
- Bug #3: Fix stop_analysis chat status reset and restart logic
- Bug #1B: Add Subscribers column to analysis_results.html UI table
- Bug #1A: Ensure subscribers saved in group_results and included in CSV fallback
- Bug #4: Detect CHANNEL_COMMENTS via linked_chat_id in _channel_to_chat_type
- Bug #5: Fix chat type checkboxes in export modal

### Changed
- [UX] Add empty state for analysis results (0 results after completion)
- Optimize SSE progress event DB queries in group_engine
- [Reliability] Log GetFullChannelRequest failures at WARNING level
- [Reliability] Add crash recovery: reset ANALYZING chats on start
- [Architecture] Make _ResolvedChat.linked_chat_id optional with default
- [Security] Sanitize error messages in HTTP responses and logs
- [OPS] Add runtime validation: detect silent failures in analysis loop
- [Security] Add rate limiting for GetFullChannelRequest API calls
- [OPS] Integration tests: verify 10 test scenarios from SPEC.md
- Plan reviewed
- Planning v0.9.11 complete

## [0.9.10] - 2026-02-16

### Fixed
- SMOKE: [Must Have] Preview count broken - 422 on empty subscriber fields
- SMOKE: [Must Have] Export crashes with 500 for Cyrillic group names
- SMOKE: [Backend] Export filter modal not implemented
- SMOKE: [Must Have] Subscriber filter min=0 excludes all chats with NULL subscribers
- SMOKE: [Must Have] Export filename loses Cyrillic group name
- SMOKE: [Must Have] Chat type filter has no effect on preview count
- Bug: dead chats marked as pending — fix ChatTypeEnum in error handler
- Bug: fix export filename — use group name instead of timestamp

### Changed
- [Architecture] Add Pydantic model for export filter params
- [Architecture] Extract shared export filter function
- [Security] Sanitize group name in export filename to prevent path traversal
- [OPS] Add rate limit handling for GetFullChannelRequest
- [Reliability] Sanitize filename in export to prevent path traversal
- [Reliability] Add FloodWait retry logic for GetFullChannelRequest
- [UX] Add loading state for export modal
- Backend: add export filter modal endpoint
- Backend: add export preview count endpoint
- Backend: add filter params to export endpoint

## [0.9.9] - 2026-02-14

### Fixed
- Fix SSE duplicate cards: HX-Trigger single-source-of-truth pattern
- SMOKE: [Backend] Export bug test fails with CSRF error (403)
- SMOKE: [Backend] Export returns 404 JSON instead of CSV when no results
- SMOKE: [Visual] SSE polling causes duplicate group cards on /chats page

### Changed
- Analyze: root cause of SSE duplicate cards regression (regressed 2x)
- [Reliability] Add FloodWait retry for Phase 1 get_entity calls
- [Security] Add CSRF protection to settings update endpoint
- Plan reviewed
- [OPS] E2E test: settings modal UI and analysis flow
- [Reliability] Handle GetFullChannel failure for invite links gracefully
- [UX] Add failed chats details view or tooltip
- [Reliability] Ensure re-run analysis clears old data atomically before start
- [UX] Show moderation-skipped chats count in group card
- [OPS] Validate CSV export: columns match selected metrics

## [0.9.8] - 2026-02-13

### Fixed
- SMOKE: [API] GET /api/groups returns error 'group' is undefined
- SMOKE: [Backend] Google Sheets importer async mock issue
- SMOKE: [Backend] Group API endpoints have 0% test coverage
- SMOKE: [Backend] GroupDatabase has 0% test coverage
- SMOKE: [Backend] GroupStatus missing FAILED state causes runtime error
- SMOKE: [Backend] Resume analysis does not clear failed chat errors
- SMOKE: [Must Have] /chats page not replaced with groups interface
- SMOKE: [Must Have] CSV export button missing from group cards
- SMOKE: [Must Have] Excessive SSE polling during in_progress (~7 req/sec)
- SMOKE: [Must Have] No analysis settings modal per group
- SMOKE: [Must Have] No create-group modal (upload file/URL/GSheets)
- SMOKE: [Must Have] Stop analysis causes JS error querySelector null
- Start analysis fails silently (no error shown to user)
- Wire GroupAnalysisEngine into router start/stop endpoints

### Changed
- API router: /api/groups SSE progress + CSV export
- DI + Groups router: CRUD endpoints
- GroupAnalysisEngine: Phase 1 — join/resolve chats
- GroupAnalysisEngine: Phase 2 — analysis via TaskQueue
- GroupAnalysisEngine: Phase 3 leave + stop/resume/subscribe
- MERGE READY: GroupEngine Phase 1 — delete stale untracked file then merge branch
- Security: Google Sheets response size limit
- UI: Build groups frontend (replace /chats page)

## [0.9.7] - 2026-02-12

### Fixed
- Fix: 9 connect_session tests fail - SessionBlockedError instead of Connecting
- Fix: 2 device_confirmation tests fail - MagicMock not AsyncMock for remove_auth_state
- [Reliability] Fix race condition in adopt_client validation
- Fix 2: Return HTTP 4xx/5xx for error responses in verify_2fa and verify_code
- Fix 1: Add auth_state cleanup in generic exception handlers
- Fix 3: Remove await from client.session.save() (root cause)
- SMOKE: [API] FileNotFoundError handlers missing status_code
- [Reliability] Add auth_state cleanup in verify_code generic exception handler
- Fix 4: Accurate error messages (not 'Failed to verify password')
- Sync __init__.py version 0.9.4 → 0.9.5

### Changed
- [Security] Prevent 2FA password leakage in exception traceback
- [Security] Add session file write lock (race condition)
- [UX] Fix button states and loading feedback in 2FA/SMS modals
- Nice-to-have: Add auth_state cleanup in OSError/TimeoutError handlers

## [0.9.6] - 2026-02-12

### Fixed
- **Infinite 2FA loop**: Fixed TypeError from awaiting synchronous session.save() method (commit e09e690)
  - Root cause: `await client.session.save()` but Telethon's session.save() returns None (not awaitable)
  - Symptom: Generic exception handler caught TypeError → returned HTTP 200 → UI showed success but auth failed → infinite loop
  - Solution: Changed to `client.session.save()` without await on line 3060 in sessions.py

## [0.9.5] - 2026-02-12

### Fixed
- Fix: Add AsyncMock for session_manager.adopt_client in test_verify_code_auto_2fa_success
- SMOKE: [Backend] Test mock incomplete - client.session.save() not AsyncMock
- Fix: Add AsyncMock for adopt_client in 2 test setups
- SMOKE: [Backend] 6 tests expect old error message format

### Changed
- Rewrite _finalize_reconnect_auth() to use adopt_client instead of disconnect+reconnect
- Add adopt_client() method to SessionManager
- [Reliability] Add client cleanup for RPCError/Exception in _poll_device_confirmation
- [Reliability] Add error handling for adopt_client failure in _finalize_reconnect_auth
- [UX] Device confirmation timeout should publish 'error' not 'disconnected'
- [Security] Add authorization validation in adopt_client()
- [OPS] Add E2E test for full auth flow (reauth → 2FA → device confirmation → connected)
- Write tests for adopt_client() and rewritten _finalize_reconnect_auth()
- Update _poll_device_confirmation to use adopt_client path
- Add unit tests for SessionManager.adopt_client()
- [UX] Add specific error message when adopt_client fails
- Planning complete for v0.10.0
- Nice-to-have: Improve error logging in _finalize_reconnect_auth

## [0.9.4] - 2026-02-11

### Fixed
- Update 5 device confirmation tests to match new AuthKeyUnregisteredError semantics
- [Bug1] Fix _poll_device_confirmation() to handle AuthKeyUnregisteredError as fatal
- [Bug1] Fix _check_device_confirmation() to not return True on AuthKeyUnregisteredError
- [Bug1] Remove false-positive device confirmation detection from AuthKeyUnregisteredError handlers
- [Bug2] Fix JS error 'Cannot read properties of null' in upload_result.html

### Changed
- [UX] Add device confirmation feedback in modal before close
- [OPS] Add automated test suite for device confirmation flow (prevent regression)
- [Reliability] Add auth_state cleanup when _poll_device_confirmation() fails fatally
- [OPS] Add automated tests for Bug2 (JS error in upload_result.html)
- [Bug1] Manual test: device confirmation flow
- [Bug1] Improve error message for AuthKeyUnregisteredError in verify_code/verify_2fa
- [Reliability] Protect _finalize_reconnect_auth() from timeout race condition

## [0.9.3] - 2026-02-11

### Fixed
- **Bug 3: API credentials extraction**: Extract api_id/api_hash from uploaded JSON and pass to validation template
- **Bug 2: JSON field validation**: Remove strict field allowlist in validate_account_info_json()
- **Bug 1b: AuthKeyUnregisteredError handling**: Fix AuthKeyUnregisteredError handling in verify_2fa()
- **Bug 1a: AuthKeyUnregisteredError handling**: Fix AuthKeyUnregisteredError handling in verify_code()
- **Bug 4: Version sync**: Update __version__ to 0.9.2 in __init__.py
- **SMOKE: API credentials auto-fill**: Fix api_id/api_hash from JSON not auto-filled in import form

### Changed
- **[Security] Credential cleanup**: Zero extracted api_id/api_hash after encryption
- **[OPS] Manual test protocol**: Create manual test protocol for v0.10.0 release
- **[Reliability] Device confirmation fallback**: Add fallback if _check_device_confirmation() fails

### Testing
- Added test verifying api_id/api_hash data attributes in validation response
- Verified all 4 bug fixes pass integration tests

## [0.9.2] - 2026-02-11

### Fixed
- **AuthKeyUnregisteredError handling**: Fixed _check_device_confirmation to catch AuthKeyUnregisteredError and return needs_confirmation instead of propagating error
- **Integration test mocks**: Fixed broken mocks causing device confirmation integration tests to fail (SMOKE)
- **Test assertions**: Fixed 2 stale disconnect_session tests asserting old response format

### Changed
- **[Security] Rate limiting**: Added rate limiting to device confirmation polling to prevent API abuse
- **[Security] Expired confirmation disconnect**: Add forced disconnect for expired device confirmation
- **[Security] AuthKeyUnregisteredError validation**: Validate AuthKeyUnregisteredError legitimacy in device confirmation
- **[Reliability] Polling cleanup**: Added cleanup for background polling task on auth state expiry
- **[Reliability] Duplicate polling prevention**: Prevent duplicate polling tasks for device confirmation
- **[Reliability] AuthKeyUnregisteredError verification**: Verify AuthKeyUnregisteredError handling in polling loop
- **[Reliability] Session file atomicity**: Add atomic session file write with backup in _finalize_reconnect_auth
- **[Reliability] Fallback handling**: Add fallback if _finalize_reconnect_auth fails during polling
- **[Reliability] Race condition handling**: Handle race between polling completion and timeout
- **[UX] Network error handling**: Handle network error during confirmation polling
- **[Architecture] Polling task deduplication**: Prevent duplicate polling tasks for same session
- **[Architecture] Auth state client access**: Ensure polling has access to auth_state client

### Testing
- Added integration test for device confirmation timeout scenario
- Added test for AuthKeyUnregisteredError → needs_confirmation flow
- Added background polling task for device confirmation → connected transition test
- **[OPS] Shutdown cleanup verification**: Verify background polling task cleanup on app shutdown

## [0.9.1] - 2026-02-11

### Fixed
- **AuthKeyUnregisteredError handling**: Fixed _check_device_confirmation to catch AuthKeyUnregisteredError and return needs_confirmation instead of propagating error
- **Integration test mocks**: Fixed broken mocks causing device confirmation integration tests to fail

### Changed
- **[Security] Rate limiting**: Added rate limiting to device confirmation polling to prevent API abuse
- **[Reliability] Polling cleanup**: Added cleanup for background polling task on auth state expiry
- **[Reliability] Duplicate polling prevention**: Prevent duplicate polling tasks for device confirmation
- **[Reliability] AuthKeyUnregisteredError verification**: Verify AuthKeyUnregisteredError handling in polling loop
- **[Reliability] Session file atomicity**: Add atomic session file write with backup in _finalize_reconnect_auth
- **[Reliability] Fallback handling**: Add fallback if _finalize_reconnect_auth fails during polling
- **[Reliability] Race condition handling**: Handle race between polling completion and timeout
- **[Reliability] Concurrent verify prevention**: Prevent concurrent verify operations during device confirmation polling
- **[Security] Expired confirmation disconnect**: Add forced disconnect for expired device confirmation
- **[Security] AuthKeyUnregisteredError validation**: Validate AuthKeyUnregisteredError legitimacy in device confirmation
- **[UX] Network error handling**: Handle network error during confirmation polling
- **[Architecture] Polling task deduplication**: Prevent duplicate polling tasks for same session
- **[Architecture] Auth state client access**: Ensure polling has access to auth_state client
- **[OPS] Shutdown cleanup verification**: Verify background polling task cleanup on app shutdown

### Testing
- Added integration test for device confirmation timeout scenario
- Added test for AuthKeyUnregisteredError → needs_confirmation flow
- Added background polling task for device confirmation → connected transition test

## [0.9.0] - 2026-02-10

### Fixed
- **Device confirmation detection**: Fixed Telegram "Is this you?" confirmation showing fake "connected" status. Now shows "Awaiting Confirmation" with clear message to confirm in other Telegram app, auto-updates when confirmed
- **AuthKeyUnregisteredError handling**: Fixed _check_device_confirmation to catch AuthKeyUnregisteredError and return needs_confirmation instead of propagating error to verify_2fa/verify_code callers
- **Background polling for confirmation**: Added background polling task that detects when user confirms on another device and auto-transitions session to connected state via SSE

## [0.8.5] - 2026-02-10

### Fixed
- **Bug1: JS code modal handler**: Close modal and update row after code verification
- **Bug1: verify-code endpoint**: Return session_row on needs_2fa instead of reconnect_success
- **Bug2: JS 2FA modal handler**: Verify close and update row after 2FA verification
- **Bug2: _finalize_reconnect_auth**: Connect via session_manager after successful 2FA
- **Bug2: verify-2fa endpoint**: Return session_row on success
- **Bug2: verify-code success**: Return session_row instead of reconnect_success
- **SMOKE: Disconnect triggers querySelector JS error**: Fixed JS error when disconnecting session
- **SMOKE: Missing auth_code_form_reconnect.html**: Fixed 500 error on code verify errors due to missing template
- **SMOKE: Navigation not translated**: Fixed .po entries marked obsolete causing navigation to show untranslated strings

### Changed
- **[OPS] Integration tests**: Added integration tests for auth flow fixes
- **[Reliability] Session manager connection**: Added proper session_manager connection after auth completion
- **[Reliability] Auth flow timeout**: Added timeout for auth flow operations to prevent hangs
- **[Reliability] Translation race condition**: Fixed race condition in translation loading
- **[Reliability] Telegram confirmation**: Handle Telegram "Is this you?" confirmation dialog
- **[Security] Rate limiting**: Added rate limiting for auth endpoints to prevent abuse
- **[Security] Session ID validation**: Added session_id validation to prevent path traversal attacks
- **[Security] HTTPS validation**: Validate HTTPS in production environment
- **[Security] Zero sensitive data**: Zero sensitive data in memory after use
- **[Troubleshoot] Persistent timeout**: Resolved persistent timeout for ChatFilter-gvnoc
- **[UX] Telegram confirmation flow**: Handle Telegram "Is this you?" confirmation flow with better UX

## [0.8.4] - 2026-02-10

### Fixed
- **disconnecting state usage**: Fixed disconnecting state still used in sessions.py, violates 8-state model
- **removed state cleanup**: Fixed missing tests for removed state cleanup verification
- **needs_config localization**: Fixed needs_config state shows raw text instead of localized label in HTMX response
- **Connect flow tests**: Fixed needs_config early return blocks testing
- **Connect without credentials**: Fixed Connect on account without API creds returns HTTP 400 instead of needs_config
- **Edit button routing**: Fixed Edit button returns 404 for saved account
- **Connect error handling**: Fixed Connect button error destroys session list
- **Session list display**: Fixed saved account not appearing in session list
- **Test state format**: Fixed tests expect string state, got tuple (state, error)
- **Mock completeness**: Fixed incomplete mocks in test_needs_2fa_to_connected_success, test_needs_code_to_needs_2fa, test_needs_code_to_connected_success

### Changed
- **Rebase conflict resolution**: Resolved multiple rebase conflicts from parallel bug fixes
- **Evidence tests**: Updated evidence tests for needs_config state migration

## [0.8.3] - 2026-02-09

### Fixed
- **SMOKE: Backend Russian translations**: Fixed missing Russian translations for session statuses
- **SMOKE: session_expired rendering**: Fixed session_expired status not being rendered in template (shows raw key in EN+RU)
- **SMOKE: session_expired translation**: Fixed session_expired status not translated to Russian
- **Connect error visibility**: Fixed Connect button failing silently - now shows error message when connection fails
- **Session status detection**: Fixed get_session_config_status() to check SecureCredentialManager for encrypted credentials
- **API credential validation**: Re-validates API credentials when changed

### Changed
- **Conflict resolution**: Resolved multiple rebase conflicts from parallel bug fixes
- **Shell environment**: Fixed broken shell environment in executor-0 worktree
- **Error handling**: Improved error handling for missing phone in account_info BEFORE send_code
- **Race condition prevention**: Prevents race condition on parallel Connect clicks
- **Timeout handling**: Added timeout for _send_verification_code_and_create_auth() and background connect task
- **Security improvements**: Sanitized error messages before publishing to SSE
- **Credential logging**: Prevented credential leakage in get_session_config_status() logs
- **File corruption handling**: Handles corrupted .credentials.enc gracefully

## [0.8.2] - 2026-02-09

### Fixed
- **Session status detection**: Fixed get_session_config_status() to check SecureCredentialManager for encrypted credentials
  - Sessions with valid encrypted credentials now show correct status instead of "Setup Required"
  - Maintains backward compatibility with plaintext config.json
- **Error message visibility**: Fixed Connect button failing silently without showing error messages
  - Error messages now displayed inline in session row when Connect fails
  - Clear "Phone number required" message when phone is missing
  - Proxy and network errors now visible to user
- **Russian translations**: Added missing Russian translations for session statuses
  - All session statuses now translated (Needs Auth, Needs API ID, Setup Required)
  - Added tooltip translations for authorization and error states

## [0.8.1] - 2026-02-08

### Fixed
- **Session not found in background task**: Fixed silent connection failures when session.session file was missing
- **Auto 2FA entry**: Fixed sign_in being called only once instead of twice for 2FA authentication
- **Verification code modal**: Fixed modal auto-opening and blocking page on load
- **Upload form validation**: Fixed 422 errors caused by missing api_id/api_hash fields in form submission
- **Connect ImportError**: Fixed crashes with "get_proxy_manager missing" import error
- **Upload directory creation**: Fixed upload save logic failing when directory not created
- **Build configuration**: Fixed build command failures in testing.yaml
- **Testing configuration**: Fixed testing.yaml configuration issues
- **Deployment sync**: Fixed server running outdated code due to FileNotFoundError fix not being deployed
- **FileNotFoundError handling**: Fixed connect failures when session.session file is missing
- **Setup Required UI**: Fixed disabled "Wait..." button appearing instead of actionable Setup/Edit button
- **Session list template**: Fixed missing has_session_file check for disconnected status in sessions_list.html
- **has_session_file check**: Fixed reporting True when session.session file is actually missing
- **Test regression**: Fixed button label test failures after changing 'Connect' to 'Authorize'
- **Upload file input**: Fixed upload form only accepting .session files, now also accepts .json files
- **Race condition**: Fixed race condition in connect_session logic

### Changed
- **Upload form**: Simplified upload form to accept both .session and .json files
- **TOCTOU protection**: Improved upload_session security against race conditions
- **Connect logic**: Simplified connect_session to auto-delete invalid sessions and resend codes
- **Session status**: Removed session_expired status entirely from codebase
- **Session listing**: Refactored list_stored_sessions to use config.json + account_info as source of truth

## [0.8.0] - 2026-02-06

### Security
- **CSRF Token Fix**: All fetch POST/DELETE requests now include X-CSRF-Token header
  - Fixed sessions_list.html verify-code and verify-2fa
  - Fixed analysis_results.html export/csv
  - Fixed chats.html dismiss_notification
  - Fixed analysis_progress.html cancel
  - Fixed results.html export/csv and dismiss_notification
- **Input Validation**: Added format validation for verification code (5-6 digits only)
- **Input Validation**: Added validation for 2FA password input

### Changed
- **Clean Session UI**: Reconnect no longer shows modal - directly initiates connection
  - Removed reconnect_modal.html and related endpoints
  - Session status now determines action button (Connect/Disconnect/Reconnect/Enter Code/Enter 2FA/Edit)
  - Simplified three-button layout: [Action] [Edit] [Delete]
- **Add Account Modal**: Button changed from "Send Code" to "Save" for clarity
- **i18n**: Added translations for all new/changed UI strings (EN and RU)

### Fixed
- **Mobile CSS**: All buttons now have consistent sizing with 44px minimum tap target
- **Double-click Prevention**: Connect/Disconnect buttons now disabled during operation

### Removed
- Orphaned /reconnect-form endpoint
- Orphaned /send-code endpoint
- Orphaned reconnect templates

## [0.7.2] - 2026-02-05

### Fixed
- **Loading Spinner on Connect**: Fixed loading spinner not appearing when clicking Connect button
  - Root cause: `connect_session` endpoint was synchronous, blocking HTTP response for 30s while awaiting Telegram
  - Solution: Endpoint now returns immediately with `connecting` state, runs connect in background task
  - SSE delivers final state (connected/error) when connection completes
- **JavaScript querySelector Error**: Fixed `querySelector null` JS error on Connect action
  - Caused by attempts to manipulate DOM elements that didn't exist due to architectural mismatch
  - Resolved by architectural fix above - no more client-side spinner manipulation needed
- **HTMX swapError on Connect**: Fixed HTMX swap errors during connection attempts
  - Added proper error handling for race conditions between SSE updates and HTMX responses

### Changed
- **Connect Architecture**: `connect_session` endpoint is now non-blocking
  - Returns row with `connecting` state immediately (<100ms response)
  - Background task handles actual Telegram connection
  - Realtime updates delivered via existing SSE infrastructure

## [0.7.1] - 2026-02-04

### Fixed
- **Network Error Detection**: Fixed overly broad OSError handling that incorrectly classified filesystem errors (PermissionError, FileNotFoundError) as network errors
  - Now checks specific errno codes (ENETUNREACH, EHOSTUNREACH, ECONNREFUSED, etc.) before treating OSError as network error
  - Prevents endpoints returning 503 Service Unavailable for non-network issues
- **Error Page Styling**: Browser error pages now show styled HTML instead of raw JSON
  - Added error.html template with consistent navigation and retry options
  - Exception handlers detect Accept header to choose between JSON and HTML responses
- **SSE Cross-Tab Updates**: Fixed SSE events not updating UI in other browser tabs
  - Implemented dedicated sse.js module that auto-connects to /api/sessions/events
  - EventSource reconnects automatically on connection loss

## [0.7.0] - 2026-02-04

### Added
- **Realtime Session Status**: Sessions list now updates automatically without page refresh
  - Server-Sent Events (SSE) endpoint `/api/sessions/events` streams status changes
  - HTMX SSE extension integrates with session list for live updates
  - Event bus architecture with rate limiting (10 events/sec per session) and deduplication
- **Loading States for Actions**: All action buttons now show visual feedback
  - Spinner replaces status during Connect, Disconnect, Reconnect operations
  - Loading state for Send Code, Verify Code, Verify 2FA actions
  - Prevents double-click with debounce protection
- **Status Transition Audit**: Documented all valid session state transitions
  - Matrix of status → action → new status mappings
  - Ensures consistent UI behavior across all flows

### Changed
- **Session Row Updates**: Individual rows refresh via SSE instead of full page reload
- **Error State Handling**: Improved error display in UI with retry options
- **Modal Submit Feedback**: Error responses now show in modal instead of silent failure

### Fixed
- **2FA Modal CSS Selectors**: Renamed `2fa-modal` IDs to `twofa-modal` for valid CSS
- **Session Lock**: Added locking to prevent concurrent operations on same session
- **Telegram Timeout**: Added 30-second timeout for Telegram API operations to prevent hangs

### Security
- **Input Validation**: Added validation for auth endpoint inputs (phone, code, password)
- **Rate Limiting**: Event bus prevents flooding from rapid status changes

### Testing
- **E2E Tests**: End-to-end test for realtime status updates
- **Integration Tests**: SSE endpoint connection and event delivery tests
- **Loading State Tests**: Coverage for all 6 action button loading states

## [0.6.4] - 2026-02-02

### Fixed
- **Reconnect Flow Complete Fix**: Fixed all issues with reconnecting expired sessions
  - `send_code()` now returns reconnect-specific template with correct endpoint
  - Reconnect code form posts to `/api/sessions/{session_id}/verify-code` (was: wrong endpoint for new sessions)
  - Reconnect code form targets `#reconnect-result` (was: non-existent `#auth-flow-result`)
  - Error responses use `reconnect_result.html` template for proper UI feedback
- **needs_code/needs_2fa Modal Handlers**: Modals now have working submit handlers
  - Added JavaScript handlers for code and 2FA verification modals
  - Handlers POST to correct endpoints with `session_id` and `auth_id`
  - `auth_id` passed via `data-auth-id` attribute on buttons
  - Double-submit prevention with button disabling
- **Reconnect Modal Not Visible**: Added `show` class to reconnect modal so it displays correctly when loaded via HTMX
- **Enter Code/2FA Buttons Not Working**: Fixed buttons for `needs_code` and `needs_2fa` states - removed `disabled` attribute, added correct modal trigger classes
- **Modal CSS Class Mismatch**: Changed JavaScript to use `show` class instead of `visible` to match CSS definitions
- **Empty Code/2FA Modals**: Added input fields to code verification and 2FA password modals
- **Missing Translations**: Fixed status text using untranslated strings
- **Missing FloodWaitError Import**: Added missing import in verify_code and verify_2fa endpoints

### Changed
- **Error Recovery for Reconnect**: verify-code returns reconnect-specific template on error for consistent flow
- **Deleted Unused Modal Duplicates**: Removed duplicate modal files (`partials/modal_code.html`, `partials/modal_2fa.html`) that were not being used

## [0.6.3] - 2026-02-01

### Fixed
- **i18n Race Condition**: Fixed race condition where language switcher and version check used i18n before initialization
  - i18n.js now exposes a `ready` Promise
  - language-switcher.js and version-check.js wait for i18n to be ready before using translations
- **Missing Locale Keys**: Added `language.current_aria` and `language.switch_to` keys to en.json and ru.json
- **Version Check 404**: Fixed `/api/version/check-updates` endpoint returning 404
- **Favicon 404**: Added `/favicon.ico` route to suppress browser 404 errors
- **Missing HX-Trigger Header**: Fixed `connect_session` endpoint not returning HX-Trigger header in early return path
- **Corrupted Session Files**: System now handles corrupted .session files gracefully with option to delete and recreate
- **Error Message Sanitization**: Exception messages are now sanitized to prevent information leakage of internal paths and details

### Added
- **Complete Russian Translations**: Filled all 584 empty Russian translations in messages.po
  - Full localization of UI: navigation, buttons, statuses, dialogs, error messages
  - Language switching now properly displays Russian interface
- **Session State Validation**: Connection/disconnection endpoints now validate session state before operations
  - Prevents race conditions and duplicate operations
  - Clear error messages for incompatible state transitions
- **Connection Timeout Protection**: Session connection attempts now have explicit 30-second timeout
  - Returns user-friendly error if Telegram API hangs
  - Prevents indefinite waits and improves responsiveness
- **API Credential Validation**: Changing API_ID/API_HASH now triggers full re-authorization
  - Validates credentials work with Telegram API
  - Shows code/2FA modal if authentication required
  - Only saves after successful validation
- **Transient Error Retry Logic**: API credential validation retries on transient network errors
  - Exponential backoff with max 3 attempts
  - Distinguishes network errors from invalid credentials
- **Auth Flow Protection**: Authentication endpoints track failed attempts and lock session after excessive failures
  - Max 5 failed attempts per session
  - 15-minute lockout period before retry allowed
- **Phone Number Sanitization**: Phone number input in auth flow is now sanitized
  - Removes spaces, dashes, parentheses
  - Validates format before sending to Telegram API
  - Clear error messages for invalid formats
- **Telegram Rate Limiting**: FloodWaitError from Telegram API now shows user-friendly message
  - Displays wait time required before retry
  - Helps users understand rate limiting
- **Dead Session Recovery**: Dead/expired sessions show clear status with recovery options
  - Distinct visual treatment for different error types
  - Reconnect button initiates re-auth flow
  - Preserves session ID for recovery

### Changed
- **Code Cleanup**: Audit and refactoring of sessions module
  - Removed unused code and duplicate logic
  - Simplified overly complex code paths
  - Improved code maintainability and readability

## [0.6.2] - 2026-01-28

### Fixed
- **i18n Race Condition**: Fixed race condition where language switcher and version check used i18n before initialization
  - i18n.js now exposes a `ready` Promise
  - language-switcher.js and version-check.js wait for i18n to be ready before using translations
- **Missing Locale Keys**: Added `language.current_aria` and `language.switch_to` keys to en.json and ru.json
- **Version Check 404**: Fixed `/api/version/check-updates` endpoint returning 404
- **Favicon 404**: Added `/favicon.ico` route to suppress browser 404 errors

### Added
- **Complete Russian Translations**: Filled all 584 empty Russian translations in messages.po
  - Full localization of UI: navigation, buttons, statuses, dialogs, error messages
  - Language switching now properly displays Russian interface

## [0.6.1] - 2026-01-28

### Changed
- **API Refactoring**: Major P3 cleanup of API routers
  - Extracted common helpers to reduce code duplication
  - Added Pydantic models for request/response validation
  - Standardized naming conventions across endpoints
- **Retry Logic**: Extracted retry logic into reusable `RetryContext` class
- **Code Cleanup**: Removed dead code and obsolete build infrastructure

### Fixed
- **Tests**: Repaired 88 failing tests across the test suite
  - Fixed 63 tests with missing `exports_dir` configuration
  - Resolved 25 additional test failures across 4 test files
  - Replaced useless `assert True` with real assertions
- **Type Annotations**: Fixed `type: ignore` comments and nullable return types
- **Settings**: Use `settings.max_messages_limit` and errno constants correctly

### Added
- **Test Coverage**: Comprehensive tests for 16 previously untested modules
- **API Validation**: Input validation and error handling for API endpoints
- **i18n**: Integrated `i18n.t()` in JavaScript files for full frontend internationalization

### Removed
- Unused `config.py` code
- Dead code and obsolete build infrastructure

## [0.6.0] - 2026-01-27

### Added
- **Complete Russian translations**: Full i18n support for all UI elements
  - 500+ translation entries for sessions, proxies, modals, buttons, status indicators
  - Error messages from Python code now translate (proxy errors, configuration errors)
  - Language switching works correctly in both directions (RU ↔ EN)

### Removed
- **Desktop Application**: Removed native window and system tray functionality
  - Removed pywebview native window (application now runs as pure CLI server)
  - Removed pystray system tray icon
  - Removed PyInstaller binary builds for Windows, macOS, and Linux
  - Distribution is now Python package only (`pip install chatfilter`)
- **Dependencies**: Removed 6 desktop-related dependencies
  - pystray, Pillow, pywebview
  - pyobjc-framework-Cocoa, pyobjc-framework-WebKit (macOS only)
- **Build Infrastructure**: Removed binary build system
  - Removed chatfilter.spec, build.sh, entitlements.plist
  - Removed GitHub Actions workflows for binary builds

### Changed
- **CLI Mode**: `chatfilter` command now runs uvicorn directly
  - Blocks until Ctrl+C (no background threading)
  - Hot reload enabled in debug mode (`--debug`)
  - Prints URL to console on startup
- **Installation**: Install via `pip install chatfilter`
  - Lighter package without GUI dependencies
  - Works on any Python 3.11+ environment
- **Credential Storage**: Switched from OS keychain to encrypted file backend
  - No more repeated password prompts on macOS
  - Credentials stored in encrypted files in data directory

### Migration
Users upgrading from 0.5.x desktop app:
1. Uninstall the desktop application
2. Install via pip: `pip install chatfilter`
3. Run: `chatfilter --port 8000`
4. Open browser manually: http://127.0.0.1:8000

### Fixed
- **Deactivated Account Detection**: Connect now validates account can access dialogs
  - Previously deactivated accounts could show "Connected" status falsely
  - Now shows "Banned" status with proper error message
  - Uses `iter_dialogs(limit=1)` check instead of just `get_me()`
- **Session Path**: Fixed ChatAnalysisService using wrong sessions directory
  - Was hardcoded to `./data/sessions` instead of `settings.sessions_dir`
  - Caused "Session not found" errors when selecting sessions on Chats page
- **HTMX Session Select**: Added missing `name` attribute to session dropdown
  - HTMX `hx-include` requires `name` to send form value
  - Fixed 422 "Field required" error when selecting session

## [0.5.2] - 2026-01-27

### Fixed
- **Session Status**: Fixed session status not updating after connect/disconnect
  - Previously only the button updated, leaving status cell stale
  - Now the entire row updates with correct state
- **Error Display**: Error messages shown in tooltip on hover instead of inline text
  - Cleaner UI with status-only display
  - Full error message visible on hover

## [0.5.1] - 2026-01-27

### Fixed
- **JavaScript**: Fixed broken `hyperlist.min.js` file that contained error text instead of library code
  - HyperList library was not loading, causing "Unexpected identifier 'found'" console error
  - Virtual scrolling in chat list now works correctly

## [0.5.0] - 2026-01-27

### Added
- **Session Connect/Disconnect**: Added explicit connect/disconnect buttons for each session
  - Connect button for disconnected sessions
  - Disconnect button for connected sessions
  - Retry button for error states (proxy error, flood wait)
  - Disabled state for banned accounts and unconfigured sessions
- **Extended Session Status**: More detailed session status indicators
  - Connected, Disconnected, Connecting, Disconnecting states
  - Banned (account blocked by Telegram)
  - Flood Wait (temporary rate limit)
  - Proxy Error (proxy connection failed)
  - Not Configured, Proxy Missing states
  - Error messages shown in tooltip on hover

### Removed
- **Keyboard Shortcuts**: Removed keyboard shortcuts feature and help modal
  - Removed `static/js/keyboard-shortcuts.js` (671 lines)
  - Removed keyboard shortcuts button from header
- **Header Status Indicators**: Removed global Telegram status from header
  - Removed "Telegram Connection Status" indicator
  - Removed "User logged in" indicator
  - These were redundant with per-session status display

### Changed
- **Code Cleanup**: Removed duplicate helper functions
  - Consolidated `get_session_manager()` and `get_chat_service()` functions
  - Removed duplicates from `routers/chats.py` (now uses `dependencies.py`)

## [0.4.12] - 2026-01-27

### Fixed
- **Auto-open browser**: Actually removed auto-open browser on startup (was documented in 0.4.11 but code remained)
- **Proxy settings lost on import**: Fixed proxy_id not being saved when importing or uploading sessions

## [0.4.11] - 2026-01-27

### Added
- **Native Window**: Application now runs in native window using pywebview
  - Replaces browser-based UI with native macOS/Windows/Linux window
  - uvicorn server runs in background thread
  - Fallback to headless mode if pywebview unavailable

### Changed
- **No auto-open browser**: Removed automatic browser launch on startup
  - Use tray icon menu "Open in Browser" to access web UI
  - Native window opens automatically instead

## [0.4.10] - 2026-01-27

### Fixed
- **macOS Tray Icon**: Fixed tray icon not appearing on macOS
  - Root cause: `run_detached()` was called from ThreadPoolExecutor worker thread instead of main thread
  - NSStatusItem requires main thread for initialization
  - Now calls `run_detached()` directly from main thread on macOS

## [0.4.9] - 2026-01-27

### Fixed
- **UI**: Fixed `querySelector` crash when loading session file (null-check for activeTab)
- **Proxy Pool**: Fixed UI disappearing and showing raw JSON when testing proxy (changed HTMX swap to trigger refresh)
- **macOS Tray**: Fixed missing tray icon and Dock icon on macOS
  - Added `pyobjc-framework-Cocoa` dependency
  - Added pyobjc hiddenimports for PyInstaller
  - Added `LSUIElement`, `NSHighResolutionCapable` to Info.plist

### Changed
- CI coverage threshold lowered to 76%

## [0.4.8] - 2026-01-26

### Fixed
- **P0: Proxy storage path**: Fixed "Read-only file system" error on macOS by using `settings.config_dir` instead of app bundle path for proxy storage
- **P1: Tray icon AppTranslocation**: Disabled tray icon when running from macOS App Translocation to prevent "Application Not Responding"
- **P1: Infinite loading spinner**: Added HTMX error handlers to show error message instead of spinning forever when API calls fail

### Changed
- Proxy pool now stores data in user config directory (`~/Library/Application Support/ChatFilter/config/proxies.json`)
- Legacy proxy migration checks both old app bundle location and new config directory
- Bundled htmx, hyperlist, chart.js locally instead of CDN (fixes offline/firewall issues)

## [0.4.7] - 2026-01-26

### Fixed
- **macOS AppTranslocation**: Data directory now auto-relocates to `~/Library/Application Support/ChatFilter` when running from read-only locations (downloaded .app from DMG)
- **Tray icon timeout**: Added 5-second timeout for tray initialization to prevent "Application Not Responding" on macOS

### Added
- **Proxy health monitoring**: Background task pings proxies every 5 minutes, auto-disables after 3 failures
- **Proxy status indicators**: Working (🟢), No ping (🔴), Untested (⚪) shown in proxy list
- **Retest button**: Manual proxy health check with instant status update

### Changed
- **Sessions page UX overhaul**: Single "Add Account" button with modal for upload or phone auth
- **Account list**: Shows status (Working/Not authorized/Disabled), proxy assignment, edit/delete actions
- **Merged proxy pages**: Combined `/proxy` and `/proxies` into single `/proxies` page
- Removed legacy global proxy support (`proxy.json`), all proxies now use pool

## [0.4.6] - 2026-01-26

### Fixed
- PyInstaller spec version sync with package version
- Added proper app icons for macOS/Windows builds
- Lazy import pystray to prevent crashes on headless systems

## [0.4.5] - 2026-01-25

### Added
- Phone-based session creation with code/2FA authentication flow
- Session config form with api_id, api_hash, proxy selection
- Proxy pool UI with add/edit modal and delete confirmation
- System tray icon integration (macOS menu bar, Windows system tray, Linux AppIndicator)
- Headless environment detection for graceful tray skip

### Fixed
- Proxy JSON deserialization type coercion

## [0.4.0] - 2026-01-24

### Changed
- **Complete UI redesign**: Transformed web interface to minimalist Apple-style design
  - Replaced Material Design bright blue with muted iOS blue (#007aff)
  - Redesigned header with white/light-gray background and thin border
  - Reduced shadows throughout (from 4px to 1-2px, lower opacity)
  - Reduced border-radius for cleaner geometry (from 8px to 4-6px)
  - Updated buttons to flat design with subtle 1px borders
  - Lightened font weights for better readability (font-weight: 400-500 max)
  - Increased white space and padding for improved breathing room
  - Removed pulsing animations from status indicators for cleaner feel

### Fixed
- Bug ChatFilter-e385: Tooltips and alerts now properly use CSS variables for text colors
  - Text colors now correctly adapt between light and dark themes
  - Added theme-specific variables: `--warning-text`, `--info-text`, `--success-text`, `--danger-text`

## [0.3.0] - 2026-01-23

### Added
- Russian language support (i18n) for web interface templates
- Network connectivity monitoring with graceful degradation
- Automatic update checking from GitHub releases

### Changed
- Upgraded CI to Python 3.12
- Optimized CI pipeline for faster builds (~30min vs 2.5h)
- Improved smoke tests with better output capture and diagnostics

### Fixed
- Windows CI compatibility: emoji encoding, pipe buffer blocking, timer resolution
- Test stability improvements across all platforms
- PyInstaller build now includes all required submodules
- Jinja2 template dependency for i18n support

## [0.2.0] - 2026-01-21

### Added
- Encrypted storage with Fernet symmetric encryption
- Machine-derived encryption keys for portable security
- Key rotation support with versioned file format

### Fixed
- Session management reliability improvements

## [0.1.0] - 2026-01-20

### Added
- Initial release of ChatFilter
- Telegram chat import and export functionality
- Message filtering and analysis
- Web-based UI for chat management
- Task queue system with deduplication
- Comprehensive smoke tests for binary releases
- Antivirus false positive mitigation for PyInstaller builds
- Unified error handling system in Web UI

### Fixed
- Memory leaks in long-running background tasks
- Task deduplication to prevent duplicate analysis runs

### Documentation
- Windows SmartScreen bypass instructions

[Unreleased]: https://github.com/Puremag1c/ChatFilter/compare/v0.24.0...HEAD
[0.24.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.19.1...v0.20.0
[0.19.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.19.0...v0.19.1
[0.19.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.15.1...v0.16.0
[0.15.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.15.0...v0.15.1
[0.15.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.14.1...v0.15.0
[0.14.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.12.0...v0.13.0
[0.10.9]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.8...v0.10.9
[0.10.8]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.7...v0.10.8
[0.10.7]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.6...v0.10.7
[0.10.6]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.5...v0.10.6
[0.10.5]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.4...v0.10.5
[0.10.4]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.3...v0.10.4
[0.10.3]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.2...v0.10.3
[0.10.2]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.12...v0.10.0
[0.9.12]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.11...v0.9.12
[0.9.11]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.10...v0.9.11
[0.9.10]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.9...v0.9.10
[0.9.9]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.8...v0.9.9
[0.9.8]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.7...v0.9.8
[0.9.7]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.6...v0.9.7
[0.9.6]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.5...v0.9.6
[0.9.5]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.4...v0.9.5
[0.9.4]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.3...v0.9.4
[0.9.3]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.8.5...v0.9.0
[0.8.5]: https://github.com/Puremag1c/ChatFilter/compare/v0.8.4...v0.8.5
[0.8.4]: https://github.com/Puremag1c/ChatFilter/compare/v0.8.3...v0.8.4
[0.8.3]: https://github.com/Puremag1c/ChatFilter/compare/v0.8.2...v0.8.3
[0.8.2]: https://github.com/Puremag1c/ChatFilter/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.7.2...v0.8.0
[0.7.2]: https://github.com/Puremag1c/ChatFilter/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.6.4...v0.7.0
[0.6.4]: https://github.com/Puremag1c/ChatFilter/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/Puremag1c/ChatFilter/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/Puremag1c/ChatFilter/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/Puremag1c/ChatFilter/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.12...v0.5.0
[0.4.12]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.11...v0.4.12
[0.4.11]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.10...v0.4.11
[0.4.10]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.9...v0.4.10
[0.4.9]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.8...v0.4.9
[0.4.8]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.7...v0.4.8
[0.4.7]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.6...v0.4.7
[0.4.6]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.0...v0.4.5
[0.4.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Puremag1c/ChatFilter/releases/tag/v0.1.0
