# Отчёт по итерации

**Версия:** 0.27.5
**Дата:** 2026-03-26

## Выполнено

### Must Have 1: Fix: переключение темы на мобильном
Реализовано. В `applyTheme()` заменён `removeAttribute('data-theme')` на `setAttribute('data-theme', 'light')`, что предотвращает перезапись цветов медиа-запросом `prefers-color-scheme: dark`. Иконка и цвета теперь меняются корректно на мобильных устройствах.

### Must Have 2: Refactor: убрать дубликат CSS тёмных переменных
Реализовано. Два блока с идентичными тёмными переменными (`[data-theme="dark"]` и `@media prefers-color-scheme: dark`) объединены в один блок с comma-селектором. FOUC предотвращён — `@media` селектор сохранён для CSS-fallback до загрузки JS.

### Must Have 3: Refactor: убрать deprecated addListener fallback
Реализовано. Ветка `else if (mediaQuery.addListener)` удалена из `theme-switcher.js`. Оставлен только современный `addEventListener('change', ...)`.

## Не выполнено

Нет. Все Must Have выполнены. Nice to Have в спецификации не было.

## Итог

Все три задачи из SPEC.md выполнены. Переключение тёмной/светлой темы теперь работает корректно на мобильных устройствах. CSS-код очищен от дубликатов, JS — от deprecated API. Тесты пройдены: 2230 passed, 0 failed. Визуальное и функциональное тестирование подтвердили корректность на десктопе и мобильных viewport-ах.
