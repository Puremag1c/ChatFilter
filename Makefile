.PHONY: i18n

i18n:
	pybabel compile -d src/chatfilter/i18n/locales -D messages
