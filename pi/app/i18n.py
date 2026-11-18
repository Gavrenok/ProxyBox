"""Local UI translations. Never translate input values, URLs or script data."""
import html
from html.parser import HTMLParser
import json
from pathlib import Path
import re

CATALOG = json.loads(Path(__file__).with_name('translations.json').read_text(encoding='utf-8'))


def language(value):
    return 'ru' if value == 'ru' else 'en'


def text(value, lang='en'):
    if not isinstance(value, str):
        return value
    clean = value.strip()
    table = CATALOG if lang == 'en' else {v: k for k, v in CATALOG.items()}
    translated = table.get(clean)
    if translated is None and lang == 'en':
        # Existing radio UI supplies both translations in a single text node.
        if ' / ' in clean and re.search('[А-Яа-я]', clean):
            left, right = clean.split(' / ', 1)
            if not re.search('[А-Яа-я]', right):
                translated = right
        for pattern, replacement in (
            (r'Страница (\d+) из (\d+)', r'Page \1 of \2'),
            (r'(\d+)–(\d+) из (\d+) · всего (\d+)', r'\1–\2 of \3 matches · \4 total'),
            (r'Библиотека прокси \((\d+)\)', r'Proxy library (\1)'),
            (r'Подключены к Wi-Fi \((\d+)\)', r'Wi-Fi clients (\1)'),
            (r'(\d+) мин назад', r'\1 min ago'), (r'(\d+) ч назад', r'\1 h ago'),
            (r'(\d+) дн назад', r'\1 d ago'),
        ):
            if re.fullmatch(pattern, clean):
                translated = re.sub(pattern, replacement, clean)
                break
    if translated is None:
        return value
    return value[:len(value)-len(value.lstrip())] + translated + value[len(value.rstrip()):]


class Translator(HTMLParser):
    def __init__(self, lang):
        super().__init__(convert_charrefs=False)
        self.lang, self.output, self.stack = lang, [], []

    def handle_starttag(self, tag, attrs):
        attrs = list(attrs)
        skipped = (self.stack[-1][1] if self.stack else False) or tag in ('script', 'style', 'textarea', 'code') or ('translate', 'no') in attrs
        if tag == 'html':
            attrs = [(key, self.lang if key == 'lang' else value) for key, value in attrs]
        if ('id', 'panel-job') in attrs:
            attrs = [(key, value) for key, value in attrs if key != 'data-lang'] + [('data-lang', self.lang)]
        rendered = []
        for key, value in attrs:
            if value is not None and key in ('placeholder', 'title', 'aria-label') and not skipped:
                value = text(value, self.lang)
            rendered.append(key if value is None else '%s="%s"' % (key, html.escape(value, quote=True)))
        self.output.append('<' + tag + (' ' + ' '.join(rendered) if rendered else '') + '>')
        if tag not in ('area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr'):
            self.stack.append((tag, skipped))

    def handle_endtag(self, tag):
        self.output.append('</' + tag + '>')
        for index in range(len(self.stack)-1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if self.stack and self.stack[-1][0] == tag:
            self.stack.pop()

    def handle_data(self, value):
        if self.stack and self.stack[-1][1]:
            self.output.append(value)
        else:
            self.output.append(html.escape(text(value, self.lang), quote=False))

    def handle_entityref(self, name): self.output.append('&' + name + ';')
    def handle_charref(self, name): self.output.append('&#' + name + ';')
    def handle_decl(self, value): self.output.append('<!' + value + '>')
    def handle_comment(self, value): self.output.append('<!--' + value + '-->')


def document(value, lang):
    parser = Translator(language(lang))
    parser.feed(value)
    parser.close()
    return ''.join(parser.output)


def javascript(value, lang):
    if lang == 'ru':
        return value  # Source literals are Russian; preserve protocol/status tokens.
    # Translate only simple complete literals, preserving JS syntax via JSON.
    def replace(match):
        original = match[2]
        translated = text(original, lang)
        return json.dumps(translated, ensure_ascii=False) if translated != original else match[0]
    return re.sub(r'''(['"])([^'"\\\r\n]*)\1''', replace, value)
