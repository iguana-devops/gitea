import {prettyNumber} from '../utils.js';

const {lang} = document.documentElement;

export function initFormattingReplacements() {
  // replace english formatted numbers with locale-specific separators
  for (const el of document.getElementsByClassName('js-pretty-number')) {
    const num = Number(el.getAttribute('data-value'));
    const formatted = prettyNumber(num, lang);
    if (formatted && formatted !== el.textContent) {
      el.textContent = formatted;
    }
  }

  // for each <time></time> tag, if it has the data-format-text-according-to-datetime, format
  // the text according to the user's chosen locale
  const locale = document.getElementsByTagName('html')[0].lang;
  const formatter = new Intl.DateTimeFormat(locale, {year: 'numeric', month: 'long', day: 'numeric'});
  for (const timeElement of document.getElementsByTagName('time')) {
    if (timeElement.hasAttribute('data-format-text-according-to-datetime')) {
      timeElement.innerText = formatter.format(new Date(timeElement.dateTime));
    }
  }
}
